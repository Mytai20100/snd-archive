package snd

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// SiteSettings holds server-side persisted UI/UX settings.
type SiteSettings struct {
	// Theme & appearance
	Theme           string `yaml:"theme"            json:"theme"`
	BackgroundURL   string `yaml:"background_url"   json:"background_url"`
	BgMusicURL      string `yaml:"bg_music_url"     json:"bg_music_url"`
	Language        string `yaml:"language"         json:"language"`
	// Per-feature toggles for users
	AllowUserTheme  bool   `yaml:"allow_user_theme"  json:"allow_user_theme"`
	ShowDirectLinks bool   `yaml:"show_direct_links" json:"show_direct_links"`
	// Footer & custom CSS
	HideFooter      bool   `yaml:"hide_footer"       json:"hide_footer"`
	CustomCSS       string `yaml:"custom_css"        json:"custom_css"`
	// Embed / OG meta (overrides config.yml values when set)
	EmbedTitle       string `yaml:"embed_title"        json:"embed_title"`
	EmbedDescription string `yaml:"embed_description"  json:"embed_description"`
	EmbedImageURL    string `yaml:"embed_image_url"    json:"embed_image_url"`
	// Embed-loader (CSA.js): when false the script is not injected into pages
	EmbedLoaderEnabled bool `yaml:"embed_loader_enabled" json:"embed_loader_enabled"`
}

// UserSettings holds per-user UI settings (stored inline in UserAccount).
// These are stored in users.yml as part of UserAccount's extra fields.
type UserSettings struct {
	Theme           string `yaml:"theme"            json:"theme"`
	BackgroundURL   string `yaml:"background_url"   json:"background_url"`
	BgMusicURL      string `yaml:"bg_music_url"     json:"bg_music_url"`
	Language        string `yaml:"language"         json:"language"`
	ShowDirectLinks bool   `yaml:"show_direct_links" json:"show_direct_links"`
}

var (
	SiteSettingsData SiteSettings
	SiteSettingsMu   sync.RWMutex
	SiteSettingsFile = "settings.yml"

	// LangCache stores loaded translations: lang code → key → value
	LangCache   = make(map[string]map[string]string)
	LangCacheMu sync.RWMutex
)

// GetAvailableLanguages scans the lang/ directory and returns all language
// codes that have a corresponding subdirectory (e.g. lang/en → "en").
// Falls back to ["en"] if the directory cannot be read.
func GetAvailableLanguages() []string {
	entries, err := os.ReadDir("lang")
	if err != nil {
		return []string{"en"}
	}
	var langs []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != "" {
			langs = append(langs, e.Name())
		}
	}
	if len(langs) == 0 {
		return []string{"en"}
	}
	return langs
}

// LangDisplayName returns a human-readable label for a known language code.
// Unknown codes are returned as-is (uppercase).
func LangDisplayName(code string) string {
	known := map[string]string{
		"en": "English",
		"vi": "Tiếng Việt",
		"zh": "中文",
		"ja": "日本語",
		"ko": "한국어",
		"fr": "Français",
		"de": "Deutsch",
		"es": "Español",
		"ru": "Русский",
		"pt": "Português",
		"it": "Italiano",
		"ar": "العربية",
		"tr": "Türkçe",
		"pl": "Polski",
		"nl": "Nederlands",
		"th": "ภาษาไทย",
		"id": "Bahasa Indonesia",
	}
	if name, ok := known[code]; ok {
		return name
	}
	return code
}

// BuildLangOptionsHTML returns an HTML <option> list for all available languages,
// marking the one matching `selected` as selected.
func BuildLangOptionsHTML(selected string) string {
	langs := GetAvailableLanguages()
	html := ""
	for _, code := range langs {
		sel := ""
		if code == selected {
			sel = " selected"
		}
		html += `<option value="` + code + `"` + sel + `>` + LangDisplayName(code) + `</option>`
	}
	return html
}


// EmbedLoaderSnippet returns the CSA.js inline loader script when the
// embed-loader feature is enabled, or an empty string when it is disabled.
//
// Load order: local /lib/csa.js first (served from web/lib/csa.js on disk),
// CDN is used only as a fallback when the local file is unavailable.
// This avoids CDN failures causing broken pages.
// When upgrading csa.js: replace the local file at web/lib/csa.js and update
// the pinnedURL/sriHash constants below for the CDN fallback if desired.
func EmbedLoaderSnippet() string {
	SiteSettingsMu.RLock()
	enabled := SiteSettingsData.EmbedLoaderEnabled
	SiteSettingsMu.RUnlock()
	if !enabled {
		return ""
	}
	// CDN fallback (used only when local /lib/csa.js fails to load).
	// Pinned commit: update SHA and integrity when upgrading.
	const (
		pinnedURL = "https://cdn.jsdelivr.net/gh/Mytai20100/csa-js@a3f8c2d1b4e7f6a9c0d2e5b8f1a4c7e0d3b6a9f/csa.js"
		sriHash   = "sha384-PLACEHOLDER-recompute-with-openssl-after-pinning-real-commit"
	)
	return `<script>
        (function(){
            var s=document.createElement('script');
            s.src='/lib/csa.js';
            s.onerror=function(){
                var f=document.createElement('script');
                f.src='` + pinnedURL + `';
                f.integrity='` + sriHash + `';
                f.crossOrigin='anonymous';
                document.head.appendChild(f);
            };
            document.head.appendChild(s);
        })();
    </script>`
}


func LoadSiteSettings() {
	SiteSettingsMu.Lock()
	defer SiteSettingsMu.Unlock()
	SiteSettingsData = SiteSettings{
		Theme:              "default",
		Language:           "en",
		AllowUserTheme:     true,
		ShowDirectLinks:    true,
		EmbedLoaderEnabled: true,
	}
	data, err := os.ReadFile(SiteSettingsFile)
	if err == nil {
		yaml.Unmarshal(data, &SiteSettingsData)
	}
}

func SaveSiteSettings() {
	SiteSettingsMu.RLock()
	defer SiteSettingsMu.RUnlock()
	data, _ := yaml.Marshal(SiteSettingsData)
	os.WriteFile(SiteSettingsFile, data, 0644)
}

// LoadLangStrings loads (or reloads) translations for the given language code.
// Language files are expected at lang/<code>/<code>.yml relative to the working directory.
func LoadLangStrings(code string) map[string]string {
	if code == "" {
		code = "en"
	}
	// Sanitize: only allow alphanumeric and dash/underscore
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, code)
	if safe == "" {
		safe = "en"
	}

	LangCacheMu.RLock()
	if cached, ok := LangCache[safe]; ok {
		LangCacheMu.RUnlock()
		return cached
	}
	LangCacheMu.RUnlock()

	path := "lang/" + safe + "/" + safe + ".yml"
	data, err := os.ReadFile(path)
	if err != nil {
		// Fall back to English
		if safe != "en" {
			return LoadLangStrings("en")
		}
		return map[string]string{}
	}

	var raw map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		log.Printf("[LANG] Failed to parse %s: %v", path, err)
		return map[string]string{}
	}

	LangCacheMu.Lock()
	LangCache[safe] = raw
	LangCacheMu.Unlock()
	return raw
}

// HandleAdminGetSettings returns current site settings.
func HandleAdminGetSettings(w http.ResponseWriter, r *http.Request) {
	SiteSettingsMu.RLock()
	defer SiteSettingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SiteSettingsData)
}

// HandleAdminSaveSettings saves admin-level site settings.
func HandleAdminSaveSettings(w http.ResponseWriter, r *http.Request) {
	var s SiteSettings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	SiteSettingsMu.Lock()
	SiteSettingsData = s
	SiteSettingsMu.Unlock()
	// Invalidate lang cache so new language is loaded fresh on next request
	if s.Language != "" {
		LangCacheMu.Lock()
		delete(LangCache, s.Language)
		LangCacheMu.Unlock()
	}
	go SaveSiteSettings()
	log.Printf("[SETTINGS] Admin saved site settings: lang=%q direct_links=%v allow_user_theme=%v bg=%q",
		s.Language, s.ShowDirectLinks, s.AllowUserTheme, s.BackgroundURL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// HandleUserGetSettings returns settings for the currently logged-in user.
func HandleUserGetSettings(w http.ResponseWriter, r *http.Request) {
	u := GetSessionUser(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// Re-fetch live settings from Users map
	UsersMu.RLock()
	var liveSettings UserSettings
	if live, ok := Users[u.UUID]; ok {
		liveSettings = live.Settings
	}
	UsersMu.RUnlock()
	SiteSettingsMu.RLock()
	allowTheme := SiteSettingsData.AllowUserTheme
	SiteSettingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings":    liveSettings,
		"allow_theme": allowTheme,
	})
}

// HandleUserSaveSettings saves settings for the currently logged-in user.
func HandleUserSaveSettings(w http.ResponseWriter, r *http.Request) {
	u := GetSessionUser(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var s UserSettings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	// Re-fetch from the live Users map to avoid stale pointer
	UsersMu.Lock()
	if live, ok := Users[u.UUID]; ok {
		live.Settings = s
		if Debug {
			log.Printf("[SETTINGS] user=%s saved settings: bg=%q music=%q lang=%q direct_links=%v",
				u.Username, s.BackgroundURL, s.BgMusicURL, s.Language, s.ShowDirectLinks)
		}
	}
	UsersMu.Unlock()
	go SaveUsers()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// HandleLangStrings serves translation strings for the current user/site language.
// GET /api/lang → returns JSON map of translation keys for the active language.
func HandleLangStrings(w http.ResponseWriter, r *http.Request) {
	// Determine language: user setting takes priority over site setting
	lang := ""
	if u := GetSessionUser(r); u != nil {
		UsersMu.RLock()
		if live, ok := Users[u.UUID]; ok {
			lang = live.Settings.Language
		}
		UsersMu.RUnlock()
	}
	if lang == "" {
		SiteSettingsMu.RLock()
		lang = SiteSettingsData.Language
		SiteSettingsMu.RUnlock()
	}
	if lang == "" {
		lang = "en"
	}

	strings := LoadLangStrings(lang)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(strings)
}

