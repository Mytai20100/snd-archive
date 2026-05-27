package snd

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
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
	// QR Code generation
	AllowQR    bool   `yaml:"allow_qr"     json:"allow_qr"`
	QRLogoURL  string `yaml:"qr_logo_url"  json:"qr_logo_url"`
	// Share page: whether to include user public files/folders in /share listing
	ShowUserPublicOnShare bool `yaml:"show_user_public_on_share" json:"show_user_public_on_share"`
	// HIGH-8 FIX: Cloudflare Turnstile keys for real bot challenge.
	// TurnstileSecretKey is never sent to the client (omitted from JSON).
	TurnstileSiteKey   string `yaml:"turnstile_site_key"   json:"turnstile_site_key"`
	TurnstileSecretKey string `yaml:"turnstile_secret_key" json:"-"`
	// ── MCP Server (admin) ───────────────────────────────────────────────────
	// AdminMCP configures the admin-level MCP server endpoint.
	// Uses the server's own API token from config.yml — never a user token.
	AdminMCP AdminMCPSettings `yaml:"admin_mcp" json:"admin_mcp"`
	// AllowUserMCP controls whether sub-users can enable their own MCP server.
	// User MCP is always isolated: it uses the user's own API token only.
	AllowUserMCP bool `yaml:"allow_user_mcp" json:"allow_user_mcp"`
	// UserMCPDefaultPerms are the maximum permissions a user MCP can have.
	// Admin cannot grant users more than these limits.
	UserMCPDefaultPerms MCPPermissions `yaml:"user_mcp_default_perms" json:"user_mcp_default_perms"`
}

// UserSettings is defined in types.go (includes MCP field).

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
		Theme:                "default",
		Language:             "en",
		AllowUserTheme:       true,
		ShowDirectLinks:      true,
		EmbedLoaderEnabled:   true,
		ShowUserPublicOnShare: true,
		// Admin MCP: disabled by default, no permissions until admin enables
		AdminMCP: AdminMCPSettings{
			Enabled:   false,
			RateLimit: 60,
			Permissions: MCPPermissions{
				CanRead: true, // read-only as safe default
			},
		},
		// User MCP: disabled globally by default
		AllowUserMCP: false,
		UserMCPDefaultPerms: MCPPermissions{
			CanRead:    true,
			CanUpload:  false,
			CanDelete:  false,
			CanCreate:  false,
			CanRename:  false,
			CanStorage: true,
			CanUsers:   false, // users can NEVER manage users via MCP
		},
	}
	data, err := os.ReadFile(SiteSettingsFile)
	if err == nil {
		yaml.Unmarshal(data, &SiteSettingsData)
		// Re-apply defaults for boolean fields added after initial release.
		// yaml.Unmarshal sets absent bool fields to false (zero value), overriding our defaults.
		// We detect this by checking whether the key is literally present in the raw file bytes.
		if !strings.Contains(string(data), "show_user_public_on_share") {
			SiteSettingsData.ShowUserPublicOnShare = true
		}
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
	// CRIT-1 FIX: Validate CustomCSS to prevent CSS injection / stored XSS.
	// Block tags that can break out of the <style> context.
	if strings.Contains(s.CustomCSS, "</style") || strings.Contains(s.CustomCSS, "<script") ||
		strings.Contains(s.CustomCSS, "javascript:") {
		http.Error(w, `{"error":"invalid css: forbidden content"}`, http.StatusBadRequest)
		return
	}
	// MED-4 FIX: Validate URL fields to only allow http/https schemes.
	for _, rawURL := range []string{s.BackgroundURL, s.BgMusicURL, s.EmbedImageURL, s.QRLogoURL} {
		if rawURL == "" {
			continue
		}
		if !isValidHTTPURL(rawURL) {
			http.Error(w, `{"error":"invalid url: only http/https allowed"}`, http.StatusBadRequest)
			return
		}
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
	allowTheme  := SiteSettingsData.AllowUserTheme
	allowQR     := SiteSettingsData.AllowQR
	qrLogoURL   := SiteSettingsData.QRLogoURL
	allowMCP    := SiteSettingsData.AllowUserMCP
	mcpMaxPerms := SiteSettingsData.UserMCPDefaultPerms
	SiteSettingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings":       liveSettings,
		"allow_theme":    allowTheme,
		"allow_qr":       allowQR,
		"qr_logo_url":    qrLogoURL,
		"allow_mcp":      allowMCP,
		"mcp_max_perms":  mcpMaxPerms,
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

	// SECURITY: Clamp user MCP permissions to admin-defined maximums.
	// A user cannot request permissions that admin hasn't allowed globally.
	SiteSettingsMu.RLock()
	allowMCP    := SiteSettingsData.AllowUserMCP
	mcpMaxPerms := SiteSettingsData.UserMCPDefaultPerms
	SiteSettingsMu.RUnlock()

	if !allowMCP {
		// Admin disabled user MCP — force it off regardless of what user sent
		s.MCP.Enabled = false
	}
	// Clamp each permission bit: user cannot exceed admin-set maximum
	s.MCP.Permissions.CanRead    = s.MCP.Permissions.CanRead    && mcpMaxPerms.CanRead
	s.MCP.Permissions.CanUpload  = s.MCP.Permissions.CanUpload  && mcpMaxPerms.CanUpload
	s.MCP.Permissions.CanDelete  = s.MCP.Permissions.CanDelete  && mcpMaxPerms.CanDelete
	s.MCP.Permissions.CanCreate  = s.MCP.Permissions.CanCreate  && mcpMaxPerms.CanCreate
	s.MCP.Permissions.CanRename  = s.MCP.Permissions.CanRename  && mcpMaxPerms.CanRename
	s.MCP.Permissions.CanStorage = s.MCP.Permissions.CanStorage && mcpMaxPerms.CanStorage
	// Users can NEVER manage other users via MCP — regardless of admin settings
	s.MCP.Permissions.CanUsers = false

	// Re-fetch from the live Users map to avoid stale pointer
	UsersMu.Lock()
	if live, ok := Users[u.UUID]; ok {
		live.Settings = s
		if Debug {
			log.Printf("[SETTINGS] user=%s saved settings: bg=%q music=%q lang=%q direct_links=%v mcp_enabled=%v",
				u.Username, s.BackgroundURL, s.BgMusicURL, s.Language, s.ShowDirectLinks, s.MCP.Enabled)
		}
	}
	UsersMu.Unlock()
	go SaveUsers()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// isValidHTTPURL returns true if s is a valid http or https URL (or empty).
// Used to validate URL fields in SiteSettings before saving.
func isValidHTTPURL(s string) bool {
	if s == "" {
		return true
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
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

