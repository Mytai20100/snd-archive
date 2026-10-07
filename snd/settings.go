package snd

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type SiteSettings struct {
	Theme                 string `yaml:"theme"            json:"theme"`
	BackgroundURL         string `yaml:"background_url"   json:"background_url"`
	BgMusicURL            string `yaml:"bg_music_url"     json:"bg_music_url"`
	Language              string `yaml:"language"         json:"language"`
	AllowUserTheme        bool   `yaml:"allow_user_theme"  json:"allow_user_theme"`
	ShowDirectLinks       bool   `yaml:"show_direct_links" json:"show_direct_links"`
	HideFooter            bool   `yaml:"hide_footer"       json:"hide_footer"`
	CustomCSS             string `yaml:"custom_css"        json:"custom_css"`
	EmbedTitle            string `yaml:"embed_title"        json:"embed_title"`
	EmbedDescription      string `yaml:"embed_description"  json:"embed_description"`
	EmbedImageURL         string `yaml:"embed_image_url"    json:"embed_image_url"`
	EmbedLoaderEnabled    bool   `yaml:"embed_loader_enabled" json:"embed_loader_enabled"`
	AllowQR               bool   `yaml:"allow_qr"     json:"allow_qr"`
	QRLogoURL             string `yaml:"qr_logo_url"  json:"qr_logo_url"`
	ShowUserPublicOnShare bool   `yaml:"show_user_public_on_share" json:"show_user_public_on_share"`
	TurnstileSiteKey      string `yaml:"turnstile_site_key"      json:"turnstile_site_key"`
	TurnstileSecretKey    string `yaml:"turnstile_secret_key"    json:"-"`
	ChallengeEnabled      bool   `yaml:"challenge_enabled"       json:"challenge_enabled"`
	ChallengeTheme        string `yaml:"challenge_theme"         json:"challenge_theme"`
	ChallengeAppearance   string `yaml:"challenge_appearance"    json:"challenge_appearance"`
	ChallengeTrustMinutes int    `yaml:"challenge_trust_minutes" json:"challenge_trust_minutes"`
	ChallengeSecret       string `yaml:"challenge_secret"        json:"-"`
}

var (
	SiteSettingsData SiteSettings
	SiteSettingsMu   sync.RWMutex
	SiteSettingsFile = "settings.yml"

	LangCache   = make(map[string]map[string]string)
	LangCacheMu sync.RWMutex
)

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

func EmbedLoaderSnippet() string {
	SiteSettingsMu.RLock()
	enabled := SiteSettingsData.EmbedLoaderEnabled
	SiteSettingsMu.RUnlock()
	if !enabled {
		return ""
	}
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
		Theme:                 "default",
		Language:              "en",
		AllowUserTheme:        true,
		ShowDirectLinks:       true,
		EmbedLoaderEnabled:    true,
		ShowUserPublicOnShare: true,
		ChallengeEnabled:      Cfg.CloudflareChallenge,
		ChallengeTheme:        "auto",
		ChallengeAppearance:   "always",
		ChallengeTrustMinutes: 1440,
	}
	data, err := os.ReadFile(SiteSettingsFile)
	if err == nil {
		yaml.Unmarshal(data, &SiteSettingsData)
		if !strings.Contains(string(data), "show_user_public_on_share") {
			SiteSettingsData.ShowUserPublicOnShare = true
		}
		if !strings.Contains(string(data), "challenge_enabled") && Cfg.CloudflareChallenge {
			SiteSettingsData.ChallengeEnabled = true
		}
		if SiteSettingsData.ChallengeTrustMinutes <= 0 {
			SiteSettingsData.ChallengeTrustMinutes = 1440
		}
		if SiteSettingsData.ChallengeTheme == "" {
			SiteSettingsData.ChallengeTheme = "auto"
		}
		if SiteSettingsData.ChallengeAppearance == "" {
			SiteSettingsData.ChallengeAppearance = "always"
		}
	}
}

func SaveSiteSettings() {
	SiteSettingsMu.RLock()
	defer SiteSettingsMu.RUnlock()
	data, _ := yaml.Marshal(SiteSettingsData)
	os.WriteFile(SiteSettingsFile, data, 0644)
}

func LoadLangStrings(code string) map[string]string {
	if code == "" {
		code = "en"
	}
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
		if safe != "en" {
			return LoadLangStrings("en")
		}
		return map[string]string{}
	}

	var raw map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		log.Printf("[LANG] Failed to parse %s: %v", path, err)
		raw = map[string]string{}
	}
	if safe != "en" {
		base := loadLangStringsBase()
		for k, v := range base {
			if _, ok := raw[k]; !ok {
				raw[k] = v
			}
		}
	}

	LangCacheMu.Lock()
	LangCache[safe] = raw
	LangCacheMu.Unlock()
	return raw
}

func loadLangStringsBase() map[string]string {
	basePath := "lang/en/en.yml"
	data, err := os.ReadFile(basePath)
	if err != nil {
		return map[string]string{}
	}
	var raw map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return map[string]string{}
	}
	LangCacheMu.Lock()
	LangCache["en"] = raw
	LangCacheMu.Unlock()
	return raw
}

func HandleAdminGetSettings(w http.ResponseWriter, r *http.Request) {
	SiteSettingsMu.RLock()
	snapshot := SiteSettingsData
	SiteSettingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings":             snapshot,
		"trusted_proxies":      Cfg.TrustedProxies,
		"trusted_proxy":        Cfg.TrustedProxy,
		"public_base_url":      Cfg.PublicBaseURL,
		"turnstile_secret_set": snapshot.TurnstileSecretKey != "",
	})
}

func HandleAdminSaveSettings(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	var s SiteSettings
	if err := json.Unmarshal(body, &s); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	var cfgPart *struct {
		TrustedProxies     *[]string `json:"trusted_proxies"`
		PublicBaseURL      *string   `json:"public_base_url"`
		TurnstileSecretKey *string   `json:"turnstile_secret_key"`
	}
	if err := json.Unmarshal(body, &cfgPart); err != nil {
		cfgPart = nil
	}
	if strings.Contains(s.CustomCSS, "</style") || strings.Contains(s.CustomCSS, "<script") ||
		strings.Contains(s.CustomCSS, "javascript:") {
		http.Error(w, `{"error":"invalid css: forbidden content"}`, http.StatusBadRequest)
		return
	}
	switch s.ChallengeTheme {
	case "auto", "light", "dark":
	default:
		s.ChallengeTheme = "auto"
	}
	switch s.ChallengeAppearance {
	case "always", "interaction-only":
	default:
		s.ChallengeAppearance = "always"
	}
	if s.ChallengeTrustMinutes <= 0 {
		s.ChallengeTrustMinutes = 1440
	}
	if cfgPart != nil && cfgPart.TurnstileSecretKey != nil && *cfgPart.TurnstileSecretKey != "" {
		s.TurnstileSecretKey = *cfgPart.TurnstileSecretKey
	}
	if s.TurnstileSecretKey == "" {
		SiteSettingsMu.RLock()
		s.TurnstileSecretKey = SiteSettingsData.TurnstileSecretKey
		SiteSettingsMu.RUnlock()
	}
	if s.ChallengeSecret == "" {
		SiteSettingsMu.RLock()
		s.ChallengeSecret = SiteSettingsData.ChallengeSecret
		SiteSettingsMu.RUnlock()
	}
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
	if s.Language != "" {
		LangCacheMu.Lock()
		delete(LangCache, s.Language)
		LangCacheMu.Unlock()
	}
	if cfgPart != nil && (cfgPart.TrustedProxies != nil || cfgPart.PublicBaseURL != nil) {
		if cfgPart.PublicBaseURL != nil {
			if *cfgPart.PublicBaseURL != "" && !isValidHTTPURL(*cfgPart.PublicBaseURL) {
				http.Error(w, `{"error":"invalid public_base_url: only http/https allowed"}`, http.StatusBadRequest)
				return
			}
			Cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(*cfgPart.PublicBaseURL), "/")
		}
		if cfgPart.TrustedProxies != nil {
			Cfg.TrustedProxies = *cfgPart.TrustedProxies
		}
		resetTrustedProxyCache()
		SaveConfig()
	}
	go SaveSiteSettings()
	log.Printf("[SETTINGS] Admin saved site settings: lang=%q direct_links=%v allow_user_theme=%v bg=%q",
		s.Language, s.ShowDirectLinks, s.AllowUserTheme, s.BackgroundURL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleUserGetSettings(w http.ResponseWriter, r *http.Request) {
	u := GetSessionUser(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	UsersMu.RLock()
	var liveSettings UserSettings
	if live, ok := Users[u.UUID]; ok {
		liveSettings = live.Settings
	}
	UsersMu.RUnlock()
	SiteSettingsMu.RLock()
	allowTheme := SiteSettingsData.AllowUserTheme
	allowQR := SiteSettingsData.AllowQR
	qrLogoURL := SiteSettingsData.QRLogoURL
	SiteSettingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings":    liveSettings,
		"allow_theme": allowTheme,
		"allow_qr":    allowQR,
		"qr_logo_url": qrLogoURL,
	})
}

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

func isValidHTTPURL(s string) bool {
	if s == "" {
		return true
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func activeLangStrings(r *http.Request) map[string]string {
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
	return LoadLangStrings(lang)
}

func HandleLangStrings(w http.ResponseWriter, r *http.Request) {
	strings := activeLangStrings(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(strings)
}
