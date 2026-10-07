package snd

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	challengeCookieName = "cf_trust"
	challengeActionName = "snd_challenge"
	challengeHeaderName = "X-Challenge"
)

var (
	challengeSecretMu   sync.RWMutex
	challengeSecret     []byte
	challengeVerifyMu   sync.Mutex
	challengeVerifySeen = make(map[string][]time.Time)
)

var challengeProtectedPrefixes = []string{
	"/download/",
	"/view/",
	"/stream/",
	"/play/",
	"/embed/",
	"/api/view/",
	"/thumbnail/",
	"/raw/",
	"/folder/",
	"/zip-view/",
}

var challengeProtectedExact = map[string]bool{
	"/":             true,
	"/my":           true,
	"/public-files": true,
	"/files":        true,
}

func ensureChallengeSecret() []byte {
	challengeSecretMu.RLock()
	s := challengeSecret
	challengeSecretMu.RUnlock()
	if len(s) > 0 {
		return s
	}
	SiteSettingsMu.RLock()
	hexSecret := SiteSettingsData.ChallengeSecret
	SiteSettingsMu.RUnlock()
	if hexSecret != "" {
		if raw, err := hex.DecodeString(hexSecret); err == nil && len(raw) >= 32 {
			challengeSecretMu.Lock()
			challengeSecret = raw
			challengeSecretMu.Unlock()
			return raw
		}
	}
	raw := []byte(GenerateRandomToken(32))
	challengeSecretMu.Lock()
	challengeSecret = raw
	challengeSecretMu.Unlock()
	SiteSettingsMu.Lock()
	SiteSettingsData.ChallengeSecret = hex.EncodeToString(raw)
	SiteSettingsMu.Unlock()
	go SaveSiteSettings()
	return raw
}

func challengeSecretBytes() []byte {
	return ensureChallengeSecret()
}

func challengeUserAgentHash(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:8])
}

func challengeSign(payload string) string {
	mac := hmac.New(sha256.New, challengeSecretBytes())
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type challengeClaims struct {
	IP  string `json:"ip"`
	UA  string `json:"ua"`
	Exp int64  `json:"exp"`
}

func issueChallengeToken(ip, ua string, ttl time.Duration) string {
	claims := challengeClaims{
		IP:  ip,
		UA:  challengeUserAgentHash(ua),
		Exp: time.Now().Add(ttl).Unix(),
	}
	body, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + challengeSign(payload)
}

func verifyChallengeToken(token, ip, ua string) bool {
	if token == "" {
		return false
	}
	dot := strings.LastIndex(token, ".")
	if dot <= 0 {
		return false
	}
	payload := token[:dot]
	sig := token[dot+1:]
	want := challengeSign(payload)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var claims challengeClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return false
	}
	if claims.Exp <= time.Now().Unix() {
		return false
	}
	if claims.IP == "" || claims.IP != ip {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(claims.UA), []byte(challengeUserAgentHash(ua))) != 1 {
		return false
	}
	return true
}

func hasValidChallengeTrust(r *http.Request) bool {
	cookie, err := r.Cookie(challengeCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return verifyChallengeToken(cookie.Value, GetClientIP(r), r.UserAgent())
}

func setChallengeTrustCookie(w http.ResponseWriter, r *http.Request) {
	SiteSettingsMu.RLock()
	minutes := SiteSettingsData.ChallengeTrustMinutes
	SiteSettingsMu.RUnlock()
	if minutes <= 0 {
		minutes = 1440
	}
	ttl := time.Duration(minutes) * time.Minute
	http.SetCookie(w, &http.Cookie{
		Name:     challengeCookieName,
		Value:    issueChallengeToken(GetClientIP(r), r.UserAgent(), ttl),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func challengeEnabled() bool {
	SiteSettingsMu.RLock()
	defer SiteSettingsMu.RUnlock()
	return SiteSettingsData.ChallengeEnabled
}

func challengeIsProtectedPath(p string) bool {
	if challengeProtectedExact[p] {
		return true
	}
	for _, pre := range challengeProtectedPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func challengeIsNavigationRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") {
		return true
	}
	if r.Header.Get("X-Requested-With") != "" {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/html")
}

func challengeClientIsTrusted(r *http.Request) bool {
	if hasValidChallengeTrust(r) {
		return true
	}
	if getValidSession(r) != nil {
		return true
	}
	if requestHasValidAPIToken(r) {
		return true
	}
	if isPreviewBot(r) && isPreviewBotPublicPath(r) && resourceIsPublic(r) {
		return true
	}
	return false
}

const challengeShellHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<link rel="stylesheet" href="/css/main.css">
<style>html,body{margin:0;min-height:100%;background:#fafafa}</style>
</head>
<body>
<div id="challengeRoot"></div>
<script src="/lib/challenge.js"></script>
</body>
</html>
`

func ChallengeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !challengeEnabled() || !challengeIsProtectedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if challengeClientIsTrusted(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Vary", "Cookie")
		w.Header().Set(challengeHeaderName, "required")
		if challengeIsNavigationRequest(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			if r.Method != http.MethodHead {
				w.Write([]byte(challengeShellHTML))
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if r.Method != http.MethodHead {
			w.Write([]byte(`{"error":"challenge_required"}`))
		}
	})
}

func challengeRateLimit(ip string, limit int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)
	challengeVerifyMu.Lock()
	defer challengeVerifyMu.Unlock()
	times := challengeVerifySeen[ip]
	pruned := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	if len(pruned) >= limit {
		challengeVerifySeen[ip] = pruned
		return false
	}
	challengeVerifySeen[ip] = append(pruned, now)
	if len(challengeVerifySeen) > 4096 {
		for k, v := range challengeVerifySeen {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(challengeVerifySeen, k)
			}
		}
	}
	return true
}

type challengeVerifyRequest struct {
	Token string `json:"token"`
}

type challengeVerifyResponse struct {
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	SiteKey    string `json:"site_key,omitempty"`
	Theme      string `json:"theme,omitempty"`
	Appearance string `json:"appearance,omitempty"`
	Configured bool   `json:"configured"`
}

func challengeJSONError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   code,
	})
}

func HandleChallengeConfig(w http.ResponseWriter, r *http.Request) {
	SiteSettingsMu.RLock()
	defer SiteSettingsMu.RUnlock()
	minutes := SiteSettingsData.ChallengeTrustMinutes
	if minutes <= 0 {
		minutes = 1440
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(challengeVerifyResponse{
		Success:    true,
		SiteKey:    SiteSettingsData.TurnstileSiteKey,
		Theme:      SiteSettingsData.ChallengeTheme,
		Appearance: SiteSettingsData.ChallengeAppearance,
		Configured: SiteSettingsData.TurnstileSiteKey != "" && SiteSettingsData.TurnstileSecretKey != "",
	})
}

func HandleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		challengeJSONError(w, "method_not_allowed")
		return
	}

	ip := GetClientIP(r)
	if !challengeRateLimit(ip, 20, 5*time.Minute) {
		AppendSecurityEvent(ip, SecEvtChallengeFail, "challenge verify rate limit exceeded", "")
		challengeJSONError(w, "rate_limited")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil {
		challengeJSONError(w, "bad_request")
		return
	}
	var req challengeVerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		challengeJSONError(w, "bad_request")
		return
	}
	if req.Token == "" || len(req.Token) > 2048 {
		challengeJSONError(w, "bad_request")
		return
	}

	SiteSettingsMu.RLock()
	siteKey := SiteSettingsData.TurnstileSiteKey
	secretKey := SiteSettingsData.TurnstileSecretKey
	SiteSettingsMu.RUnlock()

	if siteKey == "" || secretKey == "" {
		log.Printf("[CHALLENGE] enabled but Turnstile keys are missing")
		challengeJSONError(w, "not_configured")
		return
	}

	host := trustedHeader(r, "X-Forwarded-Host")
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if base := Cfg.PublicBaseURL; base != "" {
		if u := parseURLHost(base); u != "" {
			host = u
		}
	}

	result, err := siteverifyTurnstile(secretKey, req.Token, ip, host)
	if err != nil {
		AppendSecurityEvent(ip, SecEvtChallengeFail, "siteverify request failed: "+err.Error(), "")
		challengeJSONError(w, "verify_unavailable")
		return
	}
	if !result.Success {
		reason := "siteverify rejected"
		if len(result.ErrorCodes) > 0 {
			reason = "siteverify error-codes: " + strings.Join(result.ErrorCodes, ",")
		}
		AppendSecurityEvent(ip, SecEvtChallengeFail, reason, "")
		challengeJSONError(w, "verification_failed")
		return
	}
	if result.Hostname != "" && host != "" && !strings.EqualFold(result.Hostname, host) {
		AppendSecurityEvent(ip, SecEvtChallengeFail, "siteverify hostname mismatch: got "+result.Hostname+" want "+host, "")
		challengeJSONError(w, "hostname_mismatch")
		return
	}
	if result.Action != "" && result.Action != challengeActionName {
		AppendSecurityEvent(ip, SecEvtChallengeFail, "siteverify action mismatch: got "+result.Action, "")
		challengeJSONError(w, "action_mismatch")
		return
	}
	if len(result.ErrorCodes) > 0 {
		log.Printf("[CHALLENGE] siteverify success with error-codes: %s", strings.Join(result.ErrorCodes, ","))
	}

	setChallengeTrustCookie(w, r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

type turnstileResult struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	Cdata      string   `json:"cdata"`
}

func siteverifyTurnstile(secret, token, ip, host string) (*turnstileResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	form := strings.NewReader(strings.Join([]string{
		"secret=" + urlQueryEscape(secret),
		"response=" + urlQueryEscape(token),
		"remoteip=" + urlQueryEscape(ip),
		"idempotency_key=" + urlQueryEscape(GenerateRandomToken(16)),
	}, "&"))
	req, err := http.NewRequest(http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var out turnstileResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			const hexdigits = "0123456789ABCDEF"
			b.WriteByte(hexdigits[c>>4])
			b.WriteByte(hexdigits[c&0x0f])
		}
	}
	return b.String()
}

func parseURLHost(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.Index(rest, "@"); j >= 0 {
		rest = rest[j+1:]
	}
	return rest
}

func ChallengeMisconfigured() bool {
	if !challengeEnabled() {
		return false
	}
	SiteSettingsMu.RLock()
	defer SiteSettingsMu.RUnlock()
	return SiteSettingsData.TurnstileSiteKey == "" || SiteSettingsData.TurnstileSecretKey == ""
}
