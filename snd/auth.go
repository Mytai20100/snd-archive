package snd

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// formatDuration returns a human-readable ban duration string.
func formatDuration(d time.Duration) string {
	switch {
	case d >= 30*24*time.Hour:
		return "1 month"
	case d >= 7*24*time.Hour:
		return "7 days"
	case d >= 24*time.Hour:
		return "1 day"
	case d >= time.Hour:
		h := int(d.Hours())
		return fmt.Sprintf("%d hour(s)", h)
	default:
		m := int(d.Minutes())
		return fmt.Sprintf("%d minute(s)", m)
	}
}

func HandleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		TwoFACode string `json:"twofa_code,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	w.Header().Set("Content-Type", "application/json")

	// ── Admin brute-force protection ─────────────────────────────────────────
	// Only applied when the submitted username matches the admin username.
	if creds.Username == Cfg.Username {
		ip := GetClientIP(r)
		AdminLoginMu.Lock()
		ban, exists := AdminLoginBans[ip]
		if !exists {
			ban = &AdminLoginBan{}
			AdminLoginBans[ip] = ban
		}
		// Check if currently banned.
		if time.Now().Before(ban.BanExpires) {
			remaining := time.Until(ban.BanExpires).Round(time.Second)
			AdminLoginMu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Too many failed attempts. Try again in %s.", remaining),
				"banned":  true,
			})
			return
		}
		AdminLoginMu.Unlock()
	}

	isAdmin := creds.Username == Cfg.Username && creds.Password == Cfg.Password
	var loginUser *UserAccount

	if !isAdmin {
		// Wrong credentials — check if it's an admin username attempt.
		if creds.Username == Cfg.Username {
			ip := GetClientIP(r)
			AdminLoginMu.Lock()
			ban := AdminLoginBans[ip]
			ban.FailCount++
			d := BanLevel(ban.FailCount)
			failCount := ban.FailCount
			if d > 0 {
				ban.BanExpires = time.Now().Add(d)
				ban.BanDuration = d
			}
			AdminLoginMu.Unlock()
			if d > 0 {
				msg := fmt.Sprintf("Too many failed attempts. Banned for %s.", formatDuration(d))
				log.Printf("[SECURITY] Admin brute-force from %s: attempt #%d, banned %s", ip, failCount, d)
				AppendSecurityEvent(ip, SecEvtLoginBan, fmt.Sprintf("Admin brute-force: attempt #%d, banned %s", failCount, formatDuration(d)), Cfg.Username)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": msg,
					"banned":  true,
				})
				return
			}
			AppendSecurityEvent(ip, SecEvtLoginFail, fmt.Sprintf("Admin login failed (attempt #%d)", ban.FailCount), Cfg.Username)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Invalid credentials",
			})
			return
		}

		// Non-admin user login.
		// L2 FIX: Apply the same brute-force rate-limit to sub-user accounts.
		ip := GetClientIP(r)
		userBanKey := ip + ":" + creds.Username
		UserLoginMu.Lock()
		userBan, exists := UserLoginBans[userBanKey]
		if !exists {
			userBan = &AdminLoginBan{}
			UserLoginBans[userBanKey] = userBan
		}
		if time.Now().Before(userBan.BanExpires) {
			remaining := time.Until(userBan.BanExpires).Round(time.Second)
			UserLoginMu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Too many failed attempts. Try again in %s.", remaining),
				"banned":  true,
			})
			return
		}
		UserLoginMu.Unlock()

		u := GetUserByUsername(creds.Username)
		if u == nil || !u.IsActive || !CheckPassword(u.PasswordHash, creds.Password) {
			// Record the failure and possibly ban.
			UserLoginMu.Lock()
			userBan.FailCount++
			d := BanLevel(userBan.FailCount)
			if d > 0 {
				userBan.BanExpires = time.Now().Add(d)
				userBan.BanDuration = d
			}
			UserLoginMu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Invalid credentials",
			})
			return
		}
		// Successful sub-user login — clear ban record.
		UserLoginMu.Lock()
		delete(UserLoginBans, userBanKey)
		UserLoginMu.Unlock()
		loginUser = u
	}

	// Successful admin login — clear ban record.
	if isAdmin {
		ip := GetClientIP(r)
		AdminLoginMu.Lock()
		delete(AdminLoginBans, ip)
		AdminLoginMu.Unlock()
	}

	// 2FA only applies to admin
	if isAdmin && Cfg.Enable2FA {
		if creds.TwoFACode == "" {
			code := GenerateRandomToken(16)
			TwoFAMu.Lock()
			TwoFACodes[creds.Username] = TwoFACode{
				Code:      code,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Used:      false,
			}
			TwoFAMu.Unlock()
			if err := send2FACodeToDiscord(creds.Username, code); err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "Failed to send 2FA code",
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":     false,
				"require_2fa": true,
				"message":     "2FA code sent to Discord. Please check your webhook.",
			})
			return
		}

		TwoFAMu.Lock()
		storedCode, exists := TwoFACodes[creds.Username]
		TwoFAMu.Unlock()
		if !exists || storedCode.Used || time.Now().After(storedCode.ExpiresAt) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "2FA code expired or invalid",
			})
			return
		}
		if creds.TwoFACode != storedCode.Code {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Invalid 2FA code",
			})
			return
		}
		TwoFAMu.Lock()
		storedCode.Used = true
		TwoFACodes[creds.Username] = storedCode
		TwoFAMu.Unlock()
	}

	// FIX: Use crypto/rand for session ID (was time.Now().UnixNano())
	sessionID := GenerateRandomToken(32)
	ip := GetClientIP(r)
	ua := r.UserAgent()
	osName, browser := ParseUserAgent(ua)

	session := &SessionInfo{
		SessionID:  sessionID,
		IP:         ip,
		UserAgent:  ua,
		OS:         osName,
		Browser:    browser,
		LoginTime:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		IsAdmin:    isAdmin, // only true admin account gets IsAdmin=true
	}
	if loginUser != nil {
		session.UserUUID = loginUser.UUID
	}

	SessionMu.Lock()
	Sessions[sessionID] = session
	SessionMu.Unlock()

	// FIX: Set Secure only if connection is actually over TLS.
	// Using Cfg.UseHTTPS here would break HTTP sessions because
	// browsers refuse to send Secure cookies over plain HTTP.
	isHTTPS := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS,
		Path:     "/",
	})

	LogAccess(ip, "login", "/login", ua)

	redirectTo := "/"
	if loginUser != nil {
		redirectTo = "/my"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "redirect": redirectTo})
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	// FIX: Invalidate server-side session on logout
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		SessionMu.Lock()
		delete(Sessions, cookie.Value)
		SessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
	})
	http.Redirect(w, r, "/ac", http.StatusSeeOther)
}

func HandleSessions(w http.ResponseWriter, r *http.Request) {
	SessionMu.RLock()
	defer SessionMu.RUnlock()

	type SessionDisplay struct {
		SessionID  string `json:"session_id"`
		IP         string `json:"ip"`
		Username   string `json:"username"`
		OS         string `json:"os"`
		Browser    string `json:"browser"`
		LoginTime  string `json:"login_time"`
		LastAccess string `json:"last_access"`
		IsCurrent  bool   `json:"is_current"`
	}

	var sessionList []SessionDisplay
	currentCookie, _ := r.Cookie("session")
	currentSessionID := ""
	if currentCookie != nil {
		currentSessionID = currentCookie.Value
	}

	for sid, s := range Sessions {
		username := "admin"
		if !s.IsAdmin && s.UserUUID != "" {
			if u := GetUserByUUID(s.UserUUID); u != nil {
				username = u.Username
			}
		}
		sessionList = append(sessionList, SessionDisplay{
			SessionID:  sid,
			IP:         s.IP,
			Username:   username,
			OS:         s.OS,
			Browser:    s.Browser,
			LoginTime:  s.LoginTime.Format("2006-01-02 15:04:05"),
			LastAccess: s.LastAccess.Format("2006-01-02 15:04:05"),
			IsCurrent:  sid == currentSessionID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionList)
}

func HandleKickSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	w.Header().Set("Content-Type", "application/json")

	// C2 FIX: Determine whether the caller is the true admin (no UserUUID).
	callerSession := GetSessionInfo(r)
	callerIsTrueAdmin := callerSession != nil && callerSession.IsAdmin && callerSession.UserUUID == ""

	SessionMu.Lock()
	target, exists := Sessions[req.SessionID]
	if exists {
		// Only the true admin may kick another admin session.
		// Sub-users with IsAdmin=true cannot kick real-admin sessions.
		targetIsAdmin := target.IsAdmin && target.UserUUID == ""
		if targetIsAdmin && !callerIsTrueAdmin {
			SessionMu.Unlock()
			http.Error(w, "Forbidden: cannot kick admin session", http.StatusForbidden)
			return
		}
		delete(Sessions, req.SessionID)
	}
	SessionMu.Unlock()

	if Debug {
		log.Printf("[DEBUG] Session kicked: %s", req.SessionID)
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleAccessLogs(w http.ResponseWriter, r *http.Request) {
	AccessLogMu.RLock()
	defer AccessLogMu.RUnlock()

	start := 0
	if len(AccessLogs) > 100 {
		start = len(AccessLogs) - 100
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AccessLogs[start:])
}

func send2FACodeToDiscord(username string, code string) error {
	if Cfg.DiscordWebhook == "" {
		return fmt.Errorf("Discord webhook not configured")
	}
	payload := map[string]interface{}{
		"content":  fmt.Sprintf("**2FA Code for %s**\n\n```\n%s\n```\n\nExpires in 5 minutes", username, code),
		"username": Cfg.SiteName,
	}
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(Cfg.DiscordWebhook, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("Discord webhook failed with status: %d", resp.StatusCode)
	}
	return nil
}

// isSafeRedirectPath validates that a redirect path is a relative path only.
func isSafeRedirectPath(p string) bool {
	if p == "" {
		return false
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return false
	}
	return strings.HasPrefix(p, "/")
}

// HandleCFChallenge dispatches GET (show widget) and POST (verify token).
// HIGH-8 FIX: replaced the old unconditional-cookie fake challenge with real
// Cloudflare Turnstile verification.  A bot that simply GETs /cf-challenge and
// replays the Set-Cookie header will no longer receive a cf_passed cookie,
// because the cookie is only issued after the Turnstile token is verified
// server-side against https://challenges.cloudflare.com/turnstile/v0/siteverify.
func HandleCFChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		handleCFChallengeVerify(w, r)
	} else {
		handleCFChallengeGET(w, r)
	}
}

// handleCFChallengeGET renders the Turnstile challenge widget.
// If no site key is configured, it falls back to the old spinner page so that
// the server remains usable even without Turnstile credentials set up.
func handleCFChallengeGET(w http.ResponseWriter, r *http.Request) {
	returnPath := r.URL.Query().Get("return")
	if !isSafeRedirectPath(returnPath) {
		returnPath = "/"
	}
	safeReturn := html.EscapeString(returnPath)

	SiteSettingsMu.RLock()
	siteKey := SiteSettingsData.TurnstileSiteKey
	SiteSettingsMu.RUnlock()

	var pageHTML string
	if siteKey == "" {
		// Fallback: Turnstile not configured — show a notice instead of silently
		// granting access.  Admin should configure TurnstileSiteKey + TurnstileSecretKey
		// in Settings to enable real verification.
		pageHTML = `<!DOCTYPE html>
<html>
<head><title>Challenge not configured</title>
<style>body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#fafafa;}
.box{text-align:center;background:white;padding:40px;border:1px solid #e0e0e0;max-width:500px;border-radius:4px;}
p{color:#666;font-size:14px;}</style></head>
<body><div class="box">
<h2>Browser check unavailable</h2>
<p>Cloudflare Turnstile is not configured on this server.<br>
Contact the administrator to set up <strong>turnstile_site_key</strong> and <strong>turnstile_secret_key</strong> in Settings.</p>
</div></body></html>`
	} else {
		pageHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Checking your browser</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body { font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; background: #fafafa; }
        .challenge-box { text-align: center; background: white; padding: 40px; border: 1px solid #e0e0e0; max-width: 500px; border-radius: 4px; }
        h2 { margin-bottom: 24px; }
        p { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="challenge-box">
        <h2>Checking your browser</h2>
        <form method="POST" action="/cf-challenge" id="cf-form">
            <div class="cf-turnstile"
                 data-sitekey="` + html.EscapeString(siteKey) + `"
                 data-callback="onTurnstileSuccess"></div>
            <input type="hidden" name="return" value="` + safeReturn + `">
        </form>
        <p>Completing this check confirms you are a human.</p>
    </div>
    <script>
        function onTurnstileSuccess(token) {
            document.getElementById('cf-form').submit();
        }
    </script>
</body>
</html>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

// handleCFChallengeVerify receives the POST from the Turnstile widget, verifies
// the cf-turnstile-response token with Cloudflare's siteverify API, and — only
// on success — issues the cf_passed cookie and redirects the user onward.
func handleCFChallengeVerify(w http.ResponseWriter, r *http.Request) {
	returnPath := r.FormValue("return")
	if !isSafeRedirectPath(returnPath) {
		returnPath = "/"
	}

	SiteSettingsMu.RLock()
	siteKey    := SiteSettingsData.TurnstileSiteKey
	secretKey  := SiteSettingsData.TurnstileSecretKey
	SiteSettingsMu.RUnlock()

	// If keys are not configured, deny — do not fall back to granting access.
	if siteKey == "" || secretKey == "" {
		http.Error(w, "Challenge not configured", http.StatusServiceUnavailable)
		return
	}

	token := r.FormValue("cf-turnstile-response")
	if token == "" {
		// No token submitted — send back to challenge page.
		http.Redirect(w, r, "/cf-challenge?return="+url.QueryEscape(returnPath), http.StatusSeeOther)
		return
	}

	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify",
		url.Values{
			"secret":   {secretKey},
			"response": {token},
			"remoteip": {GetClientIP(r)},
		})
	if err != nil {
		log.Printf("[CF-CHALLENGE] siteverify request failed: %v", err)
		http.Redirect(w, r, "/cf-challenge?return="+url.QueryEscape(returnPath), http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.Success {
		// Failed verification — redirect back to challenge (do NOT set cookie).
		http.Redirect(w, r, "/cf-challenge?return="+url.QueryEscape(returnPath), http.StatusSeeOther)
		return
	}

	// Verified — issue the cf_passed cookie and redirect.
	isHTTPS := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     "cf_passed",
		Value:    "true",
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, returnPath, http.StatusSeeOther)
}
