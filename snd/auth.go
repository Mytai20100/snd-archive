package snd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

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
		WebRTCIP  string `json:"webrtc_ip,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	w.Header().Set("Content-Type", "application/json")

	if creds.Username == Cfg.Username {
		ip := GetClientIP(r)
		AdminLoginMu.Lock()
		ban, exists := AdminLoginBans[ip]
		if !exists {
			ban = &AdminLoginBan{}
			AdminLoginBans[ip] = ban
		}
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
		UserLoginMu.Lock()
		delete(UserLoginBans, userBanKey)
		UserLoginMu.Unlock()
		loginUser = u
	}

	if isAdmin {
		ip := GetClientIP(r)
		AdminLoginMu.Lock()
		delete(AdminLoginBans, ip)
		AdminLoginMu.Unlock()
	}

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

	sessionID := GenerateRandomToken(32)
	ip := GetClientIP(r)
	webrtcIP := NormalizeWebRTCIP(creds.WebRTCIP)
	ua := r.UserAgent()
	osName, browser := ParseUserAgent(ua)

	session := &SessionInfo{
		SessionID:  sessionID,
		IP:         ip,
		WebRTCIP:   webrtcIP,
		UserAgent:  ua,
		OS:         osName,
		Browser:    browser,
		LoginTime:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		IsAdmin:    isAdmin,
	}
	if loginUser != nil {
		session.UserUUID = loginUser.UUID
	}

	SessionMu.Lock()
	Sessions[sessionID] = session
	SessionMu.Unlock()

	isHTTPS := requestIsHTTPS(r)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS,
		Path:     "/",
	})

	LogAccess(ip, "login", "/login", ua, webrtcIP)

	redirectTo := "/"
	if loginUser != nil {
		redirectTo = "/my"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "redirect": redirectTo})
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
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
		WebRTCIP   string `json:"webrtc_ip,omitempty"`
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
			WebRTCIP:   s.WebRTCIP,
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

	callerSession := GetSessionInfo(r)
	callerIsTrueAdmin := callerSession != nil && callerSession.IsAdmin && callerSession.UserUUID == ""

	SessionMu.Lock()
	target, exists := Sessions[req.SessionID]
	if exists {
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
