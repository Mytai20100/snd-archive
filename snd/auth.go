package snd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func HandleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		TwoFACode string `json:"twofa_code,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	if creds.Username != Cfg.Username || creds.Password != Cfg.Password {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid credentials",
		})
		return
	}

	if Cfg.Enable2FA {
		if creds.TwoFACode == "" {
			code := GenerateRandomToken(82)
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

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	ip := GetClientIP(r)
	ua := r.UserAgent()
	osName, browser := ParseUserAgent(ua)

	SessionMu.Lock()
	Sessions[sessionID] = &SessionInfo{
		SessionID:  sessionID,
		IP:         ip,
		UserAgent:  ua,
		OS:         osName,
		Browser:    browser,
		LoginTime:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	SessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	LogAccess(ip, "login", "/login", ua)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleSessions(w http.ResponseWriter, r *http.Request) {
	SessionMu.RLock()
	defer SessionMu.RUnlock()

	type SessionDisplay struct {
		SessionID  string `json:"session_id"`
		IP         string `json:"ip"`
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
		sessionList = append(sessionList, SessionDisplay{
			SessionID:  sid,
			IP:         s.IP,
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

	SessionMu.Lock()
	delete(Sessions, req.SessionID)
	SessionMu.Unlock()

	if Debug {
		log.Printf("[DEBUG] Session kicked: %s", req.SessionID)
	}

	w.Header().Set("Content-Type", "application/json")
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

func HandleCFChallenge(w http.ResponseWriter, r *http.Request) {
	returnPath := r.URL.Query().Get("return")
	if returnPath == "" {
		returnPath = "/"
	}
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Checking your browser</title>
    <style>
        body {
            font-family: -apple-system, sans-serif;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; background: #fafafa;
        }
        .challenge-box {
            text-align: center; background: white;
            padding: 40px; border: 1px solid #e0e0e0; max-width: 500px;
        }
        .spinner {
            border: 3px solid #f3f3f3; border-top: 3px solid #1a1a1a;
            border-radius: 50%; width: 50px; height: 50px;
            animation: spin 1s linear infinite; margin: 20px auto;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="challenge-box">
        <h2>Checking your browser</h2>
        <div class="spinner"></div>
        <p>This process is automatic. You will be redirected shortly.</p>
    </div>
    <script>
        setTimeout(() => {
            document.cookie = "cf_passed=true; path=/; max-age=86400";
            window.location.href = "` + returnPath + `";
        }, 3000);
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
