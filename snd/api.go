package snd

import (
	"crypto/subtle"

	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// tokenEqual does constant-time comparison to prevent timing attacks.
func tokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// RequireAdmin ensures only the admin account (or sub-users with IsAdmin=true) can access the handler.
func RequireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getValidSession(r)
		if session == nil {
			http.Redirect(w, r, "/ac", http.StatusSeeOther)
			return
		}
		// True admin OR sub-user with IsAdmin flag
		isAdminAccess := session.IsAdmin
		if !isAdminAccess && session.UserUUID != "" {
			if u := GetUserByUUID(session.UserUUID); u != nil && u.IsAdmin {
				isAdminAccess = true
			}
		}
		if !isAdminAccess {
			http.Error(w, "Forbidden: admin access required", http.StatusForbidden)
			return
		}
		session.LastAccess = time.Now()
		handler(w, r)
	}
}

// RequireAuth allows both admin and active sub-users.
func RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getValidSession(r)
		if session == nil {
			http.Redirect(w, r, "/ac", http.StatusSeeOther)
			return
		}
		session.LastAccess = time.Now()
		handler(w, r)
	}
}

// RequireToken validates admin API token only.
func RequireToken(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filename := ExtractFilename(r.URL.Path)
		PermissionMu.RLock()
		perm, exists := FilePermissions[filename]
		PermissionMu.RUnlock()
		if exists && perm.IsPublic {
			handler(w, r)
			return
		}
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		if !tokenEqual(token, Cfg.APIToken) {
			http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

// RequireTokenOrAuth allows public files, token holders (admin or user), or logged-in sessions.
func RequireTokenOrAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var fullPath string
		switch {
		case strings.HasPrefix(r.URL.Path, "/view/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/view/")
		case strings.HasPrefix(r.URL.Path, "/download/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/download/")
		case strings.HasPrefix(r.URL.Path, "/stream/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/stream/")
		case strings.HasPrefix(r.URL.Path, "/embed/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/embed/")
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/raw/")
		case strings.HasPrefix(r.URL.Path, "/api/view/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/api/view/")
		case strings.HasPrefix(r.URL.Path, "/thumbnail/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/thumbnail/")
		default:
			fullPath = r.URL.Path
		}

		// SECURITY FIX: use full relative path as key, matching how HandleSetPermission stores it.
		// Previously used filepath.Base() which caused files in subfolders to never match their
		// stored permission key, making them always fall through to session-required check.
		// Also: a file set to IsPublic=false must be treated as private — existence alone is not enough.
		folderPath := filepath.Dir(fullPath)
		if folderPath == "." {
			folderPath = ""
		}

		PermissionMu.RLock()
		filePerm, fileExists := FilePermissions[fullPath]
		folderPerm, folderExists := FolderPermissions[folderPath]
		PermissionMu.RUnlock()

		// Public only if explicitly set to IsPublic=true.
		// If set to false (private), block even if entry exists.
		fileIsPublic := fileExists && filePerm.IsPublic
		folderIsPublic := folderExists && folderPerm.IsPublic
		if fileIsPublic || folderIsPublic {
			handler(w, r)
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		if tokenEqual(token, Cfg.APIToken) || GetUserByToken(token) != nil {
			handler(w, r)
			return
		}

		session := getValidSession(r)
		if session != nil {
			handler(w, r)
			return
		}

		http.Redirect(w, r, "/error?code=401&path="+r.URL.Path, http.StatusSeeOther)
	}
}

func ObfuscateHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "")
		w.Header().Set("X-Powered-By", "")
		next(w, r)
	}
}

func CfChallengeMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("cf_passed")
		if err != nil || cookie.Value != "true" {
			// FIX: preserve full path + query string for proper redirect after challenge
			returnPath := r.URL.Path
			if r.URL.RawQuery != "" {
				returnPath += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, "/cf-challenge?return="+url.QueryEscape(returnPath), http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
}

// ─── Session helpers ─────────────────────────────────────────────────────────

func getValidSession(r *http.Request) *SessionInfo {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return nil
	}
	SessionMu.RLock()
	session, exists := Sessions[cookie.Value]
	SessionMu.RUnlock()
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil
	}
	return session
}

// GetSessionUser returns the UserAccount for a user session.
// Returns nil only for the true admin account (no UserUUID) or unauthenticated.
func GetSessionUser(r *http.Request) *UserAccount {
	session := getValidSession(r)
	if session == nil || session.UserUUID == "" {
		return nil
	}
	return GetUserByUUID(session.UserUUID)
}

// GetSessionInfo returns raw session info.
func GetSessionInfo(r *http.Request) *SessionInfo {
	return getValidSession(r)
}

// IsAuthenticated returns true for any valid session (admin or user).
func IsAuthenticated(r *http.Request) bool {
	return getValidSession(r) != nil
}

// IsAdminAuthenticated returns true for admin sessions or sub-users with IsAdmin=true.
func IsAdminAuthenticated(r *http.Request) bool {
	session := getValidSession(r)
	if session == nil {
		return false
	}
	if session.IsAdmin {
		return true
	}
	if session.UserUUID != "" {
		if u := GetUserByUUID(session.UserUUID); u != nil && u.IsAdmin {
			return true
		}
	}
	return false
}

// IsAuthenticatedForUser returns true if the session belongs to the specified user OR admin.
func IsAuthenticatedForUser(r *http.Request, uuid string) bool {
	session := getValidSession(r)
	if session == nil {
		return false
	}
	return session.IsAdmin || session.UserUUID == uuid
}
