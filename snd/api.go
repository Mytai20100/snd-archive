package snd

import (
	"crypto/subtle"

	"net/http"
	"path/filepath"
	"strings"
	"time"
)

func tokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func RequireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getValidSession(r)
		if session == nil {
			http.Redirect(w, r, "/ac", http.StatusSeeOther)
			return
		}
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

func resourcePathFromRequest(r *http.Request) (fullPath, fileKey, folderKey string) {
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

	folderPath := filepath.Dir(fullPath)
	if folderPath == "." {
		folderPath = ""
	}

	fileKey = fullPath
	folderKey = folderPath
	if uuid := r.URL.Query().Get("u"); uuid != "" {
		fileKey = uuid + "/" + fullPath
		if folderPath != "" {
			folderKey = uuid + "/" + folderPath
		} else {
			folderKey = uuid + "/"
		}
	}
	return fullPath, fileKey, folderKey
}

func resourceIsPublic(r *http.Request) bool {
	_, fileKey, folderKey := resourcePathFromRequest(r)
	PermissionMu.RLock()
	filePerm, fileExists := FilePermissions[fileKey]
	folderPerm, folderExists := FolderPermissions[folderKey]
	PermissionMu.RUnlock()
	return (fileExists && filePerm.IsPublic) || (folderExists && folderPerm.IsPublic)
}

func requestAPIToken(r *http.Request) string {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-API-Token")
	}
	return token
}

func requestHasValidAPIToken(r *http.Request) bool {
	token := requestAPIToken(r)
	if token == "" {
		return false
	}
	return tokenEqual(token, Cfg.APIToken) || GetUserByToken(token) != nil
}

func RequireTokenOrAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, fileKey, folderKey := resourcePathFromRequest(r)

		PermissionMu.RLock()
		filePerm, fileExists := FilePermissions[fileKey]
		folderPerm, folderExists := FolderPermissions[folderKey]
		PermissionMu.RUnlock()

		if requestHasValidAPIToken(r) {
			handler(w, r)
			return
		}
		session := getValidSession(r)
		if session != nil {
			handler(w, r)
			return
		}

		pt := r.URL.Query().Get("pt")

		fileIsPublic := fileExists && filePerm.IsPublic
		folderIsPublic := folderExists && folderPerm.IsPublic

		if pt != "" {
			if fileIsPublic && filePerm.PublicToken != "" && tokenEqual(pt, filePerm.PublicToken) {
				handler(w, r)
				return
			}
			if folderIsPublic && folderPerm.PublicToken != "" && tokenEqual(pt, folderPerm.PublicToken) {
				handler(w, r)
				return
			}
		}

		if fileIsPublic || folderIsPublic {
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

func GetSessionUser(r *http.Request) *UserAccount {
	session := getValidSession(r)
	if session == nil || session.UserUUID == "" {
		return nil
	}
	return GetUserByUUID(session.UserUUID)
}

func GetSessionInfo(r *http.Request) *SessionInfo {
	return getValidSession(r)
}

func IsAuthenticated(r *http.Request) bool {
	return getValidSession(r) != nil
}

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

func IsAuthenticatedForUser(r *http.Request, uuid string) bool {
	session := getValidSession(r)
	if session == nil {
		return false
	}
	return session.IsAdmin || session.UserUUID == uuid
}
