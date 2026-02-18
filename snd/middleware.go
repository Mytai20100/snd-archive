package snd

import (
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

func RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/ac", http.StatusSeeOther)
			return
		}
		SessionMu.RLock()
		session, exists := Sessions[cookie.Value]
		SessionMu.RUnlock()
		if !exists || time.Now().After(session.ExpiresAt) {
			http.Redirect(w, r, "/ac", http.StatusSeeOther)
			return
		}
		SessionMu.Lock()
		session.LastAccess = time.Now()
		SessionMu.Unlock()
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
		if token != Cfg.APIToken {
			http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

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
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			fullPath = strings.TrimPrefix(r.URL.Path, "/raw/")
		default:
			fullPath = r.URL.Path
		}

		filename := filepath.Base(fullPath)
		folderPath := filepath.Dir(fullPath)
		if folderPath == "." {
			folderPath = ""
		}

		if Debug {
			log.Printf("[DEBUG] requireTokenOrAuth: fullPath=%s filename=%s folderPath=%s", fullPath, filename, folderPath)
		}

		PermissionMu.RLock()
		filePerm, fileExists := FilePermissions[filename]
		folderPerm, folderExists := FolderPermissions[folderPath]
		PermissionMu.RUnlock()

		if (fileExists && filePerm.IsPublic) || (folderExists && folderPerm.IsPublic) {
			handler(w, r)
			return
		}

		// Check valid API token first
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		if token == Cfg.APIToken {
			handler(w, r)
			return
		}

		// Check valid session
		cookie, err := r.Cookie("session")
		if err == nil {
			SessionMu.RLock()
			session, exists := Sessions[cookie.Value]
			SessionMu.RUnlock()
			if exists && !time.Now().After(session.ExpiresAt) {
				handler(w, r)
				return
			}
		}

		// Neither token nor session valid → error page
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
			http.Redirect(w, r, "/cf-challenge?return="+r.URL.Path, http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
}
