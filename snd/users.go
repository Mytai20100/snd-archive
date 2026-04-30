package snd

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// ─── Persistence ────────────────────────────────────────────────────────────

func LoadUsers() {
	data, err := os.ReadFile(UsersFile)
	if err != nil {
		return
	}
	var list []*UserAccount
	if err := yaml.Unmarshal(data, &list); err != nil {
		return
	}
	UsersMu.Lock()
	defer UsersMu.Unlock()
	Users = make(map[string]*UserAccount)
	for _, u := range list {
		Users[u.UUID] = u
	}
}

func SaveUsers() {
	UsersMu.RLock()
	list := make([]*UserAccount, 0, len(Users))
	for _, u := range Users {
		list = append(list, u)
	}
	UsersMu.RUnlock()
	data, _ := yaml.Marshal(list)
	os.WriteFile(UsersFile, data, 0600)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func NewUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// UserPublicDir returns the filesystem path for a user's public directory.
func UserPublicDir(uuid string) string {
	return filepath.Join(PublicDir, uuid)
}

// EnsureUserDir creates the per-user public directory if it doesn't exist.
func EnsureUserDir(uuid string) error {
	return os.MkdirAll(UserPublicDir(uuid), 0755)
}

// CalcUserStorage walks the user's dir and returns total bytes used.
func CalcUserStorage(uuid string) int64 {
	var total int64
	filepath.WalkDir(UserPublicDir(uuid), func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// GetUserByUUID returns a user by UUID (nil if not found).
func GetUserByUUID(uuid string) *UserAccount {
	UsersMu.RLock()
	defer UsersMu.RUnlock()
	return Users[uuid]
}

// GetUserByUsername finds a user by username (nil if not found).
func GetUserByUsername(username string) *UserAccount {
	UsersMu.RLock()
	defer UsersMu.RUnlock()
	for _, u := range Users {
		if u.Username == username {
			return u
		}
	}
	return nil
}

// GetUserByToken finds a user by API token (nil if not found).
func GetUserByToken(token string) *UserAccount {
	if token == "" {
		return nil
	}
	UsersMu.RLock()
	defer UsersMu.RUnlock()
	for _, u := range Users {
		if u.APIToken == token && u.IsActive {
			return u
		}
	}
	return nil
}

// ─── HTTP Handlers ───────────────────────────────────────────────────────────

// HandleListUsers → GET /admin/users  (admin only)
func HandleListUsers(w http.ResponseWriter, r *http.Request) {
	// M2 FIX: Only the true admin (no UserUUID) may see API tokens in the list.
	// Sub-users with IsAdmin=true get a redacted placeholder.
	callerSession := GetSessionInfo(r)
	callerIsTrueAdmin := callerSession != nil && callerSession.IsAdmin && callerSession.UserUUID == ""

	// Snapshot the user list under a short read-lock, then release before
	// doing any filesystem work so we never drop/re-acquire the lock mid-range.
	UsersMu.RLock()
	snapshot := make([]*UserAccount, 0, len(Users))
	for _, u := range Users {
		snapshot = append(snapshot, u)
	}
	UsersMu.RUnlock()

	list := make([]map[string]interface{}, 0, len(snapshot))
	for _, u := range snapshot {
		// CalcUserStorage reads the filesystem – do it outside any lock.
		used := CalcUserStorage(u.UUID)
		UsersMu.Lock()
		u.UsedStorage = used
		UsersMu.Unlock()

		tokenValue := "[redacted]"
		if callerIsTrueAdmin {
			tokenValue = u.APIToken
		}

		list = append(list, map[string]interface{}{
			"uuid":          u.UUID,
			"username":      u.Username,
			"email":         u.Email,
			"api_token":     tokenValue,
			"storage_limit": u.StorageLimit,
			"used_storage":  used, // use local var, not u.UsedStorage (avoid stale read)
			"request_count": u.RequestCount,
			"created_at":    u.CreatedAt.Format("2006-01-02 15:04:05"),
			"is_active":     u.IsActive,
			"is_admin":      u.IsAdmin,
		})
	}
	go SaveUsers()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// HandleCreateUser → POST /admin/users/create  (admin only)
func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username     string `json:"username"`
		Email        string `json:"email"`
		Password     string `json:"password"`
		StorageLimit int64  `json:"storage_limit"` // bytes; -1 unlimited
		IsAdmin      bool   `json:"is_admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Duplicate check
	if existing := GetUserByUsername(req.Username); existing != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Username already exists"})
		return
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	uuid := NewUUID()
	storageLimit := req.StorageLimit
	if storageLimit == 0 {
		storageLimit = -1 // default: unlimited
	}

	user := &UserAccount{
		UUID:         uuid,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		APIToken:     GenerateRandomToken(64),
		StorageLimit: storageLimit,
		CreatedAt:    time.Now(),
		IsActive:     true,
		IsAdmin:      req.IsAdmin,
	}

	UsersMu.Lock()
	Users[uuid] = user
	UsersMu.Unlock()

	if err := EnsureUserDir(uuid); err != nil {
		http.Error(w, "failed to create user directory", http.StatusInternalServerError)
		return
	}

	go SaveUsers()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"uuid":      uuid,
		"api_token": user.APIToken,
	})
}

// HandleUpdateUser → POST /admin/users/update  (admin only)
func HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UUID         string `json:"uuid"`
		Username     string `json:"username"`
		Email        string `json:"email"`
		Password     string `json:"password"` // empty = no change
		StorageLimit int64  `json:"storage_limit"`
		IsActive     bool   `json:"is_active"`
		IsAdmin      bool   `json:"is_admin"`
		RegenToken   bool   `json:"regen_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UUID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	UsersMu.Lock()
	user, ok := Users[req.UUID]
	if !ok {
		UsersMu.Unlock()
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if req.Username != "" {
		user.Username = req.Username
	}
	user.Email = req.Email
	user.StorageLimit = req.StorageLimit
	user.IsActive = req.IsActive
	user.IsAdmin = req.IsAdmin

	if req.Password != "" {
		hash, err := HashPassword(req.Password)
		if err == nil {
			user.PasswordHash = hash
		}
	}
	newToken := ""
	if req.RegenToken {
		user.APIToken = GenerateRandomToken(64)
		newToken = user.APIToken
	}
	UsersMu.Unlock()

	go SaveUsers()

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"success": true}
	if newToken != "" {
		resp["api_token"] = newToken
	}
	json.NewEncoder(w).Encode(resp)
}

// HandleDeleteUser → POST /admin/users/delete  (admin only)
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UUID        string `json:"uuid"`
		DeleteFiles bool   `json:"delete_files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UUID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	UsersMu.Lock()
	_, ok := Users[req.UUID]
	if !ok {
		UsersMu.Unlock()
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	delete(Users, req.UUID)
	UsersMu.Unlock()

	if req.DeleteFiles {
		os.RemoveAll(UserPublicDir(req.UUID))
	}

	// Kick any active sessions for this user
	SessionMu.Lock()
	for sid, s := range Sessions {
		if s.UserUUID == req.UUID {
			delete(Sessions, sid)
		}
	}
	SessionMu.Unlock()

	go SaveUsers()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// HandleUserPublicRaw serves a file from a user's public directory.
// URL: /raw/<filename>?u=<uuid>[&token=<usertoken>]
// or:  /<filename>?u=<uuid>[&token=<usertoken>]
func HandleUserPublicFile(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("u")
	if uuid == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}

	user := GetUserByUUID(uuid)
	if user == nil || !user.IsActive {
		RenderErrorPage(w, http.StatusNotFound, "Not Found", "User not found.", "")
		return
	}

	// Determine file path
	var relPath string
	if p := r.URL.Path; len(p) > 1 {
		// strip leading /
		relPath = p[1:]
		// strip raw/ prefix if present
		if len(relPath) > 4 && relPath[:4] == "raw/" {
			relPath = relPath[4:]
		}
	}
	if relPath == "" {
		http.Error(w, "missing file path", http.StatusBadRequest)
		return
	}

	// Sanitize path
	if filepath.IsAbs(relPath) || containsDotDot(relPath) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(UserPublicDir(uuid), relPath)

	// Check if it's a public file or valid token
	fileName := filepath.Base(relPath)
	folderRel := filepath.Dir(relPath)
	if folderRel == "." {
		folderRel = ""
	}

	PermissionMu.RLock()
	// Keys for user-scoped permissions use uuid/path
	userFileKey := uuid + "/" + relPath
	userFolderKey := uuid + "/" + folderRel
	filePerm, filePublic := FilePermissions[userFileKey]
	folderPerm, folderPublic := FolderPermissions[userFolderKey]
	PermissionMu.RUnlock()

	isPublic := (filePublic && filePerm.IsPublic) || (folderPublic && folderPerm.IsPublic)

	if isPublic {
		// Public file: anonymous access requires matching pt= public token.
		// If the file/folder has a PublicToken set, enforce it.
		// Legacy entries with no PublicToken are allowed through for backward compat.
		pt := r.URL.Query().Get("pt")
		fileHasToken := filePublic && filePerm.IsPublic && filePerm.PublicToken != ""
		folderHasToken := folderPublic && folderPerm.IsPublic && folderPerm.PublicToken != ""

		// If neither the file nor the folder has a PublicToken, allow (legacy share).
		needsTokenCheck := fileHasToken || folderHasToken
		if needsTokenCheck {
			ptOK := (fileHasToken && tokenEqual(pt, filePerm.PublicToken)) ||
				(folderHasToken && tokenEqual(pt, folderPerm.PublicToken))
			if !ptOK {
				// Still allow authenticated sessions / API tokens
				token := r.URL.Query().Get("token")
				if token == "" {
					token = r.Header.Get("X-API-Token")
				}
				tokenOK := token == user.APIToken || token == Cfg.APIToken
				if !tokenOK {
					session := getValidSession(r)
					if session == nil || (!session.IsAdmin && session.UserUUID != uuid) {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
				}
			}
		}
	} else {
		// Private file: require API token or session
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		tokenOK := token == user.APIToken || token == Cfg.APIToken

		if !tokenOK {
			// Check session: must be THIS user's session (or admin session)
			session := getValidSession(r)
			if session == nil || (!session.IsAdmin && session.UserUUID != uuid) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}

	// Count request
	UsersMu.Lock()
	user.RequestCount++
	UsersMu.Unlock()
	go SaveUsers()

	// Serve the file
	f, err := os.Open(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're looking for doesn't exist.", "Path: "+relPath)
		return
	}
	defer f.Close()

	stat, _ := f.Stat()
	fileType := GetFileType(fileName)
	ext := filepath.Ext(fileName)
	contentType := getContentTypeForType(fileType, ext)
	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func containsDotDot(path string) bool {
	for _, p := range filepath.SplitList(path) {
		if p == ".." {
			return true
		}
	}
	// Also check raw string
	for i := 0; i < len(path)-1; i++ {
		if path[i] == '.' && path[i+1] == '.' {
			return true
		}
	}
	return false
}

func getContentTypeForType(fileType, ext string) string {
	switch fileType {
	case "text":
		return "text/plain; charset=utf-8"
	case "image":
		switch ext {
		case ".png":
			return "image/png"
		case ".gif":
			return "image/gif"
		case ".webp":
			return "image/webp"
		case ".svg":
			return "image/svg+xml"
		case ".bmp":
			return "image/bmp"
		case ".avif":
			return "image/avif"
		case ".tif", ".tiff":
			return "image/tiff"
		default:
			// .jpg .jpeg .jfif .jpe and others → jpeg
			return "image/jpeg"
		}
	case "video", "audio":
		// ext is already the extension like ".mp4", wrap as filename
		return getMediaContentType("file" + ext)
	default:
		return "application/octet-stream"
	}
}

// HandleChangePassword allows a logged-in sub-user to change their own password.
// POST /user/change-password
// Body JSON: { "current_password": "...", "new_password": "..." }
func HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Method not allowed"})
		return
	}

	user := GetSessionUser(r)
	if user == nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Not a sub-user session"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid request"})
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "All fields are required"})
		return
	}
	if len(req.NewPassword) < 6 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "New password must be at least 6 characters"})
		return
	}

	// Re-fetch from DB to get current hash (user pointer might be stale)
	UsersMu.RLock()
	u, exists := Users[user.UUID]
	UsersMu.RUnlock()
	if !exists || !u.IsActive {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "User not found"})
		return
	}

	if !CheckPassword(u.PasswordHash, req.CurrentPassword) {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Current password is incorrect"})
		return
	}

	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Internal error"})
		return
	}

	UsersMu.Lock()
	Users[user.UUID].PasswordHash = newHash
	UsersMu.Unlock()
	go SaveUsers()

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Password changed successfully"})
}
