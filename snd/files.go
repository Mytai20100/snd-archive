package snd

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	h "html"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// resolveBaseDir returns the appropriate file base directory and permission key prefix.
// Admin sessions → PublicDir, "". User sessions → UserPublicDir(uuid), "uuid/".
func resolveBaseDir(r *http.Request) (baseDir string, permPrefix string) {
	if u := GetSessionUser(r); u != nil {
		return UserPublicDir(u.UUID), u.UUID + "/"
	}
	return PublicDir, ""
}

// resolveBaseDirFromToken resolves base dir by checking token auth (for non-session requests).
func resolveBaseDirFromToken(r *http.Request) (baseDir string, permPrefix string) {
	// Try session first
	if u := GetSessionUser(r); u != nil {
		return UserPublicDir(u.UUID), u.UUID + "/"
	}
	// Try user token
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-API-Token")
	}
	if token != "" {
		if u := GetUserByToken(token); u != nil {
			return UserPublicDir(u.UUID), u.UUID + "/"
		}
	}
	return PublicDir, ""
}

// safePath validates and joins base+rel, ensuring the result stays within base.
// Returns the joined path and true on success; empty string and false on traversal attempt.
func safePath(base, rel string) (string, bool) {
	if strings.Contains(rel, "..") {
		return "", false
	}
	joined := filepath.Join(base, rel)
	absBase, err1 := filepath.Abs(base)
	absJoin, err2 := filepath.Abs(joined)
	if err1 != nil || err2 != nil {
		return "", false
	}
	// Must be equal to base (file directly in base) or within base subdir
	if absJoin != absBase && !strings.HasPrefix(absJoin, absBase+string(filepath.Separator)) {
		return "", false
	}
	return joined, true
}

func HandleUpload(w http.ResponseWriter, r *http.Request) {
	GlobalStatsMu.Lock()
	GlobalStats.TotalRequests++
	GlobalStatsMu.Unlock()

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentPath := r.URL.Query().Get("path")
	if strings.Contains(currentPath, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	userAccount := GetSessionUser(r)
	baseDir := PublicDir
	if userAccount != nil {
		baseDir = UserPublicDir(userAccount.UUID)
	}

	contentType := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		http.Error(w, "Expected multipart/form-data", http.StatusBadRequest)
		return
	}

	boundary := params["boundary"]
	mr := multipart.NewReader(r.Body, boundary)

	uploadedCount := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if Debug {
				log.Printf("[UPLOAD] multipart error: %v", err)
			}
			break
		}

		filename := part.FileName()
		if filename == "" {
			part.Close()
			continue
		}

		filename = filepath.Base(filename)
		if strings.Contains(filename, "..") || filename == "" || filename == "." {
			part.Close()
			continue
		}

		// Quota check for user accounts
		if userAccount != nil && userAccount.StorageLimit > 0 {
			used := CalcUserStorage(userAccount.UUID)
			if used >= userAccount.StorageLimit {
				part.Close()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "Storage quota exceeded",
				})
				return
			}
		}

		// FIX: validate upload path with safePath
		targetPath, ok := safePath(baseDir, filepath.Join(currentPath, filename))
		if !ok {
			part.Close()
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			part.Close()
			continue
		}

		dst, err := os.Create(targetPath)
		if err != nil {
			part.Close()
			if Debug {
				log.Printf("[UPLOAD] create file error: %v", err)
			}
			continue
		}

		written, err := io.Copy(dst, part)
		dst.Close()
		part.Close()

		if err != nil {
			os.Remove(targetPath)
			if Debug {
				log.Printf("[UPLOAD] copy error for %s: %v", filename, err)
			}
			continue
		}

		if userAccount != nil {
			UsersMu.Lock()
			userAccount.UsedStorage += written
			userAccount.RequestCount++
			UsersMu.Unlock()
			go SaveUsers()
		}

		uploadedCount++
		RecordUploadBytes(written)
		if Debug {
			log.Printf("[UPLOAD] %s (%d bytes)", targetPath, written)
		}
	}

	UpdateStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"uploaded": uploadedCount,
		"message":  fmt.Sprintf("%d file(s) uploaded", uploadedCount),
	})
}

func HandleUploadChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentPath := r.URL.Query().Get("path")
	filename := r.URL.Query().Get("filename")
	offsetStr := r.URL.Query().Get("offset")
	totalStr := r.URL.Query().Get("total")
	final := r.URL.Query().Get("final") == "1"

	if strings.Contains(currentPath, "..") || strings.Contains(filename, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	filename = filepath.Base(filename)
	if filename == "" || filename == "." {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	offset, _ := strconv.ParseInt(offsetStr, 10, 64)
	total, _ := strconv.ParseInt(totalStr, 10, 64)

	userAccount := GetSessionUser(r)
	baseDir := PublicDir
	if userAccount != nil {
		baseDir = UserPublicDir(userAccount.UUID)
		if userAccount.StorageLimit > 0 {
			used := CalcUserStorage(userAccount.UUID)
			if used >= userAccount.StorageLimit {
				http.Error(w, "Storage quota exceeded", http.StatusInsufficientStorage)
				return
			}
		}
	}

	targetPath, ok := safePath(baseDir, filepath.Join(currentPath, filename))
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		http.Error(w, "Cannot create directory", http.StatusInternalServerError)
		return
	}

	tmpPath := targetPath + ".upload_tmp"

	var flag int
	if offset == 0 {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	} else {
		flag = os.O_WRONLY | os.O_CREATE
	}

	f, err := os.OpenFile(tmpPath, flag, 0644)
	if err != nil {
		http.Error(w, "Cannot open file for writing", http.StatusInternalServerError)
		return
	}

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			http.Error(w, "Seek error", http.StatusInternalServerError)
			return
		}
	}

	written, err := io.Copy(f, r.Body)
	f.Close()

	if err != nil {
		http.Error(w, "Write error", http.StatusInternalServerError)
		return
	}

	RecordUploadBytes(written)

	if Debug {
		log.Printf("[CHUNK] %s offset=%d written=%d total=%d final=%v", filename, offset, written, total, final)
	}

	if final {
		if err := os.Rename(tmpPath, targetPath); err != nil {
			http.Error(w, "Finalize error", http.StatusInternalServerError)
			return
		}
		UpdateStats()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"written": written,
		"offset":  offset,
		"total":   total,
		"done":    final,
	})
}

func HandleListFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	isAuth := IsAuthenticated(r)
	session := GetSessionInfo(r)
	userAccount := GetSessionUser(r)

	// FIX: use resolveBaseDirFromToken so user API tokens see their own directory,
	// not the admin's PublicDir. Previously token holders always fell back to PublicDir.
	baseDir, _ := resolveBaseDirFromToken(r)

	_ = session
	dirPath := filepath.Join(baseDir, path)

	files, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	var fileList []FileMetadataWithPermission
	var folders []string

	for _, file := range files {
		if file.IsDir() {
			if userAccount == nil && isAuth && path == "" && isUUIDDir(file.Name()) {
				continue
			}
			folderKey := file.Name()
			if path != "" {
				folderKey = filepath.Join(path, file.Name())
			}
			permKey := folderKey
			if userAccount != nil {
				permKey = userAccount.UUID + "/" + folderKey
			}
			PermissionMu.RLock()
			folderPerm, folderExists := FolderPermissions[permKey]
			folderIsPublic := folderExists && folderPerm.IsPublic
			PermissionMu.RUnlock()
			if !folderIsPublic && !isAuth {
				continue
			}
			folders = append(folders, file.Name())
		} else {
			info, _ := file.Info()
			fullPath := filepath.Join(path, file.Name())
			if path == "" {
				fullPath = file.Name()
			}
			permKey := fullPath
			if userAccount != nil {
				permKey = userAccount.UUID + "/" + fullPath
			}
			PermissionMu.RLock()
			perm, exists := FilePermissions[permKey]
			isPublic := exists && perm.IsPublic
			PermissionMu.RUnlock()
			if !isPublic && !isAuth {
				continue
			}
			DownloadMu.RLock()
			count := DownloadCounts[fullPath]
			DownloadMu.RUnlock()
			fileList = append(fileList, FileMetadataWithPermission{
				FileMetadata: FileMetadata{
					Name:          file.Name(),
					Type:          GetFileType(file.Name()),
					Size:          info.Size(),
					ModTime:       info.ModTime(),
					DownloadCount: count,
				},
				IsPublic: isPublic,
				Owner:    ownerName(userAccount),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files":   fileList,
		"folders": folders,
	})
}

func ownerName(u *UserAccount) string {
	if u == nil {
		return "admin"
	}
	return u.Username
}

func HandlePublicFiles(w http.ResponseWriter, r *http.Request) {
	var result []FileMetadataWithPermission

	adminFiles, _ := os.ReadDir(PublicDir)
	for _, f := range adminFiles {
		if f.IsDir() {
			continue
		}
		PermissionMu.RLock()
		perm, exists := FilePermissions[f.Name()]
		PermissionMu.RUnlock()
		if !exists || !perm.IsPublic {
			continue
		}
		info, err := f.Info()
		if err != nil {
			continue
		}
		DownloadMu.RLock()
		count := DownloadCounts[f.Name()]
		DownloadMu.RUnlock()
		result = append(result, FileMetadataWithPermission{
			FileMetadata: FileMetadata{
				Name:          f.Name(),
				Type:          GetFileType(f.Name()),
				Size:          info.Size(),
				ModTime:       info.ModTime(),
				DownloadCount: count,
			},
			IsPublic: true,
			Owner:    "admin",
		})
	}

	UsersMu.RLock()
	userList := make([]*UserAccount, 0, len(Users))
	for _, u := range Users {
		userList = append(userList, u)
	}
	UsersMu.RUnlock()

	for _, u := range userList {
		if !u.IsActive {
			continue
		}
		userDir := UserPublicDir(u.UUID)
		walkUserPublicFiles(userDir, u, "", &result)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func walkUserPublicFiles(dir string, u *UserAccount, relBase string, out *[]FileMetadataWithPermission) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		relPath := entry.Name()
		if relBase != "" {
			relPath = relBase + "/" + entry.Name()
		}
		permKey := u.UUID + "/" + relPath
		if entry.IsDir() {
			PermissionMu.RLock()
			fp, fpExists := FolderPermissions[permKey]
			PermissionMu.RUnlock()
			if fpExists && fp.IsPublic {
				walkUserPublicFiles(filepath.Join(dir, entry.Name()), u, relPath, out)
			} else {
				walkUserPublicFiles(filepath.Join(dir, entry.Name()), u, relPath, out)
			}
			continue
		}
		PermissionMu.RLock()
		perm, exists := FilePermissions[permKey]
		parentKey := u.UUID + "/" + relBase
		folderPerm, folderExists := FolderPermissions[parentKey]
		PermissionMu.RUnlock()
		isPublic := (exists && perm.IsPublic) || (folderExists && folderPerm.IsPublic)
		if !isPublic {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		displayName := entry.Name()
		DownloadMu.RLock()
		count := DownloadCounts[relPath]
		DownloadMu.RUnlock()
		*out = append(*out, FileMetadataWithPermission{
			FileMetadata: FileMetadata{
				Name:          displayName,
				Type:          GetFileType(displayName),
				Size:          info.Size(),
				ModTime:       info.ModTime(),
				DownloadCount: count,
			},
			IsPublic: true,
			Owner:    u.Username,
			UserUUID: u.UUID,
			RawPath:  relPath,
		})
	}
}

func isUUIDDir(name string) bool {
	if len(name) != 36 {
		return false
	}
	for i, c := range name {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func HandleView(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/view/"):]

	// FIX: use resolveBaseDirFromToken so user files load correctly
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		RenderErrorPage(w, http.StatusBadRequest, "Invalid Path", "Invalid file path.", "")
		return
	}

	info, err := os.Stat(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're trying to view doesn't exist.", "File: "+h.EscapeString(filename))
		return
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	fileType := DetectFileType(filename, content)
	token := r.URL.Query().Get("token")

	if fileType == "image" {
		ext := strings.ToLower(filepath.Ext(filename))
		contentType := "image/jpeg"
		switch ext {
		case ".png":
			contentType = "image/png"
		case ".gif":
			contentType = "image/gif"
		case ".webp":
			contentType = "image/webp"
		case ".svg":
			contentType = "image/svg+xml"
		case ".bmp":
			contentType = "image/bmp"
		case ".avif":
			contentType = "image/avif"
		case ".tif", ".tiff":
			contentType = "image/tiff"
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(content)
		return
	}

	if fileType == "video" || fileType == "audio" {
		streamURL := "/stream/" + filename
		if token != "" {
			streamURL += "?token=" + token
		}
		http.Redirect(w, r, streamURL, http.StatusSeeOther)
		return
	}

	isAuth := IsAuthenticated(r)
	editButton := ""
	if isAuth && fileType == "text" {
		editButton = `<a href="/edit/` + h.EscapeString(filename) + `?token=` + h.EscapeString(token) + `" class="btn">Edit File</a>`
	}

	contentHTML := ""
	if fileType == "text" {
		contentHTML = `<div class="code-block">` + h.EscapeString(string(content)) + `</div>`
	} else if fileType == "document" && strings.HasSuffix(filename, ".pdf") {
		contentHTML = `<iframe src="/raw/` + h.EscapeString(filename) + `?token=` + h.EscapeString(token) + `" style="width:100%;height:800px;border:none;"></iframe>`
	} else {
		contentHTML = `<div class="binary-notice">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:64px;height:64px;margin-bottom:16px;opacity:.5">
                <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                <polyline points="13 2 13 9 20 9"></polyline>
            </svg>
            <h3>Binary File</h3>
            <p>This file type cannot be viewed directly in the browser.</p>
            <p>Use the Download button to save it to your device.</p>
        </div>`
	}

	viewHTML := `<!DOCTYPE html>
<html>
<head>
    <title>View: ` + h.EscapeString(filepath.Base(filename)) + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #fafafa; padding: 20px; }
        .viewer-container { max-width: 1200px; margin: 0 auto; background: white; border: 1px solid #e0e0e0; border-radius: 4px; overflow: hidden; }
        .viewer-header { padding: 16px 20px; border-bottom: 1px solid #e0e0e0; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
        .viewer-title { font-size: 16px; font-weight: 500; word-break: break-all; }
        .viewer-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .btn { padding: 8px 16px; background: #1a1a1a; color: white; text-decoration: none; border: none; cursor: pointer; font-size: 13px; white-space: nowrap; border-radius: 2px; }
        .btn:hover { background: #333; }
        .viewer-content { padding: 20px; }
        .code-block { background: #f5f5f5; padding: 16px; border-radius: 4px; overflow-x: auto; font-family: 'Monaco', monospace; font-size: 13px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
        .file-info { display: flex; gap: 20px; padding: 12px; background: #f9f9f9; border-radius: 4px; margin-bottom: 20px; font-size: 13px; color: #666; flex-wrap: wrap; }
        .binary-notice { text-align: center; padding: 40px; color: #666; }
    </style>
</head>
<body>
    <div class="viewer-container">
        <div class="viewer-header">
            <div class="viewer-title">` + h.EscapeString(filepath.Base(filename)) + `</div>
            <div class="viewer-actions">
                ` + editButton + `
                <a href="/download/` + h.EscapeString(filename) + `?token=` + h.EscapeString(token) + `" class="btn">Download</a>
                <a href="/" class="btn">Back to Files</a>
            </div>
        </div>
        <div class="viewer-content">
            <div class="file-info">
                <span><strong>Size:</strong> ` + FormatBytes(info.Size()) + `</span>
                <span><strong>Type:</strong> ` + h.EscapeString(fileType) + `</span>
                <span><strong>Modified:</strong> ` + info.ModTime().Format("2006-01-02 15:04:05") + `</span>
            </div>
            ` + contentHTML + `
        </div>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(viewHTML))
}

// monacoLangForExt maps file extensions to Monaco language IDs.
func monacoLangForExt(ext string) string {
	switch strings.ToLower(ext) {
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".html", ".htm":
		return "html"
	case ".css":
		return "css"
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".md", ".markdown":
		return "markdown"
	case ".sh", ".bash":
		return "shell"
	case ".lua":
		return "lua"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".java":
		return "java"
	case ".php":
		return "php"
	case ".rb":
		return "ruby"
	case ".rs":
		return "rust"
	case ".sql":
		return "sql"
	case ".xml":
		return "xml"
	case ".toml":
		return "ini"
	case ".ini", ".cfg", ".conf":
		return "ini"
	case ".dockerfile":
		return "dockerfile"
	default:
		return "plaintext"
	}
}

func HandleEdit(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/edit/"):]

	// FIX: use resolveBaseDir for user file isolation
	baseDir, _ := resolveBaseDir(r)
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		RenderErrorPage(w, http.StatusBadRequest, "Invalid Path", "Invalid file path.", "")
		return
	}

	info, err := os.Stat(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're trying to edit doesn't exist.", "File: "+h.EscapeString(filename))
		return
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	fileType := DetectFileType(filename, content)
	if fileType != "text" {
		RenderErrorPage(w, http.StatusBadRequest, "Cannot Edit File",
			"Only text files can be edited.", "File type: "+h.EscapeString(fileType))
		return
	}

	token := r.URL.Query().Get("token")
	ext := filepath.Ext(filename)
	monacoLang := monacoLangForExt(ext)

	// Encode content as JSON string for safe injection into JS
	contentJSON, _ := json.Marshal(string(content))

	editHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Edit: ` + h.EscapeString(filepath.Base(filename)) + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #1e1e1e; height: 100vh; display: flex; flex-direction: column; }
        .editor-header { background: #2d2d2d; border-bottom: 1px solid #3d3d3d; padding: 10px 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; color: #ccc; }
        .editor-title { font-size: 14px; font-weight: 500; color: #ddd; }
        .editor-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
        .btn { padding: 6px 14px; background: #3d3d3d; color: #ddd; text-decoration: none; border: 1px solid #555; cursor: pointer; font-size: 12px; white-space: nowrap; border-radius: 3px; }
        .btn:hover { background: #4d4d4d; color: #fff; }
        .btn-primary { background: #0e7490; border-color: #0e7490; color: #fff; }
        .btn-primary:hover { background: #0891b2; }
        .editor-info { padding: 6px 16px; background: #252525; border-bottom: 1px solid #333; font-size: 11px; color: #666; display: flex; gap: 16px; flex-wrap: wrap; }
        #monaco-container { flex: 1; min-height: 0; }
        .save-status { display: none; padding: 4px 12px; border-radius: 3px; font-size: 11px; }
        .save-ok { background: #065f46; color: #6ee7b7; border: 1px solid #047857; }
        .save-err { background: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; }
    </style>
</head>
<body>
    <div class="editor-header">
        <div class="editor-title">&#9998; ` + h.EscapeString(filepath.Base(filename)) + `</div>
        <div class="editor-actions">
            <span class="save-status" id="saveStatus"></span>
            <button class="btn btn-primary" onclick="saveFile()">&#128190; Save (Ctrl+S)</button>
            <a href="/view/` + h.EscapeString(filename) + `?token=` + h.EscapeString(token) + `" class="btn">View</a>
            <a href="/" class="btn">&#8592; Cancel</a>
        </div>
    </div>
    <div class="editor-info">
        <span><strong>File:</strong> ` + h.EscapeString(filename) + `</span>
        <span><strong>Size:</strong> ` + FormatBytes(info.Size()) + `</span>
        <span><strong>Lang:</strong> ` + monacoLang + `</span>
        <span><strong>Lines:</strong> <span id="lineCount">...</span></span>
        <span><strong>Col:</strong> <span id="colCount">1</span></span>
        <span id="dirtyIndicator" style="color:#f59e0b;display:none;">&#9679; unsaved</span>
    </div>
    <div id="monaco-container"></div>

    <script src="/lib/vs/loader.js"></script>
    <script>
        const INITIAL_CONTENT = ` + string(contentJSON) + `;
        const SAVE_URL = '/save/` + h.EscapeString(filename) + `?token=` + h.EscapeString(token) + `';
        const LANG = '` + monacoLang + `';

        require.config({ paths: { 'vs': '/lib/vs' } });
        require(['vs/editor/editor.main'], function() {
            var editor = monaco.editor.create(document.getElementById('monaco-container'), {
                value: INITIAL_CONTENT,
                language: LANG,
                theme: 'vs-dark',
                fontSize: 14,
                minimap: { enabled: true },
                automaticLayout: true,
                wordWrap: 'off',
                scrollBeyondLastLine: false,
                renderWhitespace: 'boundary',
                folding: true,
                lineNumbers: 'on',
                tabSize: 4,
                insertSpaces: true,
            });

            var dirty = false;
            var originalContent = INITIAL_CONTENT;

            editor.getModel().onDidChangeContent(function() {
                dirty = editor.getValue() !== originalContent;
                document.getElementById('dirtyIndicator').style.display = dirty ? 'inline' : 'none';
            });

            editor.onDidChangeCursorPosition(function(e) {
                document.getElementById('lineCount').textContent = e.position.lineNumber;
                document.getElementById('colCount').textContent = e.position.column;
            });
            document.getElementById('lineCount').textContent = editor.getModel().getLineCount();

            // Ctrl+S / Cmd+S save
            editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, function() {
                saveFile();
            });

            window.saveFile = function() {
                var content = editor.getValue();
                fetch(SAVE_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
                    body: content
                })
                .then(function(resp) {
                    if (resp.ok) {
                        originalContent = content;
                        dirty = false;
                        document.getElementById('dirtyIndicator').style.display = 'none';
                        showStatus('&#10003; Saved', 'save-ok');
                    } else {
                        showStatus('&#10007; Save failed', 'save-err');
                    }
                })
                .catch(function() { showStatus('&#10007; Network error', 'save-err'); });
            };

            window.addEventListener('beforeunload', function(e) {
                if (dirty) {
                    e.preventDefault();
                    e.returnValue = '';
                }
            });
        });

        function showStatus(msg, cls) {
            var el = document.getElementById('saveStatus');
            el.innerHTML = msg;
            el.className = 'save-status ' + cls;
            el.style.display = 'inline-block';
            setTimeout(function() { el.style.display = 'none'; }, 3000);
        }
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(editHTML))
}

func HandleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := r.URL.Path[len("/save/"):]
	baseDir, _ := resolveBaseDir(r)

	// FIX: path traversal protection
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading content", http.StatusInternalServerError)
		return
	}
	if err = os.WriteFile(filePath, content, 0644); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	if Debug {
		log.Printf("Saved: %s", filename)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "File saved successfully"})
}

func getMediaContentType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".ogg":
		return "video/ogg"
	case ".mov":
		return "video/quicktime"
	case ".avi":
		return "video/x-msvideo"
	case ".mkv":
		return "video/x-matroska"
	case ".m4v":
		return "video/x-m4v"
	case ".3gp":
		return "video/3gpp"
	case ".m3u8":
		return "application/vnd.apple.mpegurl"
	case ".ts":
		return "video/mp2t"
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	case ".m4a":
		return "audio/mp4"
	case ".aac":
		return "audio/aac"
	case ".flac":
		return "audio/flac"
	case ".wma":
		return "audio/x-ms-wma"
	case ".opus":
		return "audio/ogg; codecs=opus"
	}
	return "application/octet-stream"
}

// HandleRawDispatch routes /raw/ requests: if ?u= param present → user file; else check auth.
func HandleRawDispatch(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("u") != "" {
		HandleUserPublicFile(w, r)
		return
	}
	RequireTokenOrAuth(HandleRaw)(w, r)
}

func HandleRaw(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/raw/"):]

	// FIX: resolve base dir by token/session so user files load correctly
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		RenderErrorPage(w, http.StatusBadRequest, "Invalid Path", "Invalid file path.", "")
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're looking for doesn't exist.", "Path: "+r.URL.Path)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "Error getting file info", http.StatusInternalServerError)
		return
	}

	fileType := GetFileType(filename)
	ext := strings.ToLower(filepath.Ext(filename))

	var contentType string
	switch fileType {
	case "text":
		contentType = "text/plain; charset=utf-8"
	case "image":
		switch ext {
		case ".png":
			contentType = "image/png"
		case ".gif":
			contentType = "image/gif"
		case ".webp":
			contentType = "image/webp"
		case ".svg":
			contentType = "image/svg+xml"
		case ".bmp":
			contentType = "image/bmp"
		case ".avif":
			contentType = "image/avif"
		case ".tif", ".tiff":
			contentType = "image/tiff"
		default:
			contentType = "image/jpeg"
		}
	case "video", "audio":
		contentType = getMediaContentType(filename)
	default:
		contentType = "application/octet-stream"
	}

	RecordDownloadBytes(stat.Size())
	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func HandleDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/download/"):]

	// FIX: resolve base dir for user files
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	DownloadMu.Lock()
	DownloadCounts[filename]++
	DownloadMu.Unlock()
	SaveDownloadCounts()

	if Debug {
		log.Printf("Download: %s", filename)
	}

	// FIX: sanitize filename for Content-Disposition header injection
	safeName := filepath.Base(filename)
	safeName = strings.ReplaceAll(safeName, "\"", "")
	safeName = strings.ReplaceAll(safeName, "\n", "")
	safeName = strings.ReplaceAll(safeName, "\r", "")

	w.Header().Set("Content-Disposition", "attachment; filename=\""+safeName+"\"")
	if fi, err := os.Stat(filePath); err == nil {
		RecordDownloadBytes(fi.Size())
	}
	http.ServeFile(w, r, filePath)
}

func HandleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := r.URL.Path[len("/delete/"):]
	baseDir, permPrefix := resolveBaseDir(r)

	// FIX: path traversal protection
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if err := os.Remove(filePath); err != nil {
		http.Error(w, "Error deleting file", http.StatusInternalServerError)
		return
	}
	permKey := permPrefix + filename
	DownloadMu.Lock()
	delete(DownloadCounts, permKey)
	DownloadMu.Unlock()
	SaveDownloadCounts()

	PermissionMu.Lock()
	delete(FilePermissions, permKey)
	PermissionMu.Unlock()
	SaveFilePermissions()

	if Debug {
		log.Printf("Deleted: %s", filename)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "File deleted successfully"})
}

func HandleRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	oldName := r.URL.Path[len("/rename/"):]
	var req struct {
		NewName string `json:"new_name"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	baseDir, permPrefix := resolveBaseDir(r)

	// FIX: path traversal protection on both old and new names
	oldPath, ok1 := safePath(baseDir, oldName)
	newPath, ok2 := safePath(baseDir, req.NewName)
	if !ok1 || !ok2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if err := os.Rename(oldPath, newPath); err != nil {
		http.Error(w, "Error renaming file", http.StatusInternalServerError)
		return
	}
	DownloadMu.Lock()
	if count, exists := DownloadCounts[permPrefix+oldName]; exists {
		DownloadCounts[permPrefix+req.NewName] = count
		delete(DownloadCounts, permPrefix+oldName)
	}
	DownloadMu.Unlock()
	SaveDownloadCounts()

	if Debug {
		log.Printf("Renamed: %s -> %s", oldName, req.NewName)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "File renamed successfully"})
}

func HandleDuplicate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := r.URL.Path[len("/duplicate/"):]
	baseDir, _ := resolveBaseDir(r)

	srcPath, ok := safePath(baseDir, filename)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	newName := base + "_copy" + ext

	counter := 1
	for {
		np, ok := safePath(baseDir, newName)
		if !ok {
			break
		}
		if _, err := os.Stat(np); os.IsNotExist(err) {
			break
		}
		newName = fmt.Sprintf("%s_copy%d%s", base, counter, ext)
		counter++
	}

	src, err := os.Open(srcPath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	defer src.Close()

	dstPath, _ := safePath(baseDir, newName)
	dst, err := os.Create(dstPath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err = io.Copy(dst, src); err != nil {
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}
	if Debug {
		log.Printf("Duplicated: %s -> %s", filename, newName)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "File duplicated as " + newName})
}

func HandleZipMultiple(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Files []string `json:"files"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if len(req.Files) == 0 {
		http.Error(w, "No files specified", http.StatusBadRequest)
		return
	}

	baseDir, _ := resolveBaseDir(r)

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"archive.zip\"")
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	for _, filename := range req.Files {
		// FIX: validate each file path
		filePath, ok := safePath(baseDir, filename)
		if !ok {
			continue
		}
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			continue
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			file.Close()
			continue
		}
		header.Name = filename
		header.Method = zip.Deflate
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			file.Close()
			continue
		}
		io.Copy(writer, file)
		file.Close()
	}
	if Debug {
		log.Printf("Created ZIP with %d files", len(req.Files))
	}
}

func HandleZipView(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/zip-view/"):]
	baseDir, permPrefix := resolveBaseDirFromToken(r)

	// Security: require auth or valid token unless file is explicitly public
	permKey := permPrefix + filename
	folderKey := permPrefix + filepath.Dir(filename)
	if folderKey == permPrefix+"." {
		folderKey = permPrefix
	}
	PermissionMu.RLock()
	filePerm, fileExists := FilePermissions[permKey]
	folderPerm, folderExists := FolderPermissions[folderKey]
	PermissionMu.RUnlock()
	isPublic := (fileExists && filePerm.IsPublic) || (folderExists && folderPerm.IsPublic)

	if !isPublic && !IsAuthenticated(r) {
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		if !tokenEqual(token, Cfg.APIToken) && GetUserByToken(token) == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	filePath, ok := safePath(baseDir, filename)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		http.Error(w, "Error reading ZIP", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	type ZipEntry struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}

	var entries []ZipEntry
	var totalSize int64
	for _, f := range reader.File {
		entries = append(entries, ZipEntry{Name: f.Name, Size: int64(f.UncompressedSize64)})
		totalSize += int64(f.UncompressedSize64)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files":      entries,
		"total_size": totalSize,
	})
}

func HandleExtractZip(w http.ResponseWriter, r *http.Request) {
	archivePath := strings.TrimPrefix(r.URL.Path, "/extract-zip/")
	baseDir, _ := resolveBaseDir(r)

	// FIX: path traversal protection
	fullArchivePath, ok := safePath(baseDir, archivePath)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid path"})
		return
	}

	extractName := archivePath
	for _, sfx := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".zip", ".gz", ".tar"} {
		if strings.HasSuffix(strings.ToLower(extractName), sfx) {
			extractName = extractName[:len(extractName)-len(sfx)]
			break
		}
	}
	extractDir := filepath.Join(baseDir, extractName+"_extracted")
	// Validate extractDir stays within baseDir
	if _, ok := safePath(baseDir, extractName+"_extracted"); !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid extract path"})
		return
	}
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	ext := strings.ToLower(filepath.Ext(fullArchivePath))
	lowerPath := strings.ToLower(fullArchivePath)

	var extractErr error
	switch {
	case strings.HasSuffix(lowerPath, ".tar.gz") || strings.HasSuffix(lowerPath, ".tgz"):
		extractErr = extractTarGz(fullArchivePath, extractDir)
	case strings.HasSuffix(lowerPath, ".tar.bz2") || strings.HasSuffix(lowerPath, ".tbz2"):
		extractErr = extractTarGz(fullArchivePath, extractDir)
	case strings.HasSuffix(lowerPath, ".tar"):
		extractErr = extractTarRaw(fullArchivePath, extractDir)
	case ext == ".gz":
		extractErr = extractSingleGz(fullArchivePath, extractDir)
	default:
		extractErr = extractZipArchive(fullArchivePath, extractDir)
	}

	w.Header().Set("Content-Type", "application/json")
	if extractErr != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": extractErr.Error()})
		return
	}

	LogAccess(GetClientIP(r), "extract", archivePath, r.UserAgent())
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func extractZipArchive(src, destDir string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, f := range reader.File {
		target := filepath.Join(destDir, filepath.Clean(f.Name))
		if !strings.HasPrefix(target, destDir) {
			continue // zip-slip guard
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, f.Mode())
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}

func extractTarGz(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	return extractTarStream(tar.NewReader(gr), destDir)
}

func extractTarRaw(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return extractTarStream(tar.NewReader(f), destDir)
}

func extractTarStream(tr *tar.Reader, destDir string) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, filepath.Clean(header.Name))
		if !strings.HasPrefix(target, destDir) {
			continue // tar-slip guard
		}
		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, os.FileMode(header.Mode))
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0755)
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				continue
			}
			io.Copy(out, tr)
			out.Close()
		}
	}
	return nil
}

func extractSingleGz(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	outName := strings.TrimSuffix(filepath.Base(src), ".gz")
	if outName == "" {
		outName = "extracted"
	}
	out, err := os.Create(filepath.Join(destDir, outName))
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, gr)
	return err
}

func HandleStream(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/stream/"):]

	// FIX: use resolveBaseDirFromToken so user streams work
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		RenderErrorPage(w, http.StatusBadRequest, "Invalid Path", "Invalid file path.", "")
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're looking for doesn't exist.", "Path: "+r.URL.Path)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "Error getting file info", http.StatusInternalServerError)
		return
	}

	contentType := getMediaContentType(filename)
	if contentType == "application/octet-stream" {
		fileType := GetFileType(filename)
		if fileType == "video" {
			contentType = "video/mp4"
		} else if fileType == "audio" {
			contentType = "audio/mpeg"
		}
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-cache")
	// CORS for HLS.js cross-origin segment loading
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Range")

	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func HandleStreamPage(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/play/"):]

	// FIX: use resolveBaseDirFromToken for user media
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		RenderErrorPage(w, http.StatusBadRequest, "Invalid Path", "Invalid file path.", "")
		return
	}

	_, err := os.Stat(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The media file you're looking for doesn't exist.", "File: "+h.EscapeString(filename))
		return
	}

	token := r.URL.Query().Get("token")
	streamURL := "/stream/" + h.EscapeString(filename)
	if token != "" {
		streamURL += "?token=" + h.EscapeString(token)
	}

	fileType := GetFileType(filename)
	baseName := filepath.Base(filename)

	var playerHTML string
	if fileType == "video" {
		playerHTML = `<video id="player" controls playsinline preload="metadata" style="width:100%;max-height:80vh;background:#000;"
            onerror="showError(this.error)">
            <source src="` + streamURL + `">
            Your browser does not support the video element.
        </video>`
	} else {
		playerHTML = `<audio id="player" controls preload="metadata" style="width:100%;margin-top:40px;"
            onerror="showError(this.error)">
            <source src="` + streamURL + `">
            Your browser does not support the audio element.
        </audio>`
	}

	pageHTML := `<!DOCTYPE html>
<html>
<head>
    <title>` + h.EscapeString(baseName) + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #fff; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
        .player-wrap { width: 100%; max-width: 960px; }
        .player-title { font-size: 15px; font-weight: 500; margin-bottom: 16px; color: #ccc; word-break: break-all; }
        .player-actions { display: flex; gap: 12px; margin-top: 20px; flex-wrap: wrap; }
        .btn { padding: 8px 18px; background: #fff; color: #000; text-decoration: none; border: none; cursor: pointer; font-size: 13px; border-radius: 4px; font-weight: 500; }
        .btn:hover { background: #ddd; }
        .btn-outline { background: transparent; color: #aaa; border: 1px solid #444; }
        .btn-outline:hover { border-color: #888; color: #fff; }
        .error-msg { display: none; color: #ff6b6b; margin-top: 16px; font-size: 14px; padding: 12px; background: #1a0a0a; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="player-wrap">
        <div class="player-title">` + h.EscapeString(baseName) + `</div>
        ` + playerHTML + `
        <div class="error-msg" id="errMsg"></div>
        <div class="player-actions">
            <a href="/download/` + h.EscapeString(filename) + `?token=` + h.EscapeString(token) + `" class="btn">Download</a>
            <a href="/" class="btn btn-outline">Back</a>
        </div>
    </div>
    <script>
        function showError(err) {
            var el = document.getElementById('errMsg');
            var msg = 'Cannot play this file in your browser.';
            if (err) {
                switch(err.code) {
                    case 1: msg = 'Playback aborted.'; break;
                    case 2: msg = 'Network error while loading media.'; break;
                    case 3: msg = 'Media decoding error — the format may not be supported.'; break;
                    case 4: msg = 'Media format not supported by this browser. Try downloading the file.'; break;
                }
            }
            el.textContent = msg;
            el.style.display = 'block';
        }
        document.getElementById('player').addEventListener('error', function() {
            showError(this.error);
        });
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

func HandleCreateFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path        string `json:"path"`
		CurrentPath string `json:"current_path"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if strings.Contains(req.Path, "..") || strings.Contains(req.CurrentPath, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	baseDir, _ := resolveBaseDir(r)
	// FIX: validate full path
	fullPath, ok := safePath(baseDir, filepath.Join(req.CurrentPath, req.Path))
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		http.Error(w, "Failed to create folder", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Folder created successfully"})
}

func HandleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	folderName := r.URL.Path[len("/delete-folder/"):]
	baseDir, permPrefix := resolveBaseDir(r)

	// FIX: path traversal protection
	folderPath, ok := safePath(baseDir, folderName)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if err := os.RemoveAll(folderPath); err != nil {
		http.Error(w, "Failed to delete folder", http.StatusInternalServerError)
		return
	}
	PermissionMu.Lock()
	key := permPrefix + folderName
	delete(FolderPermissions, key)
	PermissionMu.Unlock()
	SaveFolderPermissions()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Folder deleted successfully"})
}

func HandleRenameFolder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPath string `json:"old_path"`
		NewName string `json:"new_name"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	baseDir, permPrefix := resolveBaseDir(r)
	oldFullPath, ok1 := safePath(baseDir, req.OldPath)
	if !ok1 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid path"})
		return
	}

	newFullPath := filepath.Join(filepath.Dir(oldFullPath), req.NewName)
	// Validate newFullPath stays within baseDir
	absBase, _ := filepath.Abs(baseDir)
	absNew, _ := filepath.Abs(newFullPath)
	if !strings.HasPrefix(absNew, absBase) {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid new name"})
		return
	}

	if err := os.Rename(oldFullPath, newFullPath); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	PermissionMu.Lock()
	oldKey := permPrefix + req.OldPath
	if perm, exists := FolderPermissions[oldKey]; exists {
		delete(FolderPermissions, oldKey)
		newRelPath := filepath.Join(filepath.Dir(req.OldPath), req.NewName)
		FolderPermissions[permPrefix+newRelPath] = perm
	}
	PermissionMu.Unlock()
	SaveFolderPermissions()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleSetPermission(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Filename string `json:"filename"`
		IsPublic bool   `json:"is_public"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	key := req.Filename
	username := "admin"
	if u := GetSessionUser(r); u != nil {
		key = u.UUID + "/" + req.Filename
		username = u.Username
	}

	PermissionMu.Lock()
	FilePermissions[key] = FilePermission{IsPublic: req.IsPublic}
	PermissionMu.Unlock()
	SaveFilePermissions()

	status := "PRIVATE"
	if req.IsPublic {
		status = "PUBLIC"
	}
	log.Printf("[PERMISSION] user=%s file=%q set to %s", username, req.Filename, status)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Permission updated successfully"})
}

func HandleSetFolderPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path     string `json:"path"`
		IsPublic bool   `json:"is_public"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	key := req.Path
	username := "admin"
	if u := GetSessionUser(r); u != nil {
		key = u.UUID + "/" + req.Path
		username = u.Username
	}

	PermissionMu.Lock()
	FolderPermissions[key] = FolderPermission{IsPublic: req.IsPublic}
	PermissionMu.Unlock()
	SaveFolderPermissions()

	status := "PRIVATE"
	if req.IsPublic {
		status = "PUBLIC"
	}
	log.Printf("[PERMISSION] user=%s folder=%q set to %s", username, req.Path, status)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleSetChmod(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	mode, err := strconv.ParseUint(req.Mode, 8, 32)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid mode"})
		return
	}

	baseDir, _ := resolveBaseDir(r)
	fullPath, ok := safePath(baseDir, req.Path)
	if !ok {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid path"})
		return
	}

	if err := os.Chmod(fullPath, os.FileMode(mode)); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	PermissionMu.Lock()
	if perm, exists := FilePermissions[filepath.Base(req.Path)]; exists {
		perm.Mode = uint32(mode)
		FilePermissions[filepath.Base(req.Path)] = perm
	}
	PermissionMu.Unlock()
	SaveFilePermissions()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleFolderView(w http.ResponseWriter, r *http.Request) {
	folderPath := strings.TrimPrefix(r.URL.Path, "/folder/")

	// FIX: use resolveBaseDirFromToken for user folders
	baseDir, _ := resolveBaseDirFromToken(r)
	fullPath, ok := safePath(baseDir, folderPath)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil || !info.IsDir() {
		http.Error(w, "Folder not found", http.StatusNotFound)
		return
	}

	isAuth := IsAuthenticated(r)
	// Resolve permission key: for user-scoped base dirs, prefix with uuid
	_, permPrefix := resolveBaseDirFromToken(r)
	permKey := permPrefix + folderPath
	PermissionMu.RLock()
	folderPerm, folderExists := FolderPermissions[permKey]
	PermissionMu.RUnlock()
	isPublic := folderExists && folderPerm.IsPublic

	if !isAuth && !isPublic {
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		if !tokenEqual(token, Cfg.APIToken) && GetUserByToken(token) == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	entries, _ := os.ReadDir(fullPath)
	type FileInfo struct {
		Name     string `json:"name"`
		IsDir    bool   `json:"is_dir"`
		Size     int64  `json:"size"`
		ModTime  string `json:"mod_time"`
		IsPublic bool   `json:"is_public"`
	}

	var files []FileInfo
	for _, entry := range entries {
		entryInfo, _ := entry.Info()
		itemIsPublic := isPublic
		if !entry.IsDir() {
			PermissionMu.RLock()
			if perm, exists := FilePermissions[entry.Name()]; exists {
				itemIsPublic = perm.IsPublic
			}
			PermissionMu.RUnlock()
		}
		files = append(files, FileInfo{
			Name:     entry.Name(),
			IsDir:    entry.IsDir(),
			Size:     entryInfo.Size(),
			ModTime:  entryInfo.ModTime().Format("2006-01-02 15:04:05"),
			IsPublic: itemIsPublic,
		})
	}

	token := ""
	if isAuth {
		token = Cfg.APIToken
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"folder_path": folderPath,
		"folder_name": filepath.Base(folderPath),
		"is_public":   isPublic,
		"is_auth":     isAuth,
		"files":       files,
		"token":       token,
	})
}

func HandleFavicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "favicon.ico")
}

func HandleErrorPage(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	// FIX: escape user-supplied path to prevent XSS
	path := h.EscapeString(r.URL.Query().Get("path"))
	if code == "" {
		code = "403"
	}
	// Whitelist valid status codes
	switch code {
	case "400", "401", "403", "404", "500":
	default:
		code = "403"
	}

	title := "Access Denied"
	message := "You do not have permission to access this resource."
	hint := "If you have a valid link, make sure it includes the access token."

	if code == "404" {
		title = "Page Not Found"
		message = "The page or file you are looking for does not exist."
		hint = "Double-check the URL or go back to the home page."
	} else if code == "401" {
		title = "Unauthorized"
		message = "Authentication is required to access this resource."
		hint = "Please log in or provide a valid access token."
	}

	pathHTML := ""
	if path != "" {
		pathHTML = `<div class="error-path">Requested path: <code>` + path + `</code></div>`
	}

	pageHTML := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>` + code + ` - ` + title + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #fff; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; }
        .container { max-width: 580px; width: 100%; text-align: center; }
        .code { font-size: 96px; font-weight: 700; letter-spacing: -4px; line-height: 1; margin-bottom: 24px; color: #e8b84b; }
        .warning-icon { display: block; margin: 0 auto 20px; width: 56px; height: 56px; background: #e8b84b; clip-path: polygon(50% 0%, 0% 100%, 100% 100%); position: relative; }
        .warning-icon::after { content: '!'; position: absolute; top: 52%; left: 50%; transform: translate(-50%, -50%); font-size: 28px; font-weight: 700; color: #0a0a0a; }
        h1 { font-size: 26px; font-weight: 600; margin-bottom: 12px; }
        .message { font-size: 16px; color: #aaa; line-height: 1.6; margin-bottom: 16px; }
        .hint { font-size: 13px; color: #666; background: #1a1a1a; border: 1px solid #2a2a2a; border-left: 3px solid #e8b84b; padding: 14px 16px; text-align: left; margin-bottom: 24px; border-radius: 0 4px 4px 0; line-height: 1.5; }
        .error-path { font-size: 12px; color: #555; margin-bottom: 24px; font-family: monospace; }
        .error-path code { background: #1a1a1a; padding: 2px 8px; border-radius: 3px; color: #888; }
        .actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
        .btn { padding: 10px 22px; background: #fff; color: #000; text-decoration: none; font-size: 14px; font-weight: 500; border-radius: 4px; }
        .btn:hover { background: #e0e0e0; }
        .btn-outline { background: transparent; color: #fff; border: 1px solid #333; }
        .btn-outline:hover { border-color: #666; background: #1a1a1a; color: #fff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-icon"></div>
        <div class="code">` + code + `</div>
        <h1>` + title + `</h1>
        <p class="message">` + message + `</p>
        <div class="hint">` + hint + `</div>
        ` + pathHTML + `
        <div class="actions">
            <a href="/" class="btn">Go Home</a>
            <a href="/ac" class="btn btn-outline">Login</a>
            <a href="javascript:history.back()" class="btn btn-outline">Go Back</a>
        </div>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(403)
	w.Write([]byte(pageHTML))
}

func HandleFolderInfo(w http.ResponseWriter, r *http.Request) {
	folderPath := strings.TrimPrefix(r.URL.Path, "/folder-info/")
	baseDir, permPrefix := resolveBaseDir(r)

	// FIX: path traversal protection
	fullPath, ok := safePath(baseDir, folderPath)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	var totalSize int64
	var fileCount int64
	var folderCount int64

	filepath.Walk(fullPath, func(p string, info os.FileInfo, err error) error {
		if err != nil || p == fullPath {
			return nil
		}
		if info.IsDir() {
			folderCount++
		} else {
			fileCount++
			totalSize += info.Size()
		}
		return nil
	})

	permKey := permPrefix + folderPath
	PermissionMu.RLock()
	perm, exists := FolderPermissions[permKey]
	PermissionMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"path":         folderPath,
		"name":         filepath.Base(folderPath),
		"total_size":   totalSize,
		"file_count":   fileCount,
		"folder_count": folderCount,
		"is_public":    exists && perm.IsPublic,
	})
}

func HandleEmbedPreview(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/embed/")

	// FIX: use resolveBaseDirFromToken for user files
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, filename)
	if !ok {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	stat, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	token := r.URL.Query().Get("token")
	baseName := filepath.Base(filename)
	fileType := GetFileType(filename)

	streamURL := "/stream/" + h.EscapeString(filename)
	downloadURL := "/download/" + h.EscapeString(filename)
	if token != "" {
		streamURL += "?token=" + h.EscapeString(token)
		downloadURL += "?token=" + h.EscapeString(token)
	}

	embedTitle := Cfg.EmbedTitle
	if embedTitle == "" {
		embedTitle = baseName + " — " + Cfg.SiteName
	}
	embedDesc := Cfg.EmbedDescription
	if embedDesc == "" {
		embedDesc = "File sharing powered by " + Cfg.SiteName
	}
	embedImage := Cfg.EmbedImageURL
	if embedImage == "" {
		embedImage = Cfg.IconURL
	}

	protocol := GetProtocol()
	baseURL := protocol + "://" + r.Host

	ogType := "website"
	if fileType == "video" {
		ogType = "video.other"
	} else if fileType == "image" {
		ogType = "image"
		embedImage = baseURL + "/raw/" + h.EscapeString(filename)
		if token != "" {
			embedImage += "?token=" + h.EscapeString(token)
		}
	} else if fileType == "audio" {
		ogType = "music.song"
	}

	var bodyContent string
	switch fileType {
	case "video":
		bodyContent = `<video controls playsinline preload="metadata" style="width:100%;max-height:80vh;background:#000;border-radius:8px;">
            <source src="` + streamURL + `">
            <p style="color:#999;padding:20px;">Your browser does not support this video format. <a href="` + downloadURL + `" style="color:#e07820;">Download</a></p>
        </video>`
	case "audio":
		bodyContent = `<div style="padding:40px 0;">
            <div style="font-size:48px;text-align:center;margin-bottom:24px;">&#127925;</div>
            <audio controls preload="metadata" style="width:100%;">
                <source src="` + streamURL + `">
                <p style="color:#999;">Your browser does not support this audio format. <a href="` + downloadURL + `" style="color:#e07820;">Download</a></p>
            </audio>
        </div>`
	case "image":
		imageURL := "/raw/" + h.EscapeString(filename)
		if token != "" {
			imageURL += "?token=" + h.EscapeString(token)
		}
		bodyContent = `<img src="` + imageURL + `" style="max-width:100%;max-height:80vh;object-fit:contain;border-radius:4px;">`
	default:
		bodyContent = `<div style="padding:60px;text-align:center;color:#999;">
            <div style="font-size:48px;margin-bottom:16px;">&#128196;</div>
            <div style="font-size:18px;font-weight:500;color:#fff;margin-bottom:8px;">` + h.EscapeString(baseName) + `</div>
            <div style="font-size:14px;margin-bottom:24px;">` + FormatBytes(stat.Size()) + `</div>
            <a href="` + downloadURL + `" style="padding:12px 24px;background:#e07820;color:#fff;text-decoration:none;border-radius:6px;font-weight:500;">Download</a>
        </div>`
	}

	pageHTML := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + h.EscapeString(embedTitle) + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta property="og:title" content="` + h.EscapeString(embedTitle) + `">
    <meta property="og:description" content="` + h.EscapeString(embedDesc) + `">
    <meta property="og:image" content="` + h.EscapeString(embedImage) + `">
    <meta property="og:type" content="` + ogType + `">
    <meta property="og:url" content="` + h.EscapeString(baseURL+r.URL.Path) + `">
    <meta property="og:site_name" content="` + h.EscapeString(Cfg.SiteName) + `">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="` + h.EscapeString(embedTitle) + `">
    <meta name="twitter:description" content="` + h.EscapeString(embedDesc) + `">
    <meta name="twitter:image" content="` + h.EscapeString(embedImage) + `">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #fff; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
        .embed-wrap { width: 100%; max-width: 900px; }
        .embed-header { margin-bottom: 20px; }
        .embed-title { font-size: 18px; font-weight: 600; margin-bottom: 6px; word-break: break-all; }
        .embed-meta { font-size: 13px; color: #888; }
        .embed-body { background: #111; border-radius: 12px; overflow: hidden; padding: 16px; }
        .embed-footer { margin-top: 20px; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
        .btn { padding: 9px 20px; background: #fff; color: #000; text-decoration: none; border-radius: 6px; font-size: 13px; font-weight: 500; }
        .btn:hover { background: #ddd; }
        .btn-outline { background: transparent; color: #aaa; border: 1px solid #333; }
        .btn-outline:hover { border-color: #666; color: #fff; }
        .powered { font-size: 11px; color: #444; margin-left: auto; }
    </style>
</head>
<body>
    <div class="embed-wrap">
        <div class="embed-header">
            <div class="embed-title">` + h.EscapeString(baseName) + `</div>
            <div class="embed-meta">` + FormatBytes(stat.Size()) + ` &middot; ` + h.EscapeString(fileType) + ` &middot; ` + stat.ModTime().Format("2006-01-02") + `</div>
        </div>
        <div class="embed-body">` + bodyContent + `</div>
        <div class="embed-footer">
            <a href="` + downloadURL + `" class="btn">Download</a>
            <a href="/" class="btn btn-outline">` + h.EscapeString(Cfg.SiteName) + `</a>
            <span class="powered">powered by servernotdie v` + VERSION + `</span>
        </div>
    </div>
    <script>
        document.querySelectorAll('video, audio').forEach(function(el) {
            el.addEventListener('error', function() {
                var err = el.error;
                var msg = 'Cannot play in browser. ';
                if (err && err.code === 4) msg += 'Format not supported — try downloading.';
                var div = document.createElement('div');
                div.style.cssText = 'color:#ff6b6b;padding:16px;font-size:14px;';
                div.textContent = msg;
                el.parentNode.insertBefore(div, el.nextSibling);
            });
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

// HandleLibFile serves static files from the lib/ directory, including subdirectories (for Monaco).
func HandleLibFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/lib/")

	// FIX: was blocking "/" which prevented Monaco subdirectory loading
	// Now use safePath to allow subdirectories while preventing traversal
	libPath, ok := safePath("lib", name)
	if !ok || strings.Contains(name, "..") {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Set content type by extension
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".json"):
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	case strings.HasSuffix(name, ".woff2"):
		w.Header().Set("Content-Type", "font/woff2")
	case strings.HasSuffix(name, ".woff"):
		w.Header().Set("Content-Type", "font/woff")
	case strings.HasSuffix(name, ".ttf"):
		w.Header().Set("Content-Type", "font/ttf")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(w, r, libPath)
}

// HandleAPIView streams or renders image/video directly for the new /api/view/{file_id} endpoint.
// file_id is the URL-encoded relative file path (same as used in /raw/).
func HandleAPIView(w http.ResponseWriter, r *http.Request) {
	fileID := strings.TrimPrefix(r.URL.Path, "/api/view/")
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, fileID)
	if !ok {
		RenderErrorPage(w, http.StatusBadRequest, "Invalid Path", "Invalid file path.", "")
		return
	}
	f, err := os.Open(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "Not Found", "File not found.", "")
		return
	}
	defer f.Close()
	stat, _ := f.Stat()

	fileType := GetFileType(fileID)
	ext := strings.ToLower(filepath.Ext(fileID))

	switch fileType {
	case "image":
		ct := map[string]string{
			".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
			".svg": "image/svg+xml", ".bmp": "image/bmp", ".avif": "image/avif",
			".tif": "image/tiff", ".tiff": "image/tiff",
		}
		if c, ok := ct[ext]; ok {
			w.Header().Set("Content-Type", c)
		} else {
			w.Header().Set("Content-Type", "image/jpeg")
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	case "video", "audio":
		ct := getMediaContentType(fileID)
		// HLS support
		if ext == ".m3u8" {
			ct = "application/vnd.apple.mpegurl"
		} else if ext == ".ts" {
			ct = "video/mp2t"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	}
}

// HandleThumbnail serves a small inline version of an image for thumbnail display.
// For video files it returns a placeholder. For images it returns the image at reduced size hint.
func HandleThumbnail(w http.ResponseWriter, r *http.Request) {
	fileID := strings.TrimPrefix(r.URL.Path, "/thumbnail/")
	baseDir, _ := resolveBaseDirFromToken(r)
	filePath, ok := safePath(baseDir, fileID)
	if !ok {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	fileType := GetFileType(fileID)
	if fileType != "image" {
		// Return a simple SVG placeholder for non-images
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="120" height="80" viewBox="0 0 120 80"><rect width="120" height="80" fill="#1a1a1a"/><polygon points="45,25 45,55 75,40" fill="#666"/></svg>`))
		return
	}
	f, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	stat, _ := f.Stat()
	ext := strings.ToLower(filepath.Ext(fileID))
	ct := map[string]string{
		".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
		".svg": "image/svg+xml", ".bmp": "image/bmp",
	}
	if c, ok := ct[ext]; ok {
		w.Header().Set("Content-Type", c)
	} else {
		w.Header().Set("Content-Type", "image/jpeg")
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}
