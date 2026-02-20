package snd

import (
	"archive/zip"
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

		targetPath := filepath.Join(PublicDir, currentPath, filename)
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

		uploadedCount++
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

	targetPath := filepath.Join(PublicDir, currentPath, filename)
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
	dirPath := filepath.Join(PublicDir, path)

	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	isAuth := IsAuthenticated(r)

	files, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	var fileList []FileMetadataWithPermission
	var folders []string

	for _, file := range files {
		if file.IsDir() {
			folderKey := file.Name()
			if path != "" {
				folderKey = filepath.Join(path, file.Name())
			}
			PermissionMu.RLock()
			folderPerm, folderExists := FolderPermissions[folderKey]
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
			PermissionMu.RLock()
			perm, exists := FilePermissions[fullPath]
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
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files":   fileList,
		"folders": folders,
	})
}

func HandleView(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/view/"):]
	filePath := filepath.Join(PublicDir, filename)

	info, err := os.Stat(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're trying to view doesn't exist.", "File: "+filename)
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
		editButton = `<a href="/edit/` + filename + `?token=` + token + `" class="btn">Edit File</a>`
	}

	contentHTML := ""
	if fileType == "text" {
		contentHTML = `<div class="code-block">` + h.EscapeString(string(content)) + `</div>`
	} else if fileType == "document" && strings.HasSuffix(filename, ".pdf") {
		contentHTML = `<iframe src="/raw/` + filename + `?token=` + token + `" style="width:100%;height:800px;border:none;"></iframe>`
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
    <title>View: ` + filepath.Base(filename) + `</title>
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
            <div class="viewer-title">` + filepath.Base(filename) + `</div>
            <div class="viewer-actions">
                ` + editButton + `
                <a href="/download/` + filename + `?token=` + token + `" class="btn">Download</a>
                <a href="/" class="btn">Back to Files</a>
            </div>
        </div>
        <div class="viewer-content">
            <div class="file-info">
                <span><strong>Size:</strong> ` + FormatBytes(info.Size()) + `</span>
                <span><strong>Type:</strong> ` + fileType + `</span>
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

func HandleEdit(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/edit/"):]
	filePath := filepath.Join(PublicDir, filename)

	info, err := os.Stat(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're trying to edit doesn't exist.", "File: "+filename)
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
			"Only text files can be edited.", "File type: "+fileType)
		return
	}

	token := r.URL.Query().Get("token")
	editHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Edit: ` + filepath.Base(filename) + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #fafafa; height: 100vh; display: flex; flex-direction: column; }
        .editor-header { background: white; border-bottom: 1px solid #e0e0e0; padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
        .editor-title { font-size: 16px; font-weight: 500; }
        .editor-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .btn { padding: 8px 16px; background: #1a1a1a; color: white; text-decoration: none; border: none; cursor: pointer; font-size: 13px; white-space: nowrap; border-radius: 2px; }
        .btn:hover { background: #333; }
        .btn-primary { background: #2563eb; }
        .btn-primary:hover { background: #1d4ed8; }
        .editor-container { flex: 1; display: flex; flex-direction: column; background: white; margin: 20px; border: 1px solid #e0e0e0; border-radius: 4px; overflow: hidden; }
        .editor-info { padding: 12px 20px; background: #f9f9f9; border-bottom: 1px solid #e0e0e0; font-size: 13px; color: #666; display: flex; gap: 20px; flex-wrap: wrap; }
        .editor-textarea { flex: 1; padding: 16px; border: none; font-family: 'Monaco', monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; }
        .save-status { display: none; padding: 8px 16px; background: #10b981; color: white; border-radius: 4px; font-size: 13px; }
        .save-status.error { background: #ef4444; }
    </style>
</head>
<body>
    <div class="editor-header">
        <div class="editor-title">Editing: ` + filepath.Base(filename) + `</div>
        <div class="editor-actions">
            <span class="save-status" id="saveStatus">Saved</span>
            <button class="btn btn-primary" onclick="saveFile()">Save (Ctrl+S)</button>
            <a href="/view/` + filename + `?token=` + token + `" class="btn">View</a>
            <a href="/" class="btn">Cancel</a>
        </div>
    </div>
    <div class="editor-container">
        <div class="editor-info">
            <span><strong>Size:</strong> ` + FormatBytes(info.Size()) + `</span>
            <span><strong>Lines:</strong> <span id="lineCount">0</span></span>
            <span><strong>Modified:</strong> ` + info.ModTime().Format("2006-01-02 15:04:05") + `</span>
        </div>
        <textarea class="editor-textarea" id="editor">` + h.EscapeString(string(content)) + `</textarea>
    </div>
    <script>
        const editor = document.getElementById('editor');
        const lineCount = document.getElementById('lineCount');
        const saveStatus = document.getElementById('saveStatus');
        let originalContent = editor.value;

        function updateLineCount() {
            lineCount.textContent = editor.value.split('\n').length;
        }
        editor.addEventListener('input', updateLineCount);
        updateLineCount();

        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                saveFile();
            }
        });

        function saveFile() {
            const content = editor.value;
            fetch('/save/` + filename + `?token=` + token + `', {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                body: content
            })
            .then(response => {
                if (response.ok) {
                    originalContent = content;
                    showStatus('Saved successfully', false);
                } else {
                    showStatus('Error saving file', true);
                }
            })
            .catch(() => showStatus('Network error', true));
        }

        function showStatus(msg, isError) {
            saveStatus.textContent = msg;
            saveStatus.className = 'save-status' + (isError ? ' error' : '');
            saveStatus.style.display = 'block';
            setTimeout(() => { saveStatus.style.display = 'none'; }, 3000);
        }

        window.addEventListener('beforeunload', function(e) {
            if (editor.value !== originalContent) {
                e.preventDefault();
                e.returnValue = '';
            }
        });
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
	filePath := filepath.Join(PublicDir, filename)

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

func HandleRaw(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/raw/"):]
	filePath := filepath.Join(PublicDir, filename)

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
		default:
			contentType = "image/jpeg"
		}
	case "video", "audio":
		contentType = getMediaContentType(filename)
	default:
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func HandleDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/download/"):]
	filePath := filepath.Join(PublicDir, filename)

	DownloadMu.Lock()
	DownloadCounts[filename]++
	DownloadMu.Unlock()
	SaveDownloadCounts()

	if Debug {
		log.Printf("Download: %s", filename)
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(filename)+"\"")
	http.ServeFile(w, r, filePath)
}

func HandleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := r.URL.Path[len("/delete/"):]
	filePath := filepath.Join(PublicDir, filename)

	if err := os.Remove(filePath); err != nil {
		http.Error(w, "Error deleting file", http.StatusInternalServerError)
		return
	}
	DownloadMu.Lock()
	delete(DownloadCounts, filename)
	DownloadMu.Unlock()
	SaveDownloadCounts()

	PermissionMu.Lock()
	delete(FilePermissions, filename)
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

	oldPath := filepath.Join(PublicDir, oldName)
	newPath := filepath.Join(PublicDir, req.NewName)

	if err := os.Rename(oldPath, newPath); err != nil {
		http.Error(w, "Error renaming file", http.StatusInternalServerError)
		return
	}
	DownloadMu.Lock()
	if count, exists := DownloadCounts[oldName]; exists {
		DownloadCounts[req.NewName] = count
		delete(DownloadCounts, oldName)
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
	srcPath := filepath.Join(PublicDir, filename)

	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	newName := base + "_copy" + ext

	counter := 1
	for {
		newPath := filepath.Join(PublicDir, newName)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
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

	dst, err := os.Create(filepath.Join(PublicDir, newName))
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

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"archive.zip\"")
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	for _, filename := range req.Files {
		file, err := os.Open(filepath.Join(PublicDir, filename))
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
	reader, err := zip.OpenReader(filepath.Join(PublicDir, filename))
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
	zipPath := strings.TrimPrefix(r.URL.Path, "/extract-zip/")
	fullZipPath := filepath.Join(PublicDir, zipPath)

	extractDir := strings.TrimSuffix(fullZipPath, filepath.Ext(fullZipPath))
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	reader, err := zip.OpenReader(fullZipPath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	defer reader.Close()

	for _, file := range reader.File {
		path := filepath.Join(extractDir, file.Name)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode())
			continue
		}
		fileReader, err := file.Open()
		if err != nil {
			continue
		}
		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			fileReader.Close()
			continue
		}
		io.Copy(targetFile, fileReader)
		targetFile.Close()
		fileReader.Close()
	}

	LogAccess(GetClientIP(r), "extract-zip", zipPath, r.UserAgent())
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleStream(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/stream/"):]
	filePath := filepath.Join(PublicDir, filename)

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

	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func HandleStreamPage(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/play/"):]
	filePath := filepath.Join(PublicDir, filename)

	_, err := os.Stat(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The media file you're looking for doesn't exist.", "File: "+filename)
		return
	}

	token := r.URL.Query().Get("token")
	streamURL := "/stream/" + filename
	if token != "" {
		streamURL += "?token=" + token
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
    <title>` + baseName + `</title>
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
        <div class="player-title">` + baseName + `</div>
        ` + playerHTML + `
        <div class="error-msg" id="errMsg"></div>
        <div class="player-actions">
            <a href="/download/` + filename + `?token=` + token + `" class="btn">Download</a>
            <a href="/" class="btn btn-outline">Back</a>
        </div>
    </div>
    <script>
        function showError(err) {
            const el = document.getElementById('errMsg');
            let msg = 'Cannot play this file in your browser.';
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
	fullPath := filepath.Join(PublicDir, req.CurrentPath, req.Path)
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
	if err := os.RemoveAll(filepath.Join(PublicDir, folderName)); err != nil {
		http.Error(w, "Failed to delete folder", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Folder deleted successfully"})
}

func HandleRenameFolder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPath string `json:"old_path"`
		NewName string `json:"new_name"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	oldFullPath := filepath.Join(PublicDir, req.OldPath)
	newFullPath := filepath.Join(filepath.Dir(oldFullPath), req.NewName)

	if err := os.Rename(oldFullPath, newFullPath); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	PermissionMu.Lock()
	if perm, exists := FolderPermissions[req.OldPath]; exists {
		delete(FolderPermissions, req.OldPath)
		newPath := filepath.Join(filepath.Dir(req.OldPath), req.NewName)
		FolderPermissions[newPath] = perm
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

	PermissionMu.Lock()
	FilePermissions[req.Filename] = FilePermission{IsPublic: req.IsPublic, Token: Cfg.APIToken}
	PermissionMu.Unlock()
	SaveFilePermissions()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Permission updated successfully"})
}

func HandleSetFolderPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path     string `json:"path"`
		IsPublic bool   `json:"is_public"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	PermissionMu.Lock()
	FolderPermissions[req.Path] = FolderPermission{IsPublic: req.IsPublic, Token: Cfg.APIToken}
	PermissionMu.Unlock()
	SaveFolderPermissions()
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
	fullPath := filepath.Join(PublicDir, req.Path)
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
	fullPath := filepath.Join(PublicDir, folderPath)

	info, err := os.Stat(fullPath)
	if err != nil || !info.IsDir() {
		http.Error(w, "Folder not found", http.StatusNotFound)
		return
	}

	isAuth := IsAuthenticated(r)
	PermissionMu.RLock()
	folderPerm, folderExists := FolderPermissions[folderPath]
	PermissionMu.RUnlock()
	isPublic := folderExists && folderPerm.IsPublic

	if !isAuth && !isPublic {
		token := r.URL.Query().Get("token")
		if token != Cfg.APIToken {
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
	path := r.URL.Query().Get("path")
	if code == "" {
		code = "403"
	}

	title := "Access Denied"
	message := "You do not have permission to access this resource."
	hint := "If you have a valid link, make sure it includes the access token."

	if code == "404" {
		title = "Page Not Found"
		message = "The page or file you are looking for does not exist."
		hint = "Double-check the URL or go back to the home page."
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
	fullPath := filepath.Join(PublicDir, folderPath)

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

	PermissionMu.RLock()
	perm, exists := FolderPermissions[folderPath]
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
	filePath := filepath.Join(PublicDir, filename)

	stat, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	token := r.URL.Query().Get("token")
	baseName := filepath.Base(filename)
	fileType := GetFileType(filename)

	streamURL := "/stream/" + filename
	downloadURL := "/download/" + filename
	if token != "" {
		streamURL += "?token=" + token
		downloadURL += "?token=" + token
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
		embedImage = baseURL + "/raw/" + filename
		if token != "" {
			embedImage += "?token=" + token
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
		imageURL := "/raw/" + filename
		if token != "" {
			imageURL += "?token=" + token
		}
		bodyContent = `<img src="` + imageURL + `" style="max-width:100%;max-height:80vh;object-fit:contain;border-radius:4px;">`
	default:
		bodyContent = `<div style="padding:60px;text-align:center;color:#999;">
            <div style="font-size:48px;margin-bottom:16px;">&#128196;</div>
            <div style="font-size:18px;font-weight:500;color:#fff;margin-bottom:8px;">` + baseName + `</div>
            <div style="font-size:14px;margin-bottom:24px;">` + FormatBytes(stat.Size()) + `</div>
            <a href="` + downloadURL + `" style="padding:12px 24px;background:#e07820;color:#fff;text-decoration:none;border-radius:6px;font-weight:500;">Download</a>
        </div>`
	}

	pageHTML := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + embedTitle + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta property="og:title" content="` + embedTitle + `">
    <meta property="og:description" content="` + embedDesc + `">
    <meta property="og:image" content="` + embedImage + `">
    <meta property="og:type" content="` + ogType + `">
    <meta property="og:url" content="` + baseURL + r.URL.Path + `">
    <meta property="og:site_name" content="` + Cfg.SiteName + `">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="` + embedTitle + `">
    <meta name="twitter:description" content="` + embedDesc + `">
    <meta name="twitter:image" content="` + embedImage + `">
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
            <div class="embed-title">` + baseName + `</div>
            <div class="embed-meta">` + FormatBytes(stat.Size()) + ` &middot; ` + fileType + ` &middot; ` + stat.ModTime().Format("2006-01-02") + `</div>
        </div>
        <div class="embed-body">` + bodyContent + `</div>
        <div class="embed-footer">
            <a href="` + downloadURL + `" class="btn">Download</a>
            <a href="/" class="btn btn-outline">` + Cfg.SiteName + `</a>
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



func HandleLibFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/lib/")
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	path := "lib/" + name
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(w, r, path)
}
