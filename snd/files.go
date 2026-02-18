package snd

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	h "html"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func HandleUpload(w http.ResponseWriter, r *http.Request) {
	GlobalStatsMu.Lock()
	GlobalStats.TotalRequests++
	GlobalStatsMu.Unlock()

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseMultipartForm(0)

	currentPath := r.URL.Query().Get("path")
	if strings.Contains(currentPath, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	uploadedCount := 0
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			continue
		}
		defer file.Close()

		targetPath := filepath.Join(PublicDir, currentPath, fileHeader.Filename)
		dst, err := os.Create(targetPath)
		if err != nil {
			continue
		}
		defer dst.Close()

		written, err := io.Copy(dst, file)
		if err != nil {
			continue
		}
		uploadedCount++
		if Debug {
			log.Printf("Uploaded: %s (%d bytes)", targetPath, written)
		}
	}
	UpdateStats()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("%d file(s) uploaded", uploadedCount)))
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
		http.Redirect(w, r, "/stream/"+filename+"?token="+token, http.StatusSeeOther)
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

	html := `<!DOCTYPE html>
<html>
<head>
    <title>View: ` + filepath.Base(filename) + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
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
        .file-info { display: flex; gap: 20px; padding: 12px; background: #f9f9f9; border-radius: 4px; margin-bottom: 20px; font-size: 13px; color: #666; }
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
	w.Write([]byte(html))
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
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Edit: ` + filepath.Base(filename) + `</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
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
        .editor-info { padding: 12px 20px; background: #f9f9f9; border-bottom: 1px solid #e0e0e0; font-size: 13px; color: #666; display: flex; gap: 20px; }
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
	w.Write([]byte(html))
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

func HandleRaw(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/raw/"):]
	filePath := filepath.Join(PublicDir, filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're looking for doesn't exist.", "Path: "+r.URL.Path)
		return
	}

	fileType := GetFileType(filename)
	ext := strings.ToLower(filepath.Ext(filename))

	switch fileType {
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	case "image":
		ct := "image/jpeg"
		switch ext {
		case ".png":
			ct = "image/png"
		case ".gif":
			ct = "image/gif"
		case ".webp":
			ct = "image/webp"
		case ".svg":
			ct = "image/svg+xml"
		}
		w.Header().Set("Content-Type", ct)
	case "video":
		ct := "video/mp4"
		switch ext {
		case ".webm":
			ct = "video/webm"
		case ".ogg":
			ct = "video/ogg"
		}
		w.Header().Set("Content-Type", ct)
	case "audio":
		ct := "audio/mpeg"
		switch ext {
		case ".wav":
			ct = "audio/wav"
		case ".ogg":
			ct = "audio/ogg"
		case ".m4a":
			ct = "audio/mp4"
		}
		w.Header().Set("Content-Type", ct)
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Write(content)
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
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filename))
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

	// Clean up permissions so deleted files don't linger in public list
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
	w.Header().Set("Content-Disposition", "attachment; filename=archive.zip")
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

	file, err := os.Open(filePath)
	if err != nil {
		RenderErrorPage(w, http.StatusNotFound, "File Not Found",
			"The file you're looking for doesn't exist.", "Path: "+r.URL.Path)
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Error getting file info", http.StatusInternalServerError)
		return
	}
	size := stat.Size()

	ext := strings.ToLower(filepath.Ext(filename))
	contentType := "video/mp4"
	switch ext {
	case ".webm":
		contentType = "video/webm"
	case ".ogg":
		contentType = "video/ogg"
	case ".mov":
		contentType = "video/quicktime"
	case ".avi":
		contentType = "video/x-msvideo"
	case ".mkv":
		contentType = "video/x-matroska"
	}

	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("Accept-Ranges", "bytes")
		io.Copy(w, file)
		return
	}

	var start, end int64
	fmt.Sscanf(rangeHeader, "bytes=%d-", &start)
	if start >= size {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		http.Error(w, "Requested Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	end = size - 1
	if endStr := strings.Split(rangeHeader, "-")[1]; endStr != "" {
		fmt.Sscanf(endStr, "%d", &end)
		if end >= size {
			end = size - 1
		}
	}

	contentLength := end - start + 1
	file.Seek(start, 0)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
	w.WriteHeader(http.StatusPartialContent)
	io.CopyN(w, file, contentLength)
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

// HandleErrorPage shows a styled error/warning page for unauthorized access or wrong paths
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

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>` + code + ` - ` + title + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0a0a0a;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
        }
        .container { max-width: 580px; width: 100%; text-align: center; }
        .code {
            font-size: 96px;
            font-weight: 700;
            letter-spacing: -4px;
            line-height: 1;
            margin-bottom: 24px;
            color: #e8b84b;
        }
        .warning-icon {
            display: block;
            margin: 0 auto 20px;
            width: 56px;
            height: 56px;
            background: #e8b84b;
            clip-path: polygon(50% 0%, 0% 100%, 100% 100%);
            position: relative;
        }
        .warning-icon::after {
            content: '!';
            position: absolute;
            top: 52%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 28px;
            font-weight: 700;
            color: #0a0a0a;
        }
        h1 { font-size: 26px; font-weight: 600; margin-bottom: 12px; }
        .message { font-size: 16px; color: #aaa; line-height: 1.6; margin-bottom: 16px; }
        .hint {
            font-size: 13px;
            color: #666;
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-left: 3px solid #e8b84b;
            padding: 14px 16px;
            text-align: left;
            margin-bottom: 24px;
            border-radius: 0 4px 4px 0;
            line-height: 1.5;
        }
        .error-path {
            font-size: 12px;
            color: #555;
            margin-bottom: 24px;
            font-family: monospace;
        }
        .error-path code {
            background: #1a1a1a;
            padding: 2px 8px;
            border-radius: 3px;
            color: #888;
        }
        .actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
        .btn {
            padding: 10px 22px;
            background: #fff;
            color: #000;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            border-radius: 4px;
        }
        .btn:hover { background: #e0e0e0; }
        .btn-outline {
            background: transparent;
            color: #fff;
            border: 1px solid #333;
        }
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
	w.Write([]byte(html))
}

// HandleFolderInfo returns folder size, file count, and other metadata
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
