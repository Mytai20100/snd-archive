package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const VERSION = "1.2 beta"

type Config struct {
	IP       string `yaml:"ip"`
	Port     string `yaml:"port"`
	SiteName string `yaml:"site_name"`
	IconURL  string `yaml:"icon_url"`
}

var (
	debug      bool
	publicDir  = "public"
	configFile = "config.yml"
	config     Config
)

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.Parse()

	if err := os.MkdirAll(publicDir, 0755); err != nil {
		log.Fatalf("Failed to create public directory: %v", err)
	}

	config = loadConfig()

	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/files", handleListFiles)
	http.HandleFunc("/download/", handleDownload)
	http.HandleFunc("/view/", handleView)
	http.HandleFunc("/edit/", handleEdit)
	http.HandleFunc("/save/", handleSave)
	http.HandleFunc("/delete/", handleDelete)
	http.HandleFunc("/raw/", handleRaw)
	http.HandleFunc("/", handleFileOrIndex)

	addr := config.IP + ":" + config.Port
	fmt.Printf("ServerNotDie v%s\n", VERSION)
	fmt.Printf("Server starting on http://%s\n", addr)
	fmt.Printf("Site Name: %s\n", config.SiteName)
	fmt.Printf("Public directory: %s\n", publicDir)
	fmt.Printf("Debug mode: %v\n", debug)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func loadConfig() Config {
	cfg := Config{
		IP:       "0.0.0.0",
		Port:     "8080",
		SiteName: "File Manager",
		IconURL:  "https://cdn-icons-png.flaticon.com/512/716/716784.png",
	}

	data, err := os.ReadFile(configFile)
	if err == nil {
		yaml.Unmarshal(data, &cfg)
	} else {
		data, _ := yaml.Marshal(cfg)
		os.WriteFile(configFile, data, 0644)
		fmt.Printf("Created default config file: %s\n", configFile)
	}

	return cfg
}

func getFileType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	
	// Text files
	textExts := []string{".txt", ".log", ".md", ".json", ".xml", ".html", ".css", ".js", ".yml", ".yaml", ".conf", ".cfg", ".sh", ".bat", ".py", ".go", ".java", ".c", ".cpp", ".h", ".php", ".rb", ".rs", ".sql"}
	for _, e := range textExts {
		if ext == e {
			return "text"
		}
	}
	
	// Images
	imageExts := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico"}
	for _, e := range imageExts {
		if ext == e {
			return "image"
		}
	}
	
	// Videos
	videoExts := []string{".mp4", ".webm", ".ogg", ".mov", ".avi", ".mkv", ".flv", ".wmv"}
	for _, e := range videoExts {
		if ext == e {
			return "video"
		}
	}
	
	// Audio
	audioExts := []string{".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".wma"}
	for _, e := range audioExts {
		if ext == e {
			return "audio"
		}
	}
	
	return "binary"
}

func handleFileOrIndex(w http.ResponseWriter, r *http.Request) {
	// Nếu là root path, hiển thị trang chủ
	if r.URL.Path == "/" {
		handleIndex(w, r)
		return
	}

	// Lấy tên file từ path (bỏ dấu / đầu tiên)
	filename := strings.TrimPrefix(r.URL.Path, "/")
	
	// Kiểm tra nếu file tồn tại trong thư mục public
	filePath := filepath.Join(publicDir, filename)
	if _, err := os.Stat(filePath); err == nil {
		// File tồn tại, serve file
		serveFile(w, r, filename, filePath)
		return
	}

	// File không tồn tại, trả về 404
	http.NotFound(w, r)
}

func serveFile(w http.ResponseWriter, r *http.Request, filename string, filePath string) {
	if debug {
		log.Printf("Direct access: %s", filename)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	fileType := getFileType(filename)
	
	switch fileType {
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	case "image":
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
		case ".png":
			w.Header().Set("Content-Type", "image/png")
		case ".gif":
			w.Header().Set("Content-Type", "image/gif")
		case ".webp":
			w.Header().Set("Content-Type", "image/webp")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		default:
			w.Header().Set("Content-Type", "image/jpeg")
		}
	case "video":
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".mp4":
			w.Header().Set("Content-Type", "video/mp4")
		case ".webm":
			w.Header().Set("Content-Type", "video/webm")
		case ".ogg":
			w.Header().Set("Content-Type", "video/ogg")
		default:
			w.Header().Set("Content-Type", "video/mp4")
		}
	case "audio":
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".mp3":
			w.Header().Set("Content-Type", "audio/mpeg")
		case ".wav":
			w.Header().Set("Content-Type", "audio/wav")
		case ".ogg":
			w.Header().Set("Content-Type", "audio/ogg")
		case ".m4a":
			w.Header().Set("Content-Type", "audio/mp4")
		default:
			w.Header().Set("Content-Type", "audio/mpeg")
		}
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	
	w.Write(content)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + config.SiteName + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: #fafafa;
            color: #1a1a1a;
            line-height: 1.6;
            padding-bottom: 60px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: #fff;
        }
        .header {
            background: #fff;
            border-bottom: 1px solid #e0e0e0;
            padding: 24px 32px;
        }
        .header h1 {
            font-size: 20px;
            font-weight: 500;
            color: #1a1a1a;
            letter-spacing: -0.3px;
        }
        .upload-section {
            padding: 32px;
            border-bottom: 1px solid #e0e0e0;
        }
        .upload-area {
            position: relative;
            width: 100%;
            min-height: 140px;
            border: 1px solid #d0d0d0;
            background: #fafafa;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        .upload-area.dragover {
            border-color: #1a1a1a;
            background: #f0f0f0;
        }
        .upload-area:hover {
            border-color: #1a1a1a;
        }
        .upload-area input[type="file"] {
            position: absolute;
            width: 100%;
            height: 100%;
            opacity: 0;
            cursor: pointer;
        }
        .upload-text {
            text-align: center;
            color: #666;
            font-size: 14px;
            pointer-events: none;
        }
        .selected-files {
            margin-top: 16px;
            padding: 12px;
            background: #f5f5f5;
            border: 1px solid #e0e0e0;
            font-size: 13px;
            color: #666;
            max-height: 120px;
            overflow-y: auto;
        }
        .selected-files div {
            padding: 4px 0;
        }
        .upload-btn {
            margin-top: 16px;
            width: 100%;
            padding: 12px;
            background: #1a1a1a;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: background 0.2s ease;
        }
        .upload-btn:hover {
            background: #333;
        }
        .upload-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .progress-section {
            padding: 24px 32px;
            display: none;
            background: #fafafa;
            border-bottom: 1px solid #e0e0e0;
        }
        .progress-bar {
            width: 100%;
            height: 2px;
            background: #e0e0e0;
        }
        .progress-fill {
            height: 100%;
            background: #1a1a1a;
            width: 0%;
            transition: width 0.3s ease;
        }
        .progress-info {
            display: flex;
            justify-content: space-between;
            margin-top: 12px;
            font-size: 13px;
            color: #666;
        }
        .files-section {
            padding: 32px;
        }
        .file-item {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 16px;
            align-items: center;
            padding: 16px 0;
            border-bottom: 1px solid #f0f0f0;
            transition: background 0.2s;
        }
        .file-item:hover {
            background: #fafafa;
            margin: 0 -32px;
            padding-left: 32px;
            padding-right: 32px;
        }
        .file-item:last-child { border-bottom: none; }
        .file-info {
            min-width: 0;
        }
        .file-name {
            font-size: 14px;
            font-weight: 500;
            color: #1a1a1a;
            margin-bottom: 4px;
            word-break: break-all;
        }
        .file-type-badge {
            display: inline-block;
            padding: 2px 8px;
            font-size: 11px;
            background: #e0e0e0;
            color: #666;
            border-radius: 3px;
            margin-left: 8px;
            text-transform: uppercase;
        }
        .file-link {
            font-size: 12px;
            color: #999;
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .file-actions {
            display: flex;
            gap: 8px;
            flex-shrink: 0;
        }
        .btn {
            padding: 6px 14px;
            border: 1px solid #d0d0d0;
            background: white;
            cursor: pointer;
            font-size: 13px;
            color: #1a1a1a;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        .btn:hover {
            background: #fafafa;
            border-color: #1a1a1a;
        }
        .btn-delete {
            color: #d32f2f;
            border-color: #d32f2f;
        }
        .btn-delete:hover {
            background: #d32f2f;
            color: white;
        }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
            font-size: 14px;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            width: 90%;
            max-width: 900px;
            max-height: 90vh;
            display: flex;
            flex-direction: column;
        }
        .modal-header {
            padding: 20px 24px;
            background: #fafafa;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h3 {
            font-size: 16px;
            font-weight: 500;
            color: #1a1a1a;
        }
        .modal-body {
            flex: 1;
            overflow: auto;
            padding: 24px;
        }
        .modal-footer {
            padding: 16px 24px;
            background: #fafafa;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 8px;
            justify-content: flex-end;
        }
        .close-btn {
            background: none;
            border: none;
            color: #666;
            font-size: 24px;
            cursor: pointer;
            padding: 0;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: color 0.2s;
        }
        .close-btn:hover { color: #1a1a1a; }
        textarea {
            width: 100%;
            min-height: 400px;
            padding: 16px;
            border: 1px solid #e0e0e0;
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
            font-size: 13px;
            resize: vertical;
            line-height: 1.6;
        }
        textarea:focus {
            border-color: #1a1a1a;
            outline: none;
        }
        pre {
            background: #fafafa;
            padding: 16px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 13px;
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
            line-height: 1.6;
            border: 1px solid #e0e0e0;
        }
        .media-viewer {
            text-align: center;
            background: #000;
            padding: 20px;
        }
        .media-viewer img {
            max-width: 100%;
            max-height: 70vh;
            object-fit: contain;
        }
        .media-viewer video,
        .media-viewer audio {
            max-width: 100%;
            outline: none;
        }
        .footer {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #fff;
            border-top: 1px solid #e0e0e0;
            padding: 12px;
            text-align: center;
            font-size: 12px;
            color: #666;
            z-index: 100;
        }
        .footer strong {
            color: #1a1a1a;
            font-weight: 500;
        }
        @media (max-width: 768px) {
            .file-item {
                grid-template-columns: 1fr;
            }
            .file-actions {
                width: 100%;
                flex-wrap: wrap;
            }
            .btn {
                flex: 1;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>` + config.SiteName + `</h1>
        </div>
        
        <div class="upload-section">
            <div class="upload-area" id="uploadArea">
                <input type="file" id="fileInput" multiple>
                <div class="upload-text">
                    <span>Drop files or click to upload (multiple files supported)</span>
                </div>
            </div>
            <div class="selected-files" id="selectedFiles" style="display: none;"></div>
            <button class="upload-btn" onclick="uploadFiles()">Upload</button>
        </div>

        <div class="progress-section" id="progressSection">
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div class="progress-info">
                <span id="progressText">0%</span>
                <span id="speedText">0 MB/s</span>
            </div>
        </div>

        <div class="files-section" id="filesSection">
            <div class="empty-state">Loading...</div>
        </div>
    </div>

    <div class="modal" id="viewModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="viewTitle">View File</h3>
                <button class="close-btn" onclick="closeModal('viewModal')">&times;</button>
            </div>
            <div class="modal-body" id="viewBody">
                <pre id="viewContent"></pre>
            </div>
        </div>
    </div>

    <div class="modal" id="editModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="editTitle">Edit File</h3>
                <button class="close-btn" onclick="closeModal('editModal')">&times;</button>
            </div>
            <div class="modal-body">
                <textarea id="editContent"></textarea>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="closeModal('editModal')">Cancel</button>
                <button class="btn" onclick="saveFile()">Save</button>
            </div>
        </div>
    </div>

    <div class="footer">
        <strong>ServerNotDie</strong> v` + VERSION + `
    </div>

    <script>
        let startTime, currentEditFile;

        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const selectedFilesDiv = document.getElementById('selectedFiles');

        fileInput.addEventListener('change', updateSelectedFiles);

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            fileInput.files = e.dataTransfer.files;
            updateSelectedFiles();
        });

        function updateSelectedFiles() {
            const files = fileInput.files;
            if (files.length === 0) {
                selectedFilesDiv.style.display = 'none';
                return;
            }
            
            let html = '<strong>Selected files (' + files.length + '):</strong><br>';
            for (let i = 0; i < files.length; i++) {
                const size = (files[i].size / 1024).toFixed(2);
                html += '<div>• ' + files[i].name + ' (' + size + ' KB)</div>';
            }
            selectedFilesDiv.innerHTML = html;
            selectedFilesDiv.style.display = 'block';
        }

        function loadFiles() {
            fetch('/files')
                .then(r => r.json())
                .then(files => {
                    const section = document.getElementById('filesSection');
                    if (files.length === 0) {
                        section.innerHTML = '<div class="empty-state">No files</div>';
                        return;
                    }
                    let html = '';
                    for (let i = 0; i < files.length; i++) {
                        const f = files[i];
                        const url = window.location.origin + '/raw/' + encodeURIComponent(f.name);
                        
                        let typeBadge = '';
                        if (f.type === 'text') typeBadge = '<span class="file-type-badge">text</span>';
                        else if (f.type === 'image') typeBadge = '<span class="file-type-badge" style="background:#e3f2fd;color:#1976d2">image</span>';
                        else if (f.type === 'video') typeBadge = '<span class="file-type-badge" style="background:#fce4ec;color:#c2185b">video</span>';
                        else if (f.type === 'audio') typeBadge = '<span class="file-type-badge" style="background:#f3e5f5;color:#7b1fa2">audio</span>';
                        
                        html += '<div class="file-item">';
                        html += '<div class="file-info">';
                        html += '<div class="file-name">' + f.name + typeBadge + '</div>';
                        html += '<div class="file-link">' + window.location.origin + '/' + encodeURIComponent(f.name) + '</div>';
                        html += '</div>';
                        html += '<div class="file-actions">';
                        
                        if (f.type === 'text') {
                            html += '<button class="btn" onclick="viewFile(\'' + f.name + '\', \'text\')">View</button>';
                            html += '<button class="btn" onclick="editFile(\'' + f.name + '\')">Edit</button>';
                        } else if (f.type === 'image') {
                            html += '<button class="btn" onclick="viewFile(\'' + f.name + '\', \'image\')">View</button>';
                        } else if (f.type === 'video') {
                            html += '<button class="btn" onclick="viewFile(\'' + f.name + '\', \'video\')">Play</button>';
                        } else if (f.type === 'audio') {
                            html += '<button class="btn" onclick="viewFile(\'' + f.name + '\', \'audio\')">Play</button>';
                        }
                        
                        html += '<button class="btn" onclick="downloadFile(\'' + f.name + '\')">Download</button>';
                        html += '<button class="btn btn-delete" onclick="deleteFile(\'' + f.name + '\')">Delete</button>';
                        html += '</div></div>';
                    }
                    section.innerHTML = html;
                });
        }

        function uploadFiles() {
            const files = fileInput.files;
            if (files.length === 0) {
                alert('Please select files');
                return;
            }

            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('files', files[i]);
            }

            const progressSection = document.getElementById('progressSection');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            const speedText = document.getElementById('speedText');
            const uploadBtn = document.querySelector('.upload-btn');

            progressSection.style.display = 'block';
            uploadBtn.disabled = true;
            startTime = Date.now();

            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percent = (e.loaded / e.total * 100).toFixed(1);
                    progressFill.style.width = percent + '%';
                    progressText.textContent = percent + '%';

                    const elapsed = (Date.now() - startTime) / 1000;
                    const speed = (e.loaded / elapsed / 1024 / 1024).toFixed(2);
                    speedText.textContent = speed + ' MB/s';
                }
            });

            xhr.addEventListener('load', function() {
                if (xhr.status === 200) {
                    alert('Upload complete - ' + files.length + ' file(s) uploaded');
                    fileInput.value = '';
                    selectedFilesDiv.style.display = 'none';
                    loadFiles();
                } else {
                    alert('Upload failed: ' + xhr.responseText);
                }
                progressSection.style.display = 'none';
                progressFill.style.width = '0%';
                uploadBtn.disabled = false;
            });

            xhr.addEventListener('error', function() {
                alert('Upload error');
                progressSection.style.display = 'none';
                uploadBtn.disabled = false;
            });

            xhr.open('POST', '/upload');
            xhr.send(formData);
        }

        function viewFile(filename, type) {
            const url = '/raw/' + encodeURIComponent(filename);
            const viewBody = document.getElementById('viewBody');
            
            document.getElementById('viewTitle').textContent = filename;
            
            if (type === 'text') {
                fetch('/view/' + encodeURIComponent(filename))
                    .then(r => r.text())
                    .then(content => {
                        viewBody.innerHTML = '<pre id="viewContent"></pre>';
                        document.getElementById('viewContent').textContent = content;
                        document.getElementById('viewModal').style.display = 'block';
                    });
            } else if (type === 'image') {
                viewBody.innerHTML = '<div class="media-viewer"><img src="' + url + '" alt="' + filename + '"></div>';
                document.getElementById('viewModal').style.display = 'block';
            } else if (type === 'video') {
                viewBody.innerHTML = '<div class="media-viewer"><video controls autoplay><source src="' + url + '">Your browser does not support video.</video></div>';
                document.getElementById('viewModal').style.display = 'block';
            } else if (type === 'audio') {
                viewBody.innerHTML = '<div class="media-viewer" style="background:#fff;"><audio controls autoplay style="width:100%;"><source src="' + url + '">Your browser does not support audio.</audio></div>';
                document.getElementById('viewModal').style.display = 'block';
            }
        }

        function editFile(filename) {
            currentEditFile = filename;
            fetch('/edit/' + encodeURIComponent(filename))
                .then(r => r.text())
                .then(content => {
                    document.getElementById('editTitle').textContent = filename;
                    document.getElementById('editContent').value = content;
                    document.getElementById('editModal').style.display = 'block';
                });
        }

        function saveFile() {
            const content = document.getElementById('editContent').value;
            fetch('/save/' + encodeURIComponent(currentEditFile), {
                method: 'POST',
                headers: {'Content-Type': 'text/plain'},
                body: content
            })
            .then(r => r.json())
            .then(data => {
                alert(data.message);
                closeModal('editModal');
                loadFiles();
            });
        }

        function downloadFile(filename) {
            window.location.href = '/download/' + encodeURIComponent(filename);
        }

        function deleteFile(filename) {
            if (confirm('Delete ' + filename + '?')) {
                fetch('/delete/' + encodeURIComponent(filename), { method: 'DELETE' })
                    .then(r => r.json())
                    .then(data => {
                        alert(data.message);
                        loadFiles();
                    });
            }
        }

        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
            // Stop any playing media
            const videos = document.querySelectorAll('video');
            const audios = document.querySelectorAll('audio');
            videos.forEach(v => v.pause());
            audios.forEach(a => a.pause());
        }

        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
                // Stop any playing media
                const videos = document.querySelectorAll('video');
                const audios = document.querySelectorAll('audio');
                videos.forEach(v => v.pause());
                audios.forEach(a => a.pause());
            }
        }

        loadFiles();
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(0)

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	uploadedCount := 0
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			if debug {
				log.Printf("Error opening file: %v", err)
			}
			continue
		}
		defer file.Close()

		dst, err := os.Create(filepath.Join(publicDir, fileHeader.Filename))
		if err != nil {
			if debug {
				log.Printf("Error creating file: %v", err)
			}
			continue
		}
		defer dst.Close()

		written, err := io.Copy(dst, file)
		if err != nil {
			if debug {
				log.Printf("Error saving file: %v", err)
			}
			continue
		}

		uploadedCount++
		if debug {
			log.Printf("Uploaded: %s (%d bytes)", fileHeader.Filename, written)
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("%d file(s) uploaded successfully", uploadedCount)))
}

func handleListFiles(w http.ResponseWriter, r *http.Request) {
	files, err := os.ReadDir(publicDir)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	type FileInfo struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}

	var fileList []FileInfo
	for _, file := range files {
		if !file.IsDir() {
			fileList = append(fileList, FileInfo{
				Name: file.Name(),
				Type: getFileType(file.Name()),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fileList)
}

func handleView(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/view/"):]
	filePath := filepath.Join(publicDir, filename)

	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(content)
}

func handleEdit(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/edit/"):]
	filePath := filepath.Join(publicDir, filename)

	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(content)
}

func handleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Path[len("/save/"):]
	filePath := filepath.Join(publicDir, filename)

	content, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading content", http.StatusInternalServerError)
		return
	}

	err = os.WriteFile(filePath, content, 0644)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	if debug {
		log.Printf("Saved: %s", filename)
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"message": "File saved successfully"}
	json.NewEncoder(w).Encode(response)
}

func handleRaw(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/raw/"):]
	filePath := filepath.Join(publicDir, filename)

	if debug {
		log.Printf("Raw access: %s", filename)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	fileType := getFileType(filename)
	
	switch fileType {
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	case "image":
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
		case ".png":
			w.Header().Set("Content-Type", "image/png")
		case ".gif":
			w.Header().Set("Content-Type", "image/gif")
		case ".webp":
			w.Header().Set("Content-Type", "image/webp")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		default:
			w.Header().Set("Content-Type", "image/jpeg")
		}
	case "video":
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".mp4":
			w.Header().Set("Content-Type", "video/mp4")
		case ".webm":
			w.Header().Set("Content-Type", "video/webm")
		case ".ogg":
			w.Header().Set("Content-Type", "video/ogg")
		default:
			w.Header().Set("Content-Type", "video/mp4")
		}
	case "audio":
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".mp3":
			w.Header().Set("Content-Type", "audio/mpeg")
		case ".wav":
			w.Header().Set("Content-Type", "audio/wav")
		case ".ogg":
			w.Header().Set("Content-Type", "audio/ogg")
		case ".m4a":
			w.Header().Set("Content-Type", "audio/mp4")
		default:
			w.Header().Set("Content-Type", "audio/mpeg")
		}
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	
	w.Write(content)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/download/"):]
	filePath := filepath.Join(publicDir, filename)

	if debug {
		log.Printf("Download: %s", filename)
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	http.ServeFile(w, r, filePath)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Path[len("/delete/"):]
	filePath := filepath.Join(publicDir, filename)

	err := os.Remove(filePath)
	if err != nil {
		if debug {
			log.Printf("Error deleting file: %v", err)
		}
		http.Error(w, "Error deleting file", http.StatusInternalServerError)
		return
	}

	if debug {
		log.Printf("Deleted: %s", filename)
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"message": "File deleted successfully"}
	json.NewEncoder(w).Encode(response)
}