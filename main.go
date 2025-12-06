package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const VERSION = "1.3 archive"

type Config struct {
	IP       string `yaml:"ip"`
	Port     string `yaml:"port"`
	SiteName string `yaml:"site_name"`
	IconURL  string `yaml:"icon_url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type FileMetadata struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	DownloadCount int      `json:"download_count"`
}

var (
	debug      bool
	publicDir  = "public"
	configFile = "config.yml"
	config     Config
	sessions   = make(map[string]time.Time)
	sessionMu  sync.RWMutex
	downloadCounts = make(map[string]int)
	downloadMu     sync.RWMutex
)

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.Parse()

	if err := os.MkdirAll(publicDir, 0755); err != nil {
		log.Fatalf("Failed to create public directory: %v", err)
	}

	config = loadConfig()
	loadDownloadCounts()
	updateStats()

	http.HandleFunc("/ac", handleLogin)
	http.HandleFunc("/login", handleLoginSubmit)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/ad", requireAuth(handleAdmin))
	http.HandleFunc("/upload", requireAuth(handleUpload))
	http.HandleFunc("/files", handleListFiles)
	http.HandleFunc("/view/", handleView)
	http.HandleFunc("/edit/", requireAuth(handleEdit))
	http.HandleFunc("/save/", requireAuth(handleSave))
	http.HandleFunc("/raw/", handleRaw)
	http.HandleFunc("/download/", handleDownload)
	http.HandleFunc("/delete/", requireAuth(handleDelete))
	http.HandleFunc("/rename/", requireAuth(handleRename))
	http.HandleFunc("/duplicate/", requireAuth(handleDuplicate))
	http.HandleFunc("/zip-multiple", requireAuth(handleZipMultiple))
	http.HandleFunc("/zip-view/", handleZipView)
	http.HandleFunc("/", handleIndex)

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
		SiteName: "servernotdie",
		IconURL:  "https://cdn-icons-png.flaticon.com/512/716/716784.png",
		Username: "admin",
		Password: "admin",
	}

	data, err := os.ReadFile(configFile)
	if err == nil {
		yaml.Unmarshal(data, &cfg)
	} else {
		data, _ := yaml.Marshal(cfg)
		os.WriteFile(configFile, data, 0644)
		fmt.Printf("Created default config file: %s\n", configFile)
		fmt.Printf("Default username: admin, password: admin\n")
	}

	return cfg
}

func loadDownloadCounts() {
	data, err := os.ReadFile("download_counts.json")
	if err == nil {
		json.Unmarshal(data, &downloadCounts)
	}
}

func saveDownloadCounts() {
	downloadMu.RLock()
	data, _ := json.Marshal(downloadCounts)
	downloadMu.RUnlock()
	os.WriteFile("download_counts.json", data, 0644)
}

func getFileType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))

	textExts := []string{".txt", ".log", ".md", ".json", ".xml", ".html", ".css", ".js", ".yml", ".yaml", ".conf", ".cfg", ".sh", ".bat", ".py", ".go", ".java", ".c", ".cpp", ".h", ".php", ".rb", ".rs", ".sql"}
	for _, e := range textExts {
		if ext == e {
			return "text"
		}
	}

	imageExts := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico"}
	for _, e := range imageExts {
		if ext == e {
			return "image"
		}
	}

	videoExts := []string{".mp4", ".webm", ".ogg", ".mov", ".avi", ".mkv", ".flv", ".wmv"}
	for _, e := range videoExts {
		if ext == e {
			return "video"
		}
	}

	audioExts := []string{".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".wma"}
	for _, e := range audioExts {
		if ext == e {
			return "audio"
		}
	}

	if ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".tar" || ext == ".gz" {
		return "archive"
	}

	return "binary"
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            min-height: 100vh; 
            background: #fafafa;
            font-family: -apple-system, sans-serif;
        }
        .login-box {
            background: white;
            padding: 40px;
            border: 1px solid #e0e0e0;
            width: 400px;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 1px solid #d0d0d0;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #1a1a1a;
            color: white;
            border: none;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Login</h2>
        <form onsubmit="login(event)">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        function login(e) {
            e.preventDefault();
            fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    window.location.href = '/';
                } else {
                    alert(data.message);
                }
            });
        }
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	if creds.Username == config.Username && creds.Password == config.Password {
		sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

		sessionMu.Lock()
		sessions[sessionID] = time.Now().Add(24 * time.Hour)
		sessionMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sessionID,
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
		})

		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid credentials",
		})
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/ac", http.StatusSeeOther)
			return
		}

		sessionMu.RLock()
		expiry, exists := sessions[cookie.Value]
		sessionMu.RUnlock()

		if !exists || time.Now().After(expiry) {
			http.Redirect(w, r, "/ac", http.StatusSeeOther)
			return
		}

		handler(w, r)
	}
}

type Stats struct {
	TotalFiles    int64
	TotalSize     int64
	TotalRequests int64
	mu            sync.RWMutex
}

var stats Stats

func updateStats() {
	files, _ := os.ReadDir(publicDir)
	var size int64
	var count int64

	for _, f := range files {
		if !f.IsDir() {
			info, _ := f.Info()
			size += info.Size()
			count++
		}
	}

	stats.mu.Lock()
	stats.TotalFiles = count
	stats.TotalSize = size
	stats.mu.Unlock()
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	updateStats()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats.mu.RLock()
	totalFiles := stats.TotalFiles
	totalSize := stats.TotalSize
	totalRequests := stats.TotalRequests
	stats.mu.RUnlock()

	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - ` + config.SiteName + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #fafafa;
            color: #1a1a1a;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #e0e0e0;
        }
        h1 {
            font-size: 24px;
            font-weight: 500;
        }
        .header-actions {
            display: flex;
            gap: 8px;
        }
        .btn {
            padding: 8px 16px;
            background: #1a1a1a;
            color: white;
            text-decoration: none;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }
        .btn:hover {
            background: #333;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: white;
            padding: 24px;
            border: 1px solid #e0e0e0;
        }
        .stat-label {
            font-size: 13px;
            color: #666;
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 32px;
            font-weight: 500;
            color: #1a1a1a;
        }
        .system-info {
            background: white;
            padding: 24px;
            border: 1px solid #e0e0e0;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        .info-row:last-child {
            border-bottom: none;
        }
        .info-label {
            font-size: 14px;
            color: #666;
        }
        .info-value {
            font-size: 14px;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Admin Dashboard</h1>
            <div class="header-actions">
                <a href="/" class="btn">Home</a>
                <a href="/logout" class="btn">Logout</a>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Files</div>
                <div class="stat-value">` + fmt.Sprintf("%d", totalFiles) + `</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Storage Used</div>
                <div class="stat-value">` + formatBytes(totalSize) + `</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value">` + fmt.Sprintf("%d", totalRequests) + `</div>
            </div>
        </div>

        <div class="system-info">
            <h2 style="font-size: 18px; font-weight: 500; margin-bottom: 16px;">System Information</h2>
            <div class="info-row">
                <div class="info-label">Operating System</div>
                <div class="info-value">` + runtime.GOOS + `</div>
            </div>
            <div class="info-row">
                <div class="info-label">CPU Cores</div>
                <div class="info-value">` + fmt.Sprintf("%d", runtime.NumCPU()) + `</div>
            </div>
            <div class="info-row">
                <div class="info-label">Memory Allocated</div>
                <div class="info-value">` + formatBytes(int64(m.Alloc)) + `</div>
            </div>
            <div class="info-row">
                <div class="info-label">Go Version</div>
                <div class="info-value">` + runtime.Version() + `</div>
            </div>
        </div>
    </div>

    <script>
        setInterval(() => {
            location.reload();
        }, 10000);
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	isAuth := false
	cookie, err := r.Cookie("session")
	if err == nil {
		sessionMu.RLock()
		expiry, exists := sessions[cookie.Value]
		sessionMu.RUnlock()
		if exists && time.Now().Before(expiry) {
			isAuth = true
		}
	}

	authStatus := "false"
	authButtons := `<a href="/ac" class="btn">Login</a>`
	uploadSectionDisplay := "none"

	if isAuth {
		authStatus = "true"
		authButtons = `<a href="/ad" class="btn">Admin</a>
                       <a href="#" onclick="logout()" class="btn">Logout</a>`
		uploadSectionDisplay = "block"
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes">
    <title>` + config.SiteName + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
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
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        .header h1 {
            font-size: 20px;
            font-weight: 500;
            color: #1a1a1a;
        }
        .header-actions {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        .keyboard-hint {
            font-size: 11px;
            color: #999;
            white-space: nowrap;
        }
        .btn {
            padding: 8px 16px;
            background: #1a1a1a;
            color: white;
            text-decoration: none;
            border: none;
            cursor: pointer;
            font-size: 13px;
            display: inline-block;
            white-space: nowrap;
        }
        .btn:hover { background: #333; }
        
        /* Search Box */
        .search-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 9999;
            align-items: flex-start;
            justify-content: center;
            padding: 20px;
            overflow-y: auto;
        }
        .search-box {
            background: white;
            padding: 24px;
            width: 100%;
            max-width: 600px;
            border-radius: 8px;
            margin-top: 60px;
        }
        .search-input {
            width: 100%;
            padding: 14px;
            font-size: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 4px;
            margin-bottom: 16px;
        }
        .search-input:focus {
            outline: none;
            border-color: #1a1a1a;
        }
        .search-results {
            max-height: 400px;
            overflow-y: auto;
        }
        .search-item {
            padding: 12px;
            border-bottom: 1px solid #f0f0f0;
            cursor: pointer;
            transition: background 0.2s;
        }
        .search-item:hover {
            background: #fafafa;
        }
        .search-hint {
            font-size: 12px;
            color: #666;
            margin-top: 8px;
            text-align: center;
        }
        
        .upload-section {
            padding: 24px 20px;
            border-bottom: 1px solid #e0e0e0;
            display: ` + uploadSectionDisplay + `;
        }
        .upload-area {
            position: relative;
            width: 100%;
            min-height: 120px;
            border: 2px dashed #d0d0d0;
            background: #fafafa;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
            cursor: pointer;
            border-radius: 4px;
        }
        .upload-area.dragover {
            border-color: #1a1a1a;
            background: #f0f0f0;
        }
        .upload-area:hover { border-color: #1a1a1a; }
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
            padding: 0 16px;
        }
        .selected-files {
            margin-top: 16px;
            padding: 12px;
            background: #f5f5f5;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            font-size: 13px;
            color: #666;
            max-height: 120px;
            overflow-y: auto;
        }
        .selected-files div { padding: 4px 0; }
        .upload-btn {
            margin-top: 16px;
            width: 100%;
            padding: 12px;
            background: #1a1a1a;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }
        .upload-btn:hover { background: #333; }
        .upload-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .progress-section {
            padding: 20px;
            display: none;
            background: #fafafa;
            border-bottom: 1px solid #e0e0e0;
        }
        .progress-bar {
            width: 100%;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            overflow: hidden;
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
        
        /* Bulk select mode */
        .bulk-actions {
            display: none;
            padding: 16px 20px;
            background: #f5f5f5;
            border-bottom: 1px solid #e0e0e0;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        .bulk-actions.active {
            display: flex;
        }
        .checkbox {
            width: 18px;
            height: 18px;
            cursor: pointer;
            flex-shrink: 0;
        }
        
        .files-section {
            padding: 20px;
        }
        .file-item {
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: 12px;
            align-items: center;
            padding: 16px 12px;
            border-bottom: 1px solid #f0f0f0;
            transition: background 0.2s;
        }
        .file-item:hover {
            background: #fafafa;
        }
        .file-info {
            min-width: 0;
        }
        .file-name {
            font-size: 14px;
            font-weight: 500;
            color: #1a1a1a;
            margin-bottom: 4px;
            word-break: break-word;
        }
        .file-type-badge {
            display: inline-block;
            padding: 2px 8px;
            font-size: 10px;
            background: #e0e0e0;
            color: #666;
            border-radius: 3px;
            margin-left: 6px;
            text-transform: uppercase;
        }
        .file-meta {
            font-size: 11px;
            color: #999;
            margin-top: 4px;
        }
        .file-link {
            font-size: 11px;
            color: #0066cc;
            margin-top: 4px;
            font-family: 'SF Mono', Monaco, monospace;
            word-break: break-all;
            cursor: pointer;
        }
        .file-link:hover {
            text-decoration: underline;
        }
        .file-actions {
            display: flex;
            gap: 8px;
            flex-shrink: 0;
            position: relative;
        }
        
        /* Context Menu */
        .menu-btn {
            padding: 6px 12px;
            background: white;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            line-height: 1;
            min-width: 36px;
            height: 36px;
        }
        .menu-btn:hover {
            background: #fafafa;
            border-color: #1a1a1a;
        }
        .context-menu {
            display: none;
            position: absolute;
            top: 100%;
            right: 0;
            background: white;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            min-width: 180px;
            z-index: 1000;
            margin-top: 4px;
        }
        .context-menu.show {
            display: block;
        }
        .context-menu-item {
            padding: 12px 16px;
            cursor: pointer;
            font-size: 13px;
            border-bottom: 1px solid #f0f0f0;
        }
        .context-menu-item:last-child {
            border-bottom: none;
        }
        .context-menu-item:hover {
            background: #fafafa;
        }
        .context-menu-item.danger {
            color: #d32f2f;
        }
        .context-menu-item.danger:hover {
            background: #ffebee;
        }
        
        .btn-small {
            padding: 8px 14px;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            background: white;
            cursor: pointer;
            font-size: 13px;
            color: #1a1a1a;
            white-space: nowrap;
        }
        .btn-small:hover {
            background: #fafafa;
            border-color: #1a1a1a;
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
            overflow-y: auto;
        }
        .modal-content {
            position: relative;
            margin: 40px auto;
            background: white;
            width: 90%;
            max-width: 900px;
            max-height: calc(100vh - 80px);
            display: flex;
            flex-direction: column;
            border-radius: 8px;
        }
        .modal-header {
            padding: 20px 24px;
            background: #fafafa;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-radius: 8px 8px 0 0;
        }
        .modal-header h3 {
            font-size: 16px;
            font-weight: 500;
            word-break: break-word;
            padding-right: 16px;
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
            border-radius: 0 0 8px 8px;
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
            flex-shrink: 0;
        }
        .close-btn:hover { color: #1a1a1a; }
        
        textarea {
            width: 100%;
            min-height: 300px;
            padding: 16px;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            font-family: 'SF Mono', Monaco, monospace;
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
            font-family: 'SF Mono', Monaco, monospace;
            line-height: 1.6;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
        }
        
        /* Image Viewer - Fixed Zoom */
        .media-viewer {
            text-align: center;
            background: #000;
            padding: 0;
            position: relative;
            min-height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: auto;
            border-radius: 4px;
            cursor: default;
        }
        .media-viewer-inner {
            position: relative;
            display: inline-block;
            transition: transform 0.3s ease;
            transform-origin: center center;
        }
        .media-viewer img {
            max-width: 100%;
            max-height: 60vh;
            object-fit: contain;
            cursor: zoom-in;
            display: block;
            user-select: none;
            -webkit-user-drag: none;
        }
        .media-viewer.zoomed {
            cursor: grab;
            justify-content: flex-start;
            align-items: flex-start;
        }
        .media-viewer.zoomed:active {
            cursor: grabbing;
        }
        .media-viewer.zoomed img {
            cursor: zoom-out;
            max-width: none;
            max-height: none;
        }
        .media-viewer video,
        .media-viewer audio {
            max-width: 100%;
            outline: none;
        }
        .zoom-controls {
            position: absolute;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 10px 20px;
            border-radius: 20px;
            font-size: 12px;
            pointer-events: none;
            z-index: 10;
            white-space: nowrap;
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
        
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 24px;
            background: #1a1a1a;
            color: white;
            border-radius: 4px;
            font-size: 14px;
            z-index: 2000;
            animation: slideIn 0.3s ease;
            max-width: 90%;
            word-break: break-word;
        }
        .toast.success { background: #2e7d32; }
        .toast.error { background: #d32f2f; }
        
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .zip-entry {
            padding: 8px 12px;
            border-bottom: 1px solid #f0f0f0;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 12px;
        }
        .zip-entry:last-child {
            border-bottom: none;
        }
        
        @media (max-width: 768px) {
            .header {
                padding: 12px 16px;
            }
            .keyboard-hint {
                display: none;
            }
            .upload-section, .files-section, .bulk-actions, .progress-section {
                padding: 16px;
            }
            .file-item {
                grid-template-columns: auto 1fr;
                gap: 10px;
            }
            .file-actions {
                grid-column: 2;
                width: 100%;
                justify-content: flex-end;
            }
            .modal-content {
                width: 95%;
                margin: 20px auto;
                max-height: calc(100vh - 40px);
            }
            .modal-body {
                padding: 16px;
            }
            .media-viewer img {
                max-height: 50vh;
            }
            textarea {
                min-height: 250px;
            }
            .search-box {
                margin-top: 20px;
            }
        }
        
        @media (max-width: 480px) {
            .header h1 {
                font-size: 18px;
            }
            .btn, .btn-small {
                font-size: 12px;
                padding: 6px 12px;
            }
            .file-name {
                font-size: 13px;
            }
            .upload-text {
                font-size: 13px;
            }
        }
    </style>
</head>
<body>
    <!-- Search Overlay (Ctrl+F) -->
    <div class="search-overlay" id="searchOverlay">
        <div class="search-box">
            <input type="text" class="search-input" id="searchInput" placeholder="Search files..." autocomplete="off">
            <div class="search-results" id="searchResults"></div>
            <div class="search-hint">Press ESC to close, ↑↓ to navigate, Enter to open</div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>` + config.SiteName + `</h1>
            <div class="header-actions">
                <span class="keyboard-hint">Ctrl+F: Search | Ctrl+A: Select All</span>
                ` + authButtons + `
            </div>
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

        <!-- Bulk Actions -->
        <div class="bulk-actions" id="bulkActions">
            <span id="selectedCount" style="font-size: 14px; color: #666;">0 selected</span>
            <button class="btn-small" onclick="downloadSelectedAsZip()">Download as ZIP</button>
            <button class="btn-small" onclick="deselectAll()">Deselect All</button>
        </div>

        <div class="files-section" id="filesSection">
            <div class="empty-state">Loading...</div>
        </div>
    </div>

    <!-- Modals -->
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
                <button class="btn-small" onclick="closeModal('editModal')">Cancel</button>
                <button class="btn-small" onclick="saveFile()">Save</button>
            </div>
        </div>
    </div>

    <div class="modal" id="renameModal">
        <div class="modal-content" style="max-width: 500px;">
            <div class="modal-header">
                <h3>Rename File</h3>
                <button class="close-btn" onclick="closeModal('renameModal')">&times;</button>
            </div>
            <div class="modal-body">
                <input type="text" id="renameInput" style="width: 100%; padding: 12px; border: 1px solid #e0e0e0; font-size: 14px; border-radius: 4px;">
            </div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('renameModal')">Cancel</button>
                <button class="btn-small" onclick="confirmRename()">Rename</button>
            </div>
        </div>
    </div>

    <div class="footer">
        <strong>ServerNotDie</strong> v` + VERSION + `
    </div>

    <script>
        const isAuthenticated = ` + authStatus + `;
        let startTime, currentEditFile, currentRenameFile;
        let allFiles = [];
        let selectedFiles = new Set();
        let bulkMode = false;

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                showSearch();
            }
            if (e.key === 'Escape') {
                const searchOverlay = document.getElementById('searchOverlay');
                if (searchOverlay.style.display === 'flex') {
                    searchOverlay.style.display = 'none';
                }
            }
            if (e.ctrlKey && e.key === 'a') {
                e.preventDefault();
                selectAllFiles();
            }
        });

        function showSearch() {
            document.getElementById('searchOverlay').style.display = 'flex';
            document.getElementById('searchInput').focus();
        }

        document.getElementById('searchInput').addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            const results = document.getElementById('searchResults');
            
            if (query.length === 0) {
                results.innerHTML = '';
                return;
            }
            
            const filtered = allFiles.filter(f => 
                f.name.toLowerCase().includes(query)
            );
            
            if (filtered.length === 0) {
                results.innerHTML = '<div class="search-item">No files found</div>';
                return;
            }
            
            let html = '';
            filtered.forEach(f => {
                html += '<div class="search-item" onclick="openFile(\'' + f.name.replace(/'/g, "\\'") + '\', \'' + f.type + '\')">';
                html += '<strong>' + escapeHtml(f.name) + '</strong>';
                html += '<div style="font-size: 11px; color: #999; margin-top: 4px;">' + formatFileSize(f.size) + ' • ' + f.type + '</div>';
                html += '</div>';
            });
            results.innerHTML = html;
        });

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function openFile(name, type) {
            document.getElementById('searchOverlay').style.display = 'none';
            document.getElementById('searchInput').value = '';
            document.getElementById('searchResults').innerHTML = '';
            viewFile(name, type);
        }

        function selectAllFiles() {
            if (!bulkMode) {
                bulkMode = true;
                document.getElementById('bulkActions').classList.add('active');
            }
            
            selectedFiles.clear();
            allFiles.forEach(f => selectedFiles.add(f.name));
            
            document.querySelectorAll('.file-checkbox').forEach(cb => {
                cb.checked = true;
            });
            
            updateBulkCount();
        }

        function deselectAll() {
            selectedFiles.clear();
            document.querySelectorAll('.file-checkbox').forEach(cb => {
                cb.checked = false;
            });
            bulkMode = false;
            document.getElementById('bulkActions').classList.remove('active');
        }

        function toggleFileSelect(filename, checkbox) {
            if (checkbox.checked) {
                selectedFiles.add(filename);
                if (!bulkMode) {
                    bulkMode = true;
                    document.getElementById('bulkActions').classList.add('active');
                }
            } else {
                selectedFiles.delete(filename);
                if (selectedFiles.size === 0) {
                    bulkMode = false;
                    document.getElementById('bulkActions').classList.remove('active');
                }
            }
            updateBulkCount();
        }

        function updateBulkCount() {
            document.getElementById('selectedCount').textContent = selectedFiles.size + ' selected';
        }

        function downloadSelectedAsZip() {
            if (selectedFiles.size === 0) return;
            
            const files = Array.from(selectedFiles);
            fetch('/zip-multiple', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({files: files})
            })
            .then(r => r.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'files_' + Date.now() + '.zip';
                a.click();
                showToast('Downloaded ' + files.length + ' files as ZIP', 'success');
            })
            .catch(() => {
                showToast('Failed to create ZIP', 'error');
            });
        }

        function toggleContextMenu(e, filename) {
            e.stopPropagation();
            
            document.querySelectorAll('.context-menu').forEach(m => {
                if (m.id !== 'menu-' + filename) {
                    m.classList.remove('show');
                }
            });
            
            const menu = document.getElementById('menu-' + filename);
            menu.classList.toggle('show');
        }

        document.addEventListener('click', function() {
            document.querySelectorAll('.context-menu').forEach(m => {
                m.classList.remove('show');
            });
        });

        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const selectedFilesDiv = document.getElementById('selectedFiles');

        if (isAuthenticated) {
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
        }

        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        function logout() {
            fetch('/logout')
                .then(() => {
                    showToast('Logged out successfully', 'success');
                    setTimeout(() => window.location.reload(), 1000);
                });
        }

        function updateSelectedFiles() {
            const files = fileInput.files;
            if (files.length === 0) {
                selectedFilesDiv.style.display = 'none';
                return;
            }
            
            let html = '<strong>Selected files (' + files.length + '):</strong><br>';
            for (let i = 0; i < files.length; i++) {
                const size = (files[i].size / 1024).toFixed(2);
                html += '<div>• ' + escapeHtml(files[i].name) + ' (' + size + ' KB)</div>';
            }
            selectedFilesDiv.innerHTML = html;
            selectedFilesDiv.style.display = 'block';
        }

        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
            if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
            return (bytes / 1073741824).toFixed(2) + ' GB';
        }

        function copyLink(filename) {
            const url = window.location.origin + '/raw/' + encodeURIComponent(filename);
            navigator.clipboard.writeText(url).then(() => {
                showToast('Link copied to clipboard', 'success');
            }).catch(() => {
                showToast('Failed to copy link', 'error');
            });
        }

        function loadFiles() {
            fetch('/files')
                .then(r => r.json())
                .then(files => {
                    allFiles = files;
                    const section = document.getElementById('filesSection');
                    if (files.length === 0) {
                        section.innerHTML = '<div class="empty-state">No files uploaded yet</div>';
                        return;
                    }
                    
                    let html = '';
                    files.forEach(f => {
                        const rawUrl = window.location.origin + '/raw/' + encodeURIComponent(f.name);
                        const escapedName = f.name.replace(/'/g, "\\'");
                        
                        let typeBadge = '';
                        let badgeStyle = '';
                        if (f.type === 'text') {
                            typeBadge = 'text';
                        } else if (f.type === 'image') {
                            typeBadge = 'image';
                            badgeStyle = 'background:#e3f2fd;color:#1976d2';
                        } else if (f.type === 'video') {
                            typeBadge = 'video';
                            badgeStyle = 'background:#fce4ec;color:#c2185b';
                        } else if (f.type === 'audio') {
                            typeBadge = 'audio';
                            badgeStyle = 'background:#f3e5f5;color:#7b1fa2';
                        } else if (f.type === 'archive') {
                            typeBadge = 'zip';
                            badgeStyle = 'background:#fff3e0;color:#f57c00';
                        }
                        
                        const modDate = new Date(f.mod_time).toLocaleDateString();
                        
                        html += '<div class="file-item">';
                        html += '<input type="checkbox" class="checkbox file-checkbox" onchange="toggleFileSelect(\'' + escapedName + '\', this)">';
                        html += '<div class="file-info">';
                        html += '<div class="file-name">' + escapeHtml(f.name);
                        html += '<span class="file-type-badge" style="' + badgeStyle + '">' + typeBadge + '</span>';
                        html += '</div>';
                        html += '<div class="file-meta">' + formatFileSize(f.size) + ' • ' + modDate;
                        if (f.download_count > 0) {
                            html += ' • ' + f.download_count + ' downloads';
                        }
                        html += '</div>';
                        html += '<div class="file-link" onclick="copyLink(\'' + escapedName + '\')" title="Click to copy">' + escapeHtml(rawUrl) + '</div>';
                        html += '</div>';
                        
                        html += '<div class="file-actions">';
                        html += '<button class="menu-btn" onclick="toggleContextMenu(event, \'' + escapedName + '\')">⋮</button>';
                        
                        html += '<div class="context-menu" id="menu-' + escapedName + '">';
                        
                        if (f.type === 'text') {
                            html += '<div class="context-menu-item" onclick="viewFile(\'' + escapedName + '\', \'text\')">View</div>';
                            if (isAuthenticated) {
                                html += '<div class="context-menu-item" onclick="editFile(\'' + escapedName + '\')">Edit</div>';
                            }
                        } else if (f.type === 'image') {
                            html += '<div class="context-menu-item" onclick="viewFile(\'' + escapedName + '\', \'image\')">View</div>';
                        } else if (f.type === 'video') {
                            html += '<div class="context-menu-item" onclick="viewFile(\'' + escapedName + '\', \'video\')">Play</div>';
                        } else if (f.type === 'audio') {
                            html += '<div class="context-menu-item" onclick="viewFile(\'' + escapedName + '\', \'audio\')">Play</div>';
                        } else if (f.type === 'archive') {
                            html += '<div class="context-menu-item" onclick="viewZipContents(\'' + escapedName + '\')">View contents</div>';
                        }
                        
                        html += '<div class="context-menu-item" onclick="downloadFile(\'' + escapedName + '\')">Download</div>';
                        html += '<div class="context-menu-item" onclick="copyLink(\'' + escapedName + '\')">Copy link</div>';
                        html += '<div class="context-menu-item" onclick="downloadAsZip(\'' + escapedName + '\')">Download as ZIP</div>';
                        
                        if (isAuthenticated) {
                            html += '<div class="context-menu-item" onclick="renameFile(\'' + escapedName + '\')">Rename</div>';
                            html += '<div class="context-menu-item" onclick="duplicateFile(\'' + escapedName + '\')">Duplicate</div>';
                            html += '<div class="context-menu-item danger" onclick="deleteFile(\'' + escapedName + '\')">Delete</div>';
                        }
                        
                        html += '</div>';
                        html += '</div>';
                        html += '</div>';
                    });
                    
                    section.innerHTML = html;
                })
                .catch(() => {
                    document.getElementById('filesSection').innerHTML = '<div class="empty-state">Error loading files</div>';
                });
        }

        function downloadAsZip(filename) {
            fetch('/zip-multiple', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({files: [filename]})
            })
            .then(r => r.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename + '.zip';
                a.click();
                showToast('Downloaded as ZIP', 'success');
            });
        }

        function viewZipContents(filename) {
            fetch('/zip-view/' + encodeURIComponent(filename))
                .then(r => r.json())
                .then(data => {
                    const viewBody = document.getElementById('viewBody');
                    document.getElementById('viewTitle').textContent = filename + ' (ZIP Contents)';
                    
                    let html = '<div style="font-family: monospace; font-size: 12px;">';
                    html += '<div style="margin-bottom: 16px; padding: 12px; background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 4px;">';
                    html += '<strong>Total files:</strong> ' + data.files.length + '<br>';
                    html += '<strong>Total size:</strong> ' + formatFileSize(data.total_size);
                    html += '</div>';
                    
                    data.files.forEach(f => {
                        html += '<div class="zip-entry">';
                        html += '<strong>' + escapeHtml(f.name) + '</strong>';
                        html += '<span style="color: #999; margin-left: 16px;">' + formatFileSize(f.size) + '</span>';
                        html += '</div>';
                    });
                    html += '</div>';
                    
                    viewBody.innerHTML = html;
                    document.getElementById('viewModal').style.display = 'block';
                })
                .catch(() => {
                    showToast('Failed to read ZIP file', 'error');
                });
        }

        function renameFile(filename) {
            currentRenameFile = filename;
            document.getElementById('renameInput').value = filename;
            document.getElementById('renameModal').style.display = 'block';
            document.getElementById('renameInput').select();
        }

        function confirmRename() {
            const newName = document.getElementById('renameInput').value.trim();
            if (!newName) {
                showToast('Please enter a name', 'error');
                return;
            }
            
            fetch('/rename/' + encodeURIComponent(currentRenameFile), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({new_name: newName})
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, 'success');
                closeModal('renameModal');
                loadFiles();
            })
            .catch(() => {
                showToast('Failed to rename file', 'error');
            });
        }

        function duplicateFile(filename) {
            fetch('/duplicate/' + encodeURIComponent(filename), {
                method: 'POST'
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, 'success');
                loadFiles();
            })
            .catch(() => {
                showToast('Failed to duplicate file', 'error');
            });
        }

        function uploadFiles() {
            if (!isAuthenticated) {
                showToast('Please login to upload files', 'error');
                return;
            }

            const files = fileInput.files;
            if (files.length === 0) {
                showToast('Please select files', 'error');
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
                    showToast('Upload complete - ' + files.length + ' file(s)', 'success');
                    fileInput.value = '';
                    selectedFilesDiv.style.display = 'none';
                    loadFiles();
                } else {
                    showToast('Upload failed', 'error');
                }
                progressSection.style.display = 'none';
                progressFill.style.width = '0%';
                uploadBtn.disabled = false;
            });

            xhr.addEventListener('error', function() {
                showToast('Upload error', 'error');
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
                viewBody.innerHTML = '<div class="media-viewer" id="imageViewer"><div class="media-viewer-inner" id="imageInner"><img src="' + url + '" alt="' + escapeHtml(filename) + '" id="zoomableImage"></div><div class="zoom-controls" id="zoomHint">Click to zoom in • Scroll to zoom</div></div>';
                document.getElementById('viewModal').style.display = 'block';
                setupImageZoom();
            } else if (type === 'video') {
                viewBody.innerHTML = '<div class="media-viewer"><video controls autoplay><source src="' + url + '"></video></div>';
                document.getElementById('viewModal').style.display = 'block';
            } else if (type === 'audio') {
                viewBody.innerHTML = '<div class="media-viewer" style="background:#fff;"><audio controls autoplay style="width:100%;"><source src="' + url + '"></audio></div>';
                document.getElementById('viewModal').style.display = 'block';
            }
        }

        function setupImageZoom() {
            const viewer = document.getElementById('imageViewer');
            const inner = document.getElementById('imageInner');
            const img = document.getElementById('zoomableImage');
            const hint = document.getElementById('zoomHint');
            
            if (!viewer || !img || !inner) return;
            
            let scale = 1;
            let panning = false;
            let pointX = 0;
            let pointY = 0;
            let startX = 0;
            let startY = 0;
            
            // Set transform
            function setTransform() {
                inner.style.transform = 'translate(' + pointX + 'px, ' + pointY + 'px) scale(' + scale + ')';
            }
            
            // Click to zoom toggle
            img.addEventListener('click', function(e) {
                e.stopPropagation();
                
                if (scale === 1) {
                    // Zoom in to 2x
                    scale = 2;
                    viewer.classList.add('zoomed');
                    hint.textContent = 'Drag to pan • Click to zoom out • Scroll to adjust';
                } else {
                    // Reset zoom
                    scale = 1;
                    pointX = 0;
                    pointY = 0;
                    viewer.classList.remove('zoomed');
                    hint.textContent = 'Click to zoom in • Scroll to zoom';
                }
                setTransform();
            });
            
            // Mouse wheel zoom
            viewer.addEventListener('wheel', function(e) {
                e.preventDefault();
                
                const xs = (e.clientX - pointX) / scale;
                const ys = (e.clientY - pointY) / scale;
                const delta = e.deltaY > 0 ? -0.2 : 0.2;
                
                scale += delta;
                scale = Math.min(Math.max(0.5, scale), 5);
                
                pointX = e.clientX - xs * scale;
                pointY = e.clientY - ys * scale;
                
                if (scale > 1) {
                    viewer.classList.add('zoomed');
                    hint.textContent = 'Drag to pan • Click to zoom out • Scroll to adjust';
                } else {
                    scale = 1;
                    pointX = 0;
                    pointY = 0;
                    viewer.classList.remove('zoomed');
                    hint.textContent = 'Click to zoom in • Scroll to zoom';
                }
                
                setTransform();
            }, { passive: false });
            
            // Mouse drag to pan
            viewer.addEventListener('mousedown', function(e) {
                if (scale <= 1) return;
                e.preventDefault();
                startX = e.clientX - pointX;
                startY = e.clientY - pointY;
                panning = true;
            });
            
            viewer.addEventListener('mousemove', function(e) {
                if (!panning) return;
                e.preventDefault();
                pointX = e.clientX - startX;
                pointY = e.clientY - startY;
                setTransform();
            });
            
            viewer.addEventListener('mouseup', function() {
                panning = false;
            });
            
            viewer.addEventListener('mouseleave', function() {
                panning = false;
            });
            
            // Touch support
            let initialDistance = 0;
            let initialScale = 1;
            
            viewer.addEventListener('touchstart', function(e) {
                if (e.touches.length === 2) {
                    e.preventDefault();
                    initialDistance = Math.hypot(
                        e.touches[0].pageX - e.touches[1].pageX,
                        e.touches[0].pageY - e.touches[1].pageY
                    );
                    initialScale = scale;
                } else if (e.touches.length === 1 && scale > 1) {
                    const touch = e.touches[0];
                    startX = touch.clientX - pointX;
                    startY = touch.clientY - pointY;
                    panning = true;
                }
            }, { passive: false });
            
            viewer.addEventListener('touchmove', function(e) {
                if (e.touches.length === 2) {
                    e.preventDefault();
                    const distance = Math.hypot(
                        e.touches[0].pageX - e.touches[1].pageX,
                        e.touches[0].pageY - e.touches[1].pageY
                    );
                    scale = initialScale * (distance / initialDistance);
                    scale = Math.min(Math.max(0.5, scale), 5);
                    
                    if (scale > 1) {
                        viewer.classList.add('zoomed');
                    } else {
                        scale = 1;
                        pointX = 0;
                        pointY = 0;
                        viewer.classList.remove('zoomed');
                    }
                    setTransform();
                } else if (e.touches.length === 1 && panning) {
                    e.preventDefault();
                    const touch = e.touches[0];
                    pointX = touch.clientX - startX;
                    pointY = touch.clientY - startY;
                    setTransform();
                }
            }, { passive: false });
            
            viewer.addEventListener('touchend', function() {
                panning = false;
            });
        }

        function editFile(filename) {
            if (!isAuthenticated) {
                showToast('Please login to edit files', 'error');
                return;
            }
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
                showToast(data.message, 'success');
                closeModal('editModal');
                loadFiles();
            })
            .catch(() => {
                showToast('Failed to save file', 'error');
            });
        }

        function downloadFile(filename) {
            window.location.href = '/download/' + encodeURIComponent(filename);
        }

        function deleteFile(filename) {
            if (!isAuthenticated) {
                showToast('Please login to delete files', 'error');
                return;
            }
            if (confirm('Delete ' + filename + '?')) {
                fetch('/delete/' + encodeURIComponent(filename), { method: 'DELETE' })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, 'success');
                        loadFiles();
                    })
                    .catch(() => {
                        showToast('Failed to delete file', 'error');
                    });
            }
        }

        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
            const videos = document.querySelectorAll('video');
            const audios = document.querySelectorAll('audio');
            videos.forEach(v => v.pause());
            audios.forEach(a => a.pause());
        }

        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                const modalId = event.target.id;
                closeModal(modalId);
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
stats.mu.Lock()
stats.TotalRequests++
stats.mu.Unlock()
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
		continue
	}
	defer file.Close()

	dst, err := os.Create(filepath.Join(publicDir, fileHeader.Filename))
	if err != nil {
		continue
	}
	defer dst.Close()

	written, err := io.Copy(dst, file)
	if err != nil {
		continue
	}

	uploadedCount++
	if debug {
		log.Printf("Uploaded: %s (%d bytes)", fileHeader.Filename, written)
	}
}

updateStats()

w.WriteHeader(http.StatusOK)
w.Write([]byte(fmt.Sprintf("%d file(s) uploaded", uploadedCount)))
}

func handleListFiles(w http.ResponseWriter, r *http.Request) {
files, err := os.ReadDir(publicDir)
if err != nil {
http.Error(w, "Error reading directory", http.StatusInternalServerError)
return
}
var fileList []FileMetadata
for _, file := range files {
	if !file.IsDir() {
		info, _ := file.Info()
		downloadMu.RLock()
		count := downloadCounts[file.Name()]
		downloadMu.RUnlock()
		
		fileList = append(fileList, FileMetadata{
			Name:          file.Name(),
			Type:          getFileType(file.Name()),
			Size:          info.Size(),
			ModTime:       info.ModTime(),
			DownloadCount: count,
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
json.NewEncoder(w).Encode(map[string]string{"message": "File saved successfully"})
}
func handleRaw(w http.ResponseWriter, r *http.Request) {
filename := r.URL.Path[len("/raw/"):]
filePath := filepath.Join(publicDir, filename)
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
// Increment download counter
downloadMu.Lock()
downloadCounts[filename]++
downloadMu.Unlock()
saveDownloadCounts()

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
	http.Error(w, "Error deleting file", http.StatusInternalServerError)
	return
}

// Remove from download counts
downloadMu.Lock()
delete(downloadCounts, filename)
downloadMu.Unlock()
saveDownloadCounts()

if debug {
	log.Printf("Deleted: %s", filename)
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{"message": "File deleted successfully"})
}
func handleRename(w http.ResponseWriter, r *http.Request) {
if r.Method != "POST" {
http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
return
}
oldName := r.URL.Path[len("/rename/"):]

var req struct {
	NewName string `json:"new_name"`
}
json.NewDecoder(r.Body).Decode(&req)

oldPath := filepath.Join(publicDir, oldName)
newPath := filepath.Join(publicDir, req.NewName)

err := os.Rename(oldPath, newPath)
if err != nil {
	http.Error(w, "Error renaming file", http.StatusInternalServerError)
	return
}

// Update download counts
downloadMu.Lock()
if count, exists := downloadCounts[oldName]; exists {
	downloadCounts[req.NewName] = count
	delete(downloadCounts, oldName)
}
downloadMu.Unlock()
saveDownloadCounts()

if debug {
	log.Printf("Renamed: %s -> %s", oldName, req.NewName)
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{"message": "File renamed successfully"})
}
func handleDuplicate(w http.ResponseWriter, r *http.Request) {
if r.Method != "POST" {
http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
return
}
filename := r.URL.Path[len("/duplicate/"):]
srcPath := filepath.Join(publicDir, filename)

// Generate new name
ext := filepath.Ext(filename)
base := strings.TrimSuffix(filename, ext)
newName := base + "_copy" + ext

// Check if copy already exists, add number
counter := 1
for {
	newPath := filepath.Join(publicDir, newName)
	if _, err := os.Stat(newPath); os.IsNotExist(err) {
		break
	}
	newName = fmt.Sprintf("%s_copy%d%s", base, counter, ext)
	counter++
}

dstPath := filepath.Join(publicDir, newName)

src, err := os.Open(srcPath)
if err != nil {
	http.Error(w, "Error reading file", http.StatusInternalServerError)
	return
}
defer src.Close()

dst, err := os.Create(dstPath)
if err != nil {
	http.Error(w, "Error creating file", http.StatusInternalServerError)
	return
}
defer dst.Close()

_, err = io.Copy(dst, src)
if err != nil {
	http.Error(w, "Error copying file", http.StatusInternalServerError)
	return
}

if debug {
	log.Printf("Duplicated: %s -> %s", filename, newName)
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{"message": "File duplicated as " + newName})
}
func handleZipMultiple(w http.ResponseWriter, r *http.Request) {
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
	filePath := filepath.Join(publicDir, filename)
	
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

if debug {
	log.Printf("Created ZIP with %d files", len(req.Files))
}
}
func handleZipView(w http.ResponseWriter, r *http.Request) {
filename := r.URL.Path[len("/zip-view/"):]
filePath := filepath.Join(publicDir, filename)
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
	entries = append(entries, ZipEntry{
		Name: f.Name,
		Size: int64(f.UncompressedSize64),
	})
	totalSize += int64(f.UncompressedSize64)
}

response := map[string]interface{}{
	"files":      entries,
	"total_size": totalSize,
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(response)
}
