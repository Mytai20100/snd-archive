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
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const VERSION = "1.3.2 archive"

type Config struct {
	IP           string `yaml:"ip"`
	Port         string `yaml:"port"`
	SiteName     string `yaml:"site_name"`
	IconURL      string `yaml:"icon_url"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	UseHTTPS     bool   `yaml:"use_https"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	APIToken     string `yaml:"api_token"`
	Enable2FA    bool   `yaml:"enable_2fa"`
	DiscordWebhook string `yaml:"discord_webhook"`
	SFTPEnabled  bool   `yaml:"sftp_enabled"`
	SFTPPort     string `yaml:"sftp_port"`
	SFTPKeyPath  string `yaml:"sftp_key_path"`
}
type FilePermission struct {
	IsPublic bool   `json:"is_public"`
	Token    string `json:"token,omitempty"`
}
type FileMetadata struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	DownloadCount int      `json:"download_count"`
}
type TwoFACode struct {
	Code      string
	ExpiresAt time.Time
	Used      bool
}
type ErrorPage struct {
	StatusCode int
	Title      string
	Message    string
	Details    string
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
    filePermissions   = make(map[string]FilePermission)
	permissionMu      sync.RWMutex
	twoFACodes        = make(map[string]TwoFACode)
	twoFAMu           sync.RWMutex
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

	// Routes
    http.HandleFunc("/favicon.ico", handleFavicon)
	http.HandleFunc("/ac", handleLogin)
	http.HandleFunc("/login", handleLoginSubmit)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/ad", requireAuth(handleAdmin))
	http.HandleFunc("/files", obfuscateHandler(handleListFiles))
	http.HandleFunc("/upload", obfuscateHandler(requireAuth(handleUpload)))
	http.HandleFunc("/create-folder", requireAuth(handleCreateFolder))
	http.HandleFunc("/delete-folder/", requireAuth(handleDeleteFolder))
	http.HandleFunc("/set-permission", requireAuth(handleSetPermission))
	http.HandleFunc("/view/", requireTokenOrAuth(handleView)) 
	http.HandleFunc("/stream/", requireTokenOrAuth(handleStream))
	http.HandleFunc("/edit/", requireAuth(requireToken(handleEdit)))
	http.HandleFunc("/save/", requireAuth(requireToken(handleSave)))
	http.HandleFunc("/raw/", requireTokenOrAuth(handleRaw)) 
    http.HandleFunc("/download/", requireTokenOrAuth(handleDownload))
	http.HandleFunc("/delete/", requireAuth(handleDelete))
	http.HandleFunc("/rename/", requireAuth(handleRename))
	http.HandleFunc("/duplicate/", requireAuth(handleDuplicate))
	http.HandleFunc("/zip-multiple", requireAuth(handleZipMultiple))
	http.HandleFunc("/zip-view/", handleZipView)
	http.HandleFunc("/benchmark/ping", handleBenchmarkPing)
	http.HandleFunc("/benchmark/download", handleBenchmarkDownload)
	http.HandleFunc("/benchmark/upload", handleBenchmarkUpload)
	http.HandleFunc("/benchmark/disk", requireAuth(handleBenchmarkDisk))
	http.HandleFunc("/", handleIndex)

	addr := config.IP + ":" + config.Port
	fmt.Printf("ServerNotDie v%s\n", VERSION)
	fmt.Printf("Server starting on %s://%s\n", getProtocol(), addr)
	fmt.Printf("API Token: `%s`\n", config.APIToken)
	fmt.Printf("2FA Enabled: %v\n", config.Enable2FA)

	if config.SFTPEnabled {
		go startSFTPServer()
	}

	if config.UseHTTPS {
		if err := http.ListenAndServeTLS(addr, config.CertFile, config.KeyFile, nil); err != nil {
			log.Fatalf("HTTPS Server failed: %v", err)
		}
	} else {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("HTTP Server failed: %v", err)
		}
	}
}

func startSFTPServer() {
	panic("unimplemented")
}

func getProtocol() string {
	if config.UseHTTPS {
		return "https"
	}
	return "http"
}

func loadConfig() Config {
	cfg := Config{
		IP:             "0.0.0.0",
		Port:           "8080",
		SiteName:       "servernotdie",
		IconURL:        "https://cdn-icons-png.flaticon.com/512/716/716784.png",
		Username:       "admin",
		Password:       "admin",
		UseHTTPS:       true,
		CertFile:       "server.crt",
		KeyFile:        "server.key",
		APIToken:       generateRandomToken(82),
		Enable2FA:      false,
		DiscordWebhook: "",
		SFTPEnabled:    false,
		SFTPPort:       "2022",
		SFTPKeyPath:    "sftp_key.pem",
	}

	data, err := os.ReadFile(configFile)
	if err == nil {
		yaml.Unmarshal(data, &cfg)
	} else {
		data, _ := yaml.Marshal(cfg)
		os.WriteFile(configFile, data, 0644)
		fmt.Printf("Created default config file: %s\n", configFile)
		fmt.Printf("Default API Token: %s\n", cfg.APIToken)
	}

	loadFilePermissions()
	return cfg
}

func generateRandomToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
func requireTokenOrAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filename := extractFilename(r.URL.Path)
		
		// Check if file is public
		permissionMu.RLock()
		perm, exists := filePermissions[filename]
		permissionMu.RUnlock()
		
		if exists && perm.IsPublic {
			// Public file - chỉ cần token
			handler(w, r)
			return
		}
		
		// Private file - cần cả token VÀ session
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		
		if token != config.APIToken {
			http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
			return
		}
		
		// Check session for private files
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "Unauthorized: Login required for private files", http.StatusUnauthorized)
			return
		}
		
		sessionMu.RLock()
		expiry, exists := sessions[cookie.Value]
		sessionMu.RUnlock()
		
		if !exists || time.Now().After(expiry) {
			http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
			return
		}
		
		handler(w, r)
	}
}
func loadFilePermissions() {
	data, err := os.ReadFile("file_permissions.json")
	if err == nil {
		json.Unmarshal(data, &filePermissions)
	}
}

func saveFilePermissions() {
	permissionMu.RLock()
	data, _ := json.Marshal(filePermissions)
	permissionMu.RUnlock()
	os.WriteFile("file_permissions.json", data, 0644)
}
func requireToken(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filename := extractFilename(r.URL.Path)
		
		permissionMu.RLock()
		perm, exists := filePermissions[filename]
		permissionMu.RUnlock()
		if exists && perm.IsPublic {
			handler(w, r)
			return
		}
		
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		
		if token != config.APIToken {
			http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
			return
		}
		
		handler(w, r)
	}
}
func send2FACodeToDiscord(username string, code string) error {
	if config.DiscordWebhook == "" {
		return fmt.Errorf("Discord webhook not configured")
	}
	
	payload := map[string]interface{}{
		"content": fmt.Sprintf(" **2FA Code for %s**\n\n```\n%s\n```\n\n Expires in 5 minutes", username, code),
		"username": config.SiteName,
	}
	
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(config.DiscordWebhook, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("Discord webhook failed with status: %d", resp.StatusCode)
	}
	
	return nil
}
func handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Path        string `json:"path"`
		CurrentPath string `json:"current_path"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	// Validate
	if strings.Contains(req.Path, "..") || strings.Contains(req.CurrentPath, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	fullPath := filepath.Join(publicDir, req.CurrentPath, req.Path)
	err := os.MkdirAll(fullPath, 0755)
	if err != nil {
		http.Error(w, "Failed to create folder", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Folder created successfully"})
}

func handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	folderName := r.URL.Path[len("/delete-folder/"):]
	folderPath := filepath.Join(publicDir, folderName)
	
	err := os.RemoveAll(folderPath)
	if err != nil {
		http.Error(w, "Failed to delete folder", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Folder deleted successfully"})
}

func handleSetPermission(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Filename string `json:"filename"`
		IsPublic bool   `json:"is_public"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	permissionMu.Lock()
	filePermissions[req.Filename] = FilePermission{
		IsPublic: req.IsPublic,
		Token:    config.APIToken,
	}
	permissionMu.Unlock()
	
	saveFilePermissions()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Permission updated successfully"})
}
func handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TwoFACode string `json:"twofa_code,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	if creds.Username != config.Username || creds.Password != config.Password {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid credentials",
		})
		return
	}

	if config.Enable2FA {
		if creds.TwoFACode == "" {
			code := generateRandomToken(82)
			twoFAMu.Lock()
			twoFACodes[creds.Username] = TwoFACode{
				Code:      code,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Used:      false,
			}
			twoFAMu.Unlock()
			if err := send2FACodeToDiscord(creds.Username, code); err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "Failed to send 2FA code",
				})
				return
			}
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"require_2fa": true,
				"message": "2FA code sent to Discord. Please check your webhook.",
			})
			return
		}
		
		twoFAMu.Lock()
		storedCode, exists := twoFACodes[creds.Username]
		twoFAMu.Unlock()
		
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
		twoFAMu.Lock()
		storedCode.Used = true
		twoFACodes[creds.Username] = storedCode
		twoFAMu.Unlock()
	}

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
}
func extractFilename(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
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

	// Text & Code files
	textExts := []string{
		".txt", ".log", ".md", ".markdown", ".json", ".xml", ".html", ".htm", ".css", ".js", 
		".jsx", ".ts", ".tsx", ".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg", ".config",
		".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1", ".psm1",
		".py", ".pyc", ".pyw", ".pyx", ".go", ".java", ".class", ".jar",
		".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
		".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
		".rb", ".rake", ".rbw", ".rs", ".rlib",
		".sql", ".sqlite", ".db",
		".swift", ".kt", ".kts", ".scala", ".groovy",
		".r", ".rdata", ".rds",
		".pl", ".pm", ".t", ".pod",
		".lua", ".vim", ".vimrc",
		".dockerfile", ".makefile", ".cmake",
		".proto", ".thrift",
		".graphql", ".gql",
		".vue", ".svelte",
		".dart", ".ex", ".exs", ".erl", ".hrl",
		".clj", ".cljs", ".cljc", ".edn",
		".elm", ".purs",
		".diff", ".patch",
		".gitignore", ".gitattributes", ".editorconfig",
		".env", ".properties",
		".csv", ".tsv",
	}
	for _, e := range textExts {
		if ext == e {
			return "text"
		}
	}

	// Image files
	imageExts := []string{
		".jpg", ".jpeg", ".jpe", ".jfif",
		".png", ".apng",
		".gif",
		".bmp", ".dib",
		".webp",
		".svg", ".svgz",
		".ico", ".icon",
		".tif", ".tiff",
		".psd", ".psb",
		".ai", ".eps",
		".raw", ".cr2", ".nef", ".orf", ".sr2",
		".heic", ".heif",
		".avif",
		".jxl",
		".xcf",
		".sketch",
	}
	for _, e := range imageExts {
		if ext == e {
			return "image"
		}
	}

	// Video files
	videoExts := []string{
		".mp4", ".m4v", ".m4p",
		".webm",
		".ogg", ".ogv",
		".mov", ".qt",
		".avi",
		".mkv", ".mk3d", ".mka", ".mks",
		".flv", ".f4v",
		".wmv", ".asf",
		".mpg", ".mpeg", ".mpe", ".mpv", ".m2v",
		".3gp", ".3g2",
		".vob",
		".ts", ".m2ts", ".mts",
		".divx",
		".rm", ".rmvb",
		".swf",
	}
	for _, e := range videoExts {
		if ext == e {
			return "video"
		}
	}

	// Audio files
	audioExts := []string{
		".mp3",
		".wav", ".wave",
		".ogg", ".oga", ".opus",
		".m4a", ".m4b", ".m4p",
		".flac",
		".aac",
		".wma",
		".aiff", ".aif", ".aifc",
		".ape",
		".alac",
		".mid", ".midi",
		".ra", ".ram",
		".wv",
		".tta",
		".mka",
		".dsd", ".dsf", ".dff",
		".amr",
		".awb",
	}
	for _, e := range audioExts {
		if ext == e {
			return "audio"
		}
	}

	// Archive files
	archiveExts := []string{
		".zip", ".zipx",
		".rar", ".rev", ".r00", ".r01",
		".7z",
		".tar",
		".gz", ".gzip", ".tgz",
		".bz2", ".bzip2", ".tbz2",
		".xz", ".txz",
		".zst", ".zstd",
		".lz", ".lzma", ".tlz",
		".lz4",
		".z",
		".cab",
		".iso", ".img", ".dmg",
		".ace",
		".arj",
		".jar", ".war", ".ear",
		".apk", ".ipa",
		".deb", ".rpm",
		".pkg",
		".msi",
		".exe", // Windows installer archives
	}
	for _, e := range archiveExts {
		if ext == e {
			return "archive"
		}
	}

	// Document files
	documentExts := []string{
		".pdf",
		".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm",
		".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".xltx", ".xltm",
		".ppt", ".pptx", ".pptm", ".pot", ".potx", ".potm", ".pps", ".ppsx", ".ppsm",
		".odt", ".ods", ".odp", ".odg", ".odf",
		".rtf",
		".tex", ".latex",
		".epub", ".mobi", ".azw", ".azw3",
		".djvu", ".djv",
		".pages", ".numbers", ".key",
	}
	for _, e := range documentExts {
		if ext == e {
			return "document"
		}
	}

	// Font files
	fontExts := []string{
		".ttf", ".otf", ".woff", ".woff2", ".eot",
		".fon", ".fnt",
	}
	for _, e := range fontExts {
		if ext == e {
			return "font"
		}
	}

	// 3D Model files
	modelExts := []string{
		".obj", ".fbx", ".dae", ".3ds", ".blend", ".stl", ".ply",
		".gltf", ".glb", ".usdz",
	}
	for _, e := range modelExts {
		if ext == e {
			return "3d-model"
		}
	}

	// Certificate & Key files
	certExts := []string{
		".pem", ".crt", ".cer", ".der",
		".key", ".pub",
		".p12", ".pfx", ".p7b", ".p7c",
		".csr",
		".jks", ".keystore",
	}
	for _, e := range certExts {
		if ext == e {
			return "certificate"
		}
	}

	// Database files
	databaseExts := []string{
		".db", ".sqlite", ".sqlite3",
		".mdb", ".accdb",
		".dbf",
		".frm", ".myd", ".myi",
	}
	for _, e := range databaseExts {
		if ext == e {
			return "database"
		}
	}

	// Backup files
	backupExts := []string{
		".bak", ".backup", ".old", ".orig",
		".swp", ".swo", ".tmp",
		"~",
	}
	for _, e := range backupExts {
		if ext == e {
			return "backup"
		}
	}

	return "binary"
}
func handleStream(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/stream/"):]
	filePath := filepath.Join(publicDir, filename)
	
	file, err := os.Open(filePath)
	if err != nil {
		renderErrorPage(w, http.StatusNotFound, 
            "File Not Found", 
            "The file you're looking for doesn't exist.",
            "Path: " + r.URL.Path)
		return
	}
	defer file.Close()
	
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Error getting file info", http.StatusInternalServerError)
		return
	}
	
	size := stat.Size()
	
	// Set content type based on extension
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
	
	// Handle range requests for seeking
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("Accept-Ranges", "bytes")
		io.Copy(w, file)
		return
	}
	
	// Parse range header
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
func handleBenchmarkPing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "pong", "time": time.Now().Format(time.RFC3339Nano)})
}
// Obfuscate response to hide API structure
func obfuscateHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Remove server header
		w.Header().Set("Server", "")
		w.Header().Set("X-Powered-By", "")
		next(w, r)
	}
}
func handleBenchmarkDownload(w http.ResponseWriter, r *http.Request) {
	size := 10 * 1024 * 1024 // 10MB
	if sizeParam := r.URL.Query().Get("size"); sizeParam != "" {
		if s, err := strconv.Atoi(sizeParam); err == nil {
			size = s * 1024 * 1024
		}
	}
	
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	
	buffer := make([]byte, 32768)
	for i := 0; i < size; i += len(buffer) {
		remaining := size - i
		if remaining < len(buffer) {
			w.Write(buffer[:remaining])
		} else {
			w.Write(buffer)
		}
	}
}

func handleBenchmarkUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	startTime := time.Now()
	written, err := io.Copy(io.Discard, r.Body)
	duration := time.Since(startTime).Seconds()
	
	if err != nil {
		http.Error(w, "Upload error", http.StatusInternalServerError)
		return
	}
	
	speed := float64(written) / duration / 1024 / 1024
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"bytes":    written,
		"duration": duration,
		"speed":    speed,
	})
}

func handleBenchmarkDisk(w http.ResponseWriter, r *http.Request) {
	testFile := filepath.Join(publicDir, ".benchmark_test")
	defer os.Remove(testFile)
	
	// Write test
	writeStart := time.Now()
	data := make([]byte, 10*1024*1024) // 10MB
	writeErr := os.WriteFile(testFile, data, 0644)
	writeDuration := time.Since(writeStart).Seconds()
	writeSpeed := float64(len(data)) / writeDuration / 1024 / 1024
	
	// Read test
	readStart := time.Now()
	_, readErr := os.ReadFile(testFile)
	readDuration := time.Since(readStart).Seconds()
	readSpeed := float64(len(data)) / readDuration / 1024 / 1024
	
	if writeErr != nil || readErr != nil {
		http.Error(w, "Disk test error", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"write_speed": writeSpeed,
		"read_speed":  readSpeed,
		"write_time":  writeDuration,
		"read_time":   readDuration,
	})
}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
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
        <input type="text" id="twofa" placeholder="2FA Code (if enabled)" style="display:none;">
        <button type="submit">Login</button>
    </form>
    <div id="twofa-message" style="margin-top: 16px; padding: 12px; background: #f5f5f5; display: none; font-size: 12px;"></div>
</div>
<script>
    function login(e) {
        e.preventDefault();
        const payload = {
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        };
        
        const twofaCode = document.getElementById('twofa').value;
        if (twofaCode) {
            payload.twofa_code = twofaCode;
        }
        
        fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                window.location.href = '/';
            } else if (data.require_2fa) {
                document.getElementById('twofa').style.display = 'block';
                document.getElementById('twofa-message').style.display = 'block';
                document.getElementById('twofa-message').innerHTML = ' ' + data.message + '<br><small>Check your Discord for the 82-character code</small>';
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
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
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

        <div class="system-info" style="margin-top: 16px;">
            <h2 style="font-size: 18px; font-weight: 500; margin-bottom: 16px;">Performance Benchmark</h2>
            <div style="display: grid; gap: 12px;">
                <button class="btn" onclick="runPingTest()" style="width: 100%;">Test Ping</button>
                <button class="btn" onclick="runDownloadTest()" style="width: 100%;">Test Download Speed</button>
                <button class="btn" onclick="runUploadTest()" style="width: 100%;">Test Upload Speed</button>
                <button class="btn" onclick="runDiskTest()" style="width: 100%;">Test Disk Speed</button>
            </div>
            <div id="benchmarkResults" style="margin-top: 16px; padding: 16px; background: #fafafa; border: 1px solid #e0e0e0; border-radius: 4px; min-height: 100px; font-family: 'SF Mono', monospace; font-size: 12px; white-space: pre-wrap; display: none;"></div>
        </div>
    </div>

    <script>
        let autoReloadInterval;
        let isBenchmarkRunning = false;

        function startAutoReload() {
            if (!isBenchmarkRunning) {
                autoReloadInterval = setInterval(() => {
                    if (!isBenchmarkRunning) {
                        location.reload();
                    }
                }, 10000);
            }
        }

        function stopAutoReload() {
            if (autoReloadInterval) {
                clearInterval(autoReloadInterval);
            }
        }

        startAutoReload();

        function showBenchmarkResult(text) {
            const results = document.getElementById('benchmarkResults');
            results.style.display = 'block';
            results.textContent = text;
        }

        async function runPingTest() {
            isBenchmarkRunning = true;
            stopAutoReload();
            showBenchmarkResult('Testing ping...');
            const samples = 10;
            const pings = [];
            
            try {
                for (let i = 0; i < samples; i++) {
                    const start = performance.now();
                    await fetch('/benchmark/ping');
                    const end = performance.now();
                    pings.push(end - start);
                }
                
                const avg = pings.reduce((a, b) => a + b, 0) / pings.length;
                const min = Math.min(...pings);
                const max = Math.max(...pings);
                
                showBenchmarkResult('Ping Test Results:\nAverage: ' + avg.toFixed(2) + ' ms\nMin: ' + min.toFixed(2) + ' ms\nMax: ' + max.toFixed(2) + ' ms');
            } catch (error) {
                showBenchmarkResult('Ping test failed: ' + error.message);
            } finally {
                isBenchmarkRunning = false;
                startAutoReload();
            }
        }

        async function runDownloadTest() {
            isBenchmarkRunning = true;
            stopAutoReload();
            showBenchmarkResult('Testing download speed...');
            const size = 10;
            
            try {
                const start = performance.now();
                const response = await fetch('/benchmark/download?size=' + size);
                await response.blob();
                const end = performance.now();
                
                const duration = (end - start) / 1000;
                const speed = (size / duration).toFixed(2);
                
                showBenchmarkResult('Download Test Results:\nSize: ' + size + ' MB\nDuration: ' + duration.toFixed(2) + ' seconds\nSpeed: ' + speed + ' MB/s');
            } catch (error) {
                showBenchmarkResult('Download test failed: ' + error.message);
            } finally {
                isBenchmarkRunning = false;
                startAutoReload();
            }
        }

        async function runUploadTest() {
            isBenchmarkRunning = true;
            stopAutoReload();
            showBenchmarkResult('Testing upload speed...');
            const size = 10 * 1024 * 1024;
            const data = new Uint8Array(size);
            
            try {
                const start = performance.now();
                await fetch('/benchmark/upload', {
                    method: 'POST',
                    body: data
                });
                const end = performance.now();
                
                const duration = (end - start) / 1000;
                const speed = (size / 1024 / 1024 / duration).toFixed(2);
                
                showBenchmarkResult('Upload Test Results:\nSize: 10 MB\nDuration: ' + duration.toFixed(2) + ' seconds\nSpeed: ' + speed + ' MB/s');
            } catch (error) {
                showBenchmarkResult('Upload test failed: ' + error.message);
            } finally {
                isBenchmarkRunning = false;
                startAutoReload();
            }
        }

        async function runDiskTest() {
            isBenchmarkRunning = true;
            stopAutoReload();
            showBenchmarkResult('Testing disk speed...');
            
            try {
                const response = await fetch('/benchmark/disk');
                const data = await response.json();
                
                showBenchmarkResult('Disk Test Results:\nWrite Speed: ' + data.write_speed.toFixed(2) + ' MB/s\nRead Speed: ' + data.read_speed.toFixed(2) + ' MB/s\nWrite Time: ' + data.write_time.toFixed(3) + ' seconds\nRead Time: ' + data.read_time.toFixed(3) + ' seconds');
            } catch (error) {
                showBenchmarkResult('Disk test failed: ' + error.message);
            } finally {
                isBenchmarkRunning = false;
                startAutoReload();
            }
        }
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
	apiTokenSection := ""

	if isAuth {
		authStatus = "true"
		authButtons = `<button class="btn" onclick="createFolder()">New Folder</button>
                       <a href="/ad" class="btn">Admin</a>
                       <a href="#" onclick="logout(); return false;" class="btn">Logout</a>`
		uploadSectionDisplay = "block"
		apiTokenSection = `
        <div class="upload-section" id="apiTokenSection" style="background: #fff3e0; border: 2px solid #f57c00; position: relative;">
            <button onclick="closeApiTokenSection()" style="position: absolute; top: 8px; right: 8px; background: none; border: none; font-size: 20px; color: #e65100; cursor: pointer; width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 4px;" onmouseover="this.style.background='#ffccbc'" onmouseout="this.style.background='none'" title="Hide API Token">&times;</button>
            <div style="padding: 12px;">
                <div style="font-size: 13px; font-weight: 500; color: #e65100; margin-bottom: 8px;">API Token</div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <input type="password" id="apiTokenDisplay" value="` + config.APIToken + `" readonly 
                           style="flex: 1; padding: 8px; border: 1px solid #f57c00; background: white; font-family: monospace; font-size: 12px;">
                    <button class="btn" onclick="toggleTokenVisibility()" style="white-space: nowrap;">Show</button>
                    <button class="btn" onclick="copyToken()" style="white-space: nowrap;">Copy</button>
                </div>
                <div style="font-size: 11px; color: #e65100; margin-top: 8px;">
                    Token is automatically added to file URLs. Share links will include the token.
                </div>
            </div>
        </div>`
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
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
            .toggle-switch {
    position: relative;
    display: inline-block;
    width: 44px;
    height: 24px;
}

.toggle-switch input {
    opacity: 0;
    width: 0;
    height: 0;
}

.toggle-slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #f44336;
    transition: 0.3s;
    border-radius: 24px;
}

.toggle-slider:before {
    position: absolute;
    content: "";
    height: 18px;
    width: 18px;
    left: 3px;
    bottom: 3px;
    background-color: white;
    transition: 0.3s;
    border-radius: 50%;
}

input:checked + .toggle-slider {
    background-color: #4caf50;
}

input:checked + .toggle-slider:before {
    transform: translateX(20px);
}

.toggle-slider:after {
    content: 'Private';
    position: absolute;
    right: 8px;
    top: 4px;
    font-size: 9px;
    color: white;
    font-weight: 500;
}

input:checked + .toggle-slider:after {
    content: 'Public';
    left: 8px;
    right: auto;
}
    </style>
</head>
<body>
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
        <div style="padding: 12px 20px; background: #f5f5f5; border-bottom: 1px solid #e0e0e0; font-size: 13px;" id="breadcrumb">
            <span style="color: #666;">Root</span>
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
        ` + apiTokenSection + `
        <div class="progress-section" id="progressSection">
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div class="progress-info">
                <span id="progressText">0%</span>
                <span id="speedText">0 MB/s</span>
            </div>
        </div>

        <div class="bulk-actions" id="bulkActions">
            <span id="selectedCount" style="font-size: 14px; color: #666;">0 selected</span>
            <button class="btn-small" onclick="downloadSelectedAsZip()">Download as ZIP</button>
            <button class="btn-small" onclick="deselectAll()">Deselect All</button>
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
    <div class="modal" id="createFolderModal">
    <div class="modal-content" style="max-width: 500px;">
        <div class="modal-header">
            <h3>Create New Folder</h3>
            <button class="close-btn" onclick="closeModal('createFolderModal')">&times;</button>
        </div>
        <div class="modal-body">
            <input type="text" id="folderNameInput" placeholder="Enter folder name" 
                   style="width: 100%; padding: 12px; border: 1px solid #e0e0e0; font-size: 14px; border-radius: 4px;">
        </div>
        <div class="modal-footer">
            <button class="btn-small" onclick="closeModal('createFolderModal')">Cancel</button>
            <button class="btn-small" onclick="confirmCreateFolder()">Create</button>
        </div>
    </div>
</div>
    <div class="footer">
        <strong>ServerNotDie</strong> v` + VERSION + `
    </div>

    <script>
        let currentPath = '';
        const isAuthenticated = ` + authStatus + `;
        let startTime, currentEditFile, currentRenameFile;
        let allFiles = [];
        let selectedFiles = new Set();
        let bulkMode = false;

        function closeApiTokenSection() {
            const section = document.getElementById('apiTokenSection');
            if (section) {
                section.style.display = 'none';
                localStorage.setItem('hideApiToken', 'true');
                showToast('API Token section hidden', 'success');
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            const hideApiToken = localStorage.getItem('hideApiToken');
            const section = document.getElementById('apiTokenSection');
            if (hideApiToken === 'true' && section) {
                section.style.display = 'none';
            }
        });

        function toggleTokenVisibility() {
            const tokenInput = document.getElementById('apiTokenDisplay');
            const btn = event.target;
            
            if (tokenInput.type === 'password') {
                tokenInput.type = 'text';
                btn.textContent = 'Hide';
            } else {
                tokenInput.type = 'password';
                btn.textContent = 'Show';
            }
        }

        function copyToken() {
            const tokenInput = document.getElementById('apiTokenDisplay');
            tokenInput.select();
            tokenInput.setSelectionRange(0, 99999);
            
            navigator.clipboard.writeText(tokenInput.value).then(() => {
                showToast('API Token copied!', 'success');
            }).catch(() => {
                showToast('Failed to copy token', 'error');
            });
        }

        function navigateToFolder(folderName) {
            currentPath = folderName;
            loadFiles();
            updateBreadcrumb();
        }

        function navigateToRoot() {
            currentPath = '';
            loadFiles();
            updateBreadcrumb();
        }

        function updateBreadcrumb() {
            const breadcrumb = document.getElementById('breadcrumb');
            if (!breadcrumb) return;
            
            if (currentPath === '') {
                breadcrumb.innerHTML = '<span style="color: #666;">📁 Root</span>';
            } else {
                const parts = currentPath.split('/').filter(p => p);
                let html = '<a href="#" onclick="navigateToRoot(); return false;" style="color: #0066cc; text-decoration: none;">📁 Root</a>';
                
                let pathSoFar = '';
                parts.forEach((part, index) => {
                    pathSoFar += (pathSoFar ? '/' : '') + part;
                    if (index === parts.length - 1) {
                        html += ' / <span style="color: #666;">' + escapeHtml(part) + '</span>';
                    } else {
                        const navPath = pathSoFar;
                        html += ' / <a href="#" onclick="currentPath=\'' + navPath.replace(/'/g, "\\'") + '\'; loadFiles(); updateBreadcrumb(); return false;" style="color: #0066cc; text-decoration: none;">' + escapeHtml(part) + '</a>';
                    }
                });
                breadcrumb.innerHTML = html;
            }
        }

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
            const baseUrl = window.location.origin + '/raw/' + encodeURIComponent(filename);
            const url = addTokenToURL(baseUrl);
            
            navigator.clipboard.writeText(url).then(() => {
                showToast('Link with token copied!', 'success');
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = url;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand('copy');
                    showToast('Link with token copied!', 'success');
                } catch (err) {
                    showToast('Failed to copy link', 'error');
                }
                document.body.removeChild(textArea);
            });
        }
        function togglePublicAccessSwitch(filename, isPublic) {
    fetch('/set-permission', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            filename: filename,
            is_public: isPublic
        })
    })
    .then(r => r.json())
    .then(data => {
        const status = isPublic ? 'PUBLIC' : 'PRIVATE';
        showToast(filename + ' is now ' + status, 'success');
        loadFiles();
    })
    .catch(() => {
        showToast('Failed to update permission', 'error');
        loadFiles();
    });
}

function createFolder() {
    document.getElementById('folderNameInput').value = '';
    document.getElementById('createFolderModal').style.display = 'block';
    document.getElementById('folderNameInput').focus();
}

function confirmCreateFolder() {
    const folderName = document.getElementById('folderNameInput').value.trim();
    
    if (!folderName) {
        showToast('Please enter a folder name', 'error');
        return;
    }
    
    if (folderName.includes('..') || folderName.includes('/') || folderName.includes('\\')) {
        showToast('Invalid folder name', 'error');
        return;
    }
    
    fetch('/create-folder', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            path: folderName,
            current_path: currentPath
        })
    })
    .then(r => r.json())
    .then(data => {
        showToast(data.message, 'success');
        closeModal('createFolderModal');
        loadFiles();
    })
    .catch(() => {
        showToast('Failed to create folder', 'error');
    });
}
        function togglePublicAccess(filename) {
            const currentStatus = prompt('Enter "public" to make accessible without token, or "private" to require token:', 'public');
            
            if (!currentStatus || (currentStatus !== 'public' && currentStatus !== 'private')) {
                return;
            }
            
            const isPublic = currentStatus === 'public';
            
            fetch('/set-permission', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    filename: filename,
                    is_public: isPublic
                })
            })
            .then(r => r.json())
            .then(data => {
                const status = isPublic ? 'PUBLIC' : 'PRIVATE';
                showToast(filename + ' is now ' + status, 'success');
                loadFiles();
            })
            .catch(() => {
                showToast('Failed to update permission', 'error');
            });
        }

        function createFolder() {
            const folderName = prompt('Enter folder name:');
            if (!folderName) return;
            
            if (folderName.includes('..') || folderName.includes('/') || folderName.includes('\\')) {
                showToast('Invalid folder name', 'error');
                return;
            }
            
            fetch('/create-folder', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    path: folderName,
                    current_path: currentPath
                })
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, 'success');
                loadFiles();
            })
            .catch(() => {
                showToast('Failed to create folder', 'error');
            });
        }

        function deleteFolder(folderName) {
            const confirmText = prompt('Type "DELETE" to confirm deletion of folder: ' + folderName);
            
            if (confirmText !== 'DELETE') {
                showToast('Deletion cancelled', 'error');
                return;
            }
            
            fetch('/delete-folder/' + encodeURIComponent(folderName), {
                method: 'DELETE'
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, 'success');
                loadFiles();
            })
            .catch(() => {
                showToast('Failed to delete folder', 'error');
            });
        }

        function addTokenToURL(url) {
            const token = document.getElementById('apiTokenDisplay') ? 
                          document.getElementById('apiTokenDisplay').value : 
                          '` + config.APIToken + `';
            return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
        }

        function loadFiles() {
    const url = currentPath ? '/files?path=' + encodeURIComponent(currentPath) : '/files';
    
    fetch(url)
        .then(r => {
            if (!r.ok) throw new Error('Failed to load');
            return r.json();
        })
        .then(data => {
            let files = [];
            let folders = [];
            
            if (Array.isArray(data)) {
                files = data;
            } else {
                files = data.files || [];
                folders = data.folders || [];
            }
            
            allFiles = files;
            const section = document.getElementById('filesSection');
            
            if (folders.length === 0 && files.length === 0) {
                section.innerHTML = '<div class="empty-state">No files or folders here</div>';
                return;
            }
            
            let html = '';
            
            // Render folders với menu ba chấm
            folders.forEach(folder => {
                const escapedName = folder.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                const fullPath = currentPath ? currentPath + '/' + folder : folder;
                
                html += '<div class="file-item" style="background: #f9f9f9;">';
                html += '<div style="font-size: 32px; line-height: 1;">📁</div>';
                html += '<div class="file-info" onclick="navigateToFolder(\'' + fullPath.replace(/'/g, "\\'") + '\')" style="cursor: pointer;">';
                html += '<div class="file-name" style="font-weight: 600;">' + escapeHtml(folder);
                html += '<span class="file-type-badge" style="background:#e3f2fd;color:#1976d2">FOLDER</span>';
                html += '</div>';
                html += '<div class="file-meta" style="color: #999;">Click to open</div>';
                html += '</div>';
                
                if (isAuthenticated) {
                    html += '<div class="file-actions">';
                    html += '<button class="menu-btn" onclick="toggleContextMenu(event, \'folder-' + escapedName + '\'); return false;">⋮</button>';
                    
                    html += '<div class="context-menu" id="menu-folder-' + escapedName + '">';
                    html += '<div class="context-menu-item danger" onclick="deleteFolder(\'' + escapedName + '\')">Delete Folder</div>';
                    html += '</div>';
                    
                    html += '</div>';
                }
                html += '</div>';
            });
            
            // Render files
            files.forEach(f => {
                const fullFileName = currentPath ? currentPath + '/' + f.name : f.name;
                const rawUrl = window.location.origin + '/raw/' + encodeURIComponent(fullFileName);
                const escapedName = fullFileName.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                
                let typeBadge = f.type || 'file';
                let badgeStyle = '';

                switch(f.type) {
                    case 'text':
                        badgeStyle = 'background:#e8f5e9;color:#2e7d32';
                        break;
                    case 'image':
                        badgeStyle = 'background:#e3f2fd;color:#1976d2';
                        break;
                    case 'video':
                        badgeStyle = 'background:#fce4ec;color:#c2185b';
                        break;
                    case 'audio':
                        badgeStyle = 'background:#f3e5f5;color:#7b1fa2';
                        break;
                    case 'archive':
                        badgeStyle = 'background:#fff3e0;color:#f57c00';
                        break;
                    case 'document':
                        badgeStyle = 'background:#ffebee;color:#d32f2f';
                        break;
                    case 'font':
                        badgeStyle = 'background:#e0f2f1;color:#00695c';
                        break;
                    case '3d-model':
                        badgeStyle = 'background:#fce4ec;color:#880e4f';
                        break;
                    case 'certificate':
                        badgeStyle = 'background:#fff9c4;color:#f57f17';
                        break;
                    case 'database':
                        badgeStyle = 'background:#e1f5fe;color:#0277bd';
                        break;
                    case 'backup':
                        badgeStyle = 'background:#efebe9;color:#5d4037';
                        break;
                    default:
                        badgeStyle = 'background:#f5f5f5;color:#616161';
                }
                
                const modDate = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';
                const fileSize = f.size || 0;
                const isPublic = f.is_public || false;
                
                html += '<div class="file-item">';
                html += '<input type="checkbox" class="checkbox file-checkbox" onchange="toggleFileSelect(\'' + escapedName + '\', this)">';
                html += '<div class="file-info">';
                html += '<div class="file-name">' + escapeHtml(f.name);
                html += '<span class="file-type-badge" style="' + badgeStyle + '">' + typeBadge + '</span>';
                
                // Toggle switch cho Public/Private
                if (isAuthenticated) {
                    html += '<label class="toggle-switch" style="margin-left: 8px; vertical-align: middle;" onclick="event.stopPropagation();">';
                    html += '<input type="checkbox" ' + (isPublic ? 'checked' : '') + ' onchange="togglePublicAccessSwitch(\'' + escapedName + '\', this.checked)">';
                    html += '<span class="toggle-slider"></span>';
                    html += '</label>';
                } else {
                    if (isPublic) {
                        html += '<span class="file-type-badge" style="background:#4caf50;color:white;margin-left:4px">PUBLIC</span>';
                    } else {
                        html += '<span class="file-type-badge" style="background:#f44336;color:white;margin-left:4px">PRIVATE</span>';
                    }
                }
                
                html += '</div>';
                html += '<div class="file-meta">' + formatFileSize(fileSize) + ' • ' + modDate;
                if (f.download_count > 0) {
                    html += ' • ' + f.download_count + ' downloads';
                }
                html += '</div>';
                html += '<div class="file-link" onclick="copyLink(\'' + escapedName + '\')" title="Click to copy">' + escapeHtml(rawUrl) + '</div>';
                html += '</div>';
                
                html += '<div class="file-actions">';
                html += '<button class="menu-btn" onclick="toggleContextMenu(event, \'' + escapedName + '\'); return false;">⋮</button>';
                
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
        .catch(err => {
            console.error('Load error:', err);
            document.getElementById('filesSection').innerHTML = '<div class="empty-state">Error loading files. Please refresh the page.</div>';
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
            uploadBtn.textContent = 'Uploading...';
            startTime = Date.now();

            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percent = (e.loaded / e.total * 100).toFixed(1);
                    progressFill.style.width = percent + '%';
            
                    const elapsed = (Date.now() - startTime) / 1000;
                    const speed = elapsed > 0 ? (e.loaded / elapsed / 1024 / 1024).toFixed(2) : '0.00';
            
                    const remaining = e.total - e.loaded;
                    const eta = elapsed > 0 ? remaining / (e.loaded / elapsed) : 0;
                    const etaMin = Math.floor(eta / 60);
                    const etaSec = Math.floor(eta % 60);
            
                    let etaText = '';
                    if (eta < 60) {
                        etaText = ' • ETA: ' + etaSec + 's';
                    } else {
                        etaText = ' • ETA: ' + etaMin + 'm ' + etaSec + 's';
                    }
            
                    progressText.textContent = percent + '%' + etaText;
                    speedText.textContent = speed + ' MB/s • ' + Math.floor(elapsed) + 's elapsed';
                }
            });

            xhr.addEventListener('load', function() {
                if (xhr.status === 200) {
                    showToast('Upload complete - ' + files.length + ' file(s)', 'success');
                    fileInput.value = '';
                    selectedFilesDiv.style.display = 'none';
                    setTimeout(() => loadFiles(), 500);
                } else {
                    showToast('Upload failed: ' + xhr.statusText, 'error');
                }
                progressSection.style.display = 'none';
                progressFill.style.width = '0%';
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload';
            });

            xhr.addEventListener('error', function() {
                showToast('Upload error: Network or server issue', 'error');
                progressSection.style.display = 'none';
                progressFill.style.width = '0%';
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload';
            });

            const uploadUrl = currentPath ? '/upload?path=' + encodeURIComponent(currentPath) : '/upload';
            xhr.open('POST', uploadUrl);
            xhr.send(formData);
        }

        function viewFile(filename, type) {
            const url = addTokenToURL('/raw/' + encodeURIComponent(filename));
            const viewBody = document.getElementById('viewBody');
            
            document.getElementById('viewTitle').textContent = filename;
            
            if (type === 'text') {
                fetch(addTokenToURL('/view/' + encodeURIComponent(filename)))
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
                const streamUrl = addTokenToURL('/stream/' + encodeURIComponent(filename));
                viewBody.innerHTML = '<div class="media-viewer" style="background: #000;"><video controls autoplay playsinline webkit-playsinline style="width: 100%; max-height: 70vh;"><source src="' + streamUrl + '" type="video/mp4">Your browser does not support video playback.</video></div>';
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
            
            function setTransform() {
                inner.style.transform = 'translate(' + pointX + 'px, ' + pointY + 'px) scale(' + scale + ')';
            }
            
            img.addEventListener('click', function(e) {
                e.stopPropagation();
                
                if (scale === 1) {
                    scale = 2;
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
            });
            
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
    fetch(addTokenToURL('/edit/' + encodeURIComponent(filename)))
        .then(r => r.text())
        .then(content => {
            document.getElementById('editTitle').textContent = filename;
            document.getElementById('editContent').value = content;
            document.getElementById('editModal').style.display = 'block';
        });
}

function downloadFile(filename) {
    const url = addTokenToURL('/download/' + encodeURIComponent(filename));
    window.location.href = url;
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
	
	// Get current path from query parameter
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

		// Create file in the current path
		targetPath := filepath.Join(publicDir, currentPath, fileHeader.Filename)
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
		if debug {
			log.Printf("Uploaded: %s (%d bytes)", targetPath, written)
		}
	}

	updateStats()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("%d file(s) uploaded", uploadedCount)))
}

func handleListFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	dirPath := filepath.Join(publicDir, path)
	
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
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
	
	files, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}
	
	type FileMetadataWithPermission struct {
		FileMetadata
		IsPublic bool `json:"is_public"`
	}
	
	var fileList []FileMetadataWithPermission
	var folders []string
	
	for _, file := range files {
		if file.IsDir() {
			folders = append(folders, file.Name())
		} else {
			info, _ := file.Info()
			fullPath := filepath.Join(path, file.Name())
			permissionMu.RLock()
			perm, exists := filePermissions[fullPath]
			isPublic := exists && perm.IsPublic
			permissionMu.RUnlock()
			if !isPublic && !isAuth {
				continue
			}
			
			downloadMu.RLock()
			count := downloadCounts[fullPath]
			downloadMu.RUnlock()
			
			fileList = append(fileList, FileMetadataWithPermission{
				FileMetadata: FileMetadata{
					Name:          file.Name(),
					Type:          getFileType(file.Name()),
					Size:          info.Size(),
					ModTime:       info.ModTime(),
					DownloadCount: count,
				},
				IsPublic: isPublic,
			})
		}
	}

	response := map[string]interface{}{
		"files":   fileList,
		"folders": folders,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleView(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/view/"):]
	filePath := filepath.Join(publicDir, filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		renderErrorPage(w, http.StatusNotFound,
			"File Not Found",
			"The file you're trying to view doesn't exist.",
			"File: " + filename)
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
	renderErrorPage(w, http.StatusNotFound, 
        "File Not Found", 
        "The file you're looking for doesn't exist.",
        "Path: " + r.URL.Path)
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
func handleFavicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "favicon.ico")
}
func renderErrorPage(w http.ResponseWriter, statusCode int, title, message, details string) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>` + fmt.Sprintf("%d", statusCode) + ` - ` + title + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #000;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        .error-container {
            max-width: 600px;
            text-align: center;
        }
        .error-code {
            font-size: 120px;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .error-title {
            font-size: 32px;
            font-weight: 600;
            margin-bottom: 16px;
            color: #fff;
        }
        .error-message {
            font-size: 18px;
            color: #999;
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .error-details {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 32px;
            text-align: left;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 13px;
            color: #ff6b6b;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .error-actions {
            display: flex;
            gap: 12px;
            justify-content: center;
            flex-wrap: wrap;
        }
        .btn {
            padding: 12px 24px;
            background: #fff;
            color: #000;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            font-size: 14px;
            transition: all 0.2s;
            border: 2px solid #fff;
        }
        .btn:hover {
            background: transparent;
            color: #fff;
        }
        .btn-secondary {
            background: transparent;
            color: #fff;
            border: 2px solid #333;
        }
        .btn-secondary:hover {
            border-color: #666;
            background: #1a1a1a;
        }
        @media (max-width: 768px) {
            .error-code {
                font-size: 80px;
            }
            .error-title {
                font-size: 24px;
            }
            .error-message {
                font-size: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">` + fmt.Sprintf("%d", statusCode) + `</div>
        <h1 class="error-title">` + title + `</h1>
        <p class="error-message">` + message + `</p>
        ` + func() string {
			if details != "" {
				return `<div class="error-details">` + details + `</div>`
			}
			return ""
		}() + `
        <div class="error-actions">
            <a href="/" class="btn">Go Home</a>
            <a href="javascript:history.back()" class="btn btn-secondary">Go Back</a>
        </div>
    </div>
</body>
</html>`
	
	w.Write([]byte(html))
}
