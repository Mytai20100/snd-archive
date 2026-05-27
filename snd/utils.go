package snd

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func FormatBytes(bytes int64) string {
	const unit = 1024
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	val := float64(bytes)
	exp := 0
	for val >= unit && exp < len(units)-1 {
		val /= unit
		exp++
	}
	// If value rounds to >= 1000, promote to next unit to avoid e.g. "1002.89 KB"
	if val >= 999.995 && exp < len(units)-1 {
		val /= unit
		exp++
	}
	// Use up to 2 decimal places but strip trailing zeros
	s := fmt.Sprintf("%.2f", val)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
	}
	return s + " " + units[exp]
}

func UpdateStats() {
	var size int64
	var count int64
	// Walk recursively but skip per-user UUID subdirectories at the top level.
	// Those are accounted for separately via CalcUserStorage.
	topEntries, _ := os.ReadDir(PublicDir)
	for _, entry := range topEntries {
		if entry.IsDir() && isUUIDDir(entry.Name()) {
			// skip user subdirs — they belong to sub-user accounts
			continue
		}
		fullPath := filepath.Join(PublicDir, entry.Name())
		if entry.IsDir() {
			filepath.WalkDir(fullPath, func(_ string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				info, err := d.Info()
				if err == nil {
					size += info.Size()
					count++
				}
				return nil
			})
		} else {
			info, err := entry.Info()
			if err == nil {
				size += info.Size()
				count++
			}
		}
	}
	GlobalStatsMu.Lock()
	GlobalStats.TotalFiles = count
	GlobalStats.TotalSize = size
	GlobalStatsMu.Unlock()
}

func GetClientIP(r *http.Request) string {
	// HIGH-1 FIX: Only trust X-Forwarded-For / X-Real-IP when TrustedProxy is enabled.
	// Without this, attackers can spoof their IP to bypass DDoS bans and brute-force protection.
	if Cfg.TrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			// Take the LAST IP (appended by the trusted proxy), not the first (client-controlled).
			return strings.TrimSpace(ips[len(ips)-1])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func ParseUserAgent(ua string) (osName, browser string) {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "windows") {
		osName = "Windows"
	} else if strings.Contains(ua, "mac os") || strings.Contains(ua, "macos") {
		osName = "macOS"
	} else if strings.Contains(ua, "linux") {
		osName = "Linux"
	} else if strings.Contains(ua, "android") {
		osName = "Android"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		osName = "iOS"
	} else {
		osName = "Unknown"
	}
	if strings.Contains(ua, "edg/") {
		browser = "Edge"
	} else if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg") {
		browser = "Chrome"
	} else if strings.Contains(ua, "firefox") {
		browser = "Firefox"
	} else if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		browser = "Safari"
	} else if strings.Contains(ua, "opera") || strings.Contains(ua, "opr/") {
		browser = "Opera"
	} else {
		browser = "Unknown"
	}
	return
}

func ExtractFilename(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func LogAccess(ip, action, path, userAgent string) {
	if Debug {
		log.Printf("[ACCESS] IP=%s Action=%s Path=%s UA=%s\n", ip, action, path, userAgent)
	}
	AccessLogMu.Lock()
	AccessLogs = append(AccessLogs, AccessLog{
		Timestamp: time.Now(),
		IP:        ip,
		Action:    action,
		Path:      path,
		UserAgent: userAgent,
	})
	if len(AccessLogs) > 1000 {
		AccessLogs = AccessLogs[len(AccessLogs)-1000:]
	}
	AccessLogMu.Unlock()
	go SaveAccessLogs()
}

func LoadDownloadCounts() {
	data, err := os.ReadFile("download_counts.json")
	if err == nil {
		json.Unmarshal(data, &DownloadCounts)
	}
}

func SaveDownloadCounts() {
	DownloadMu.RLock()
	data, _ := json.Marshal(DownloadCounts)
	DownloadMu.RUnlock()
	os.WriteFile("download_counts.json", data, 0644)
}

func LoadFilePermissions() {
	data, err := os.ReadFile("file_permissions.json")
	if err == nil {
		json.Unmarshal(data, &FilePermissions)
	}
}

func SaveFilePermissions() {
	PermissionMu.RLock()
	data, _ := json.Marshal(FilePermissions)
	PermissionMu.RUnlock()
	os.WriteFile("file_permissions.json", data, 0644)
}

func LoadFolderPermissions() {
	data, err := os.ReadFile("folder_permissions.json")
	if err == nil {
		json.Unmarshal(data, &FolderPermissions)
	}
}

func SaveFolderPermissions() {
	PermissionMu.RLock()
	data, _ := json.Marshal(FolderPermissions)
	PermissionMu.RUnlock()
	os.WriteFile("folder_permissions.json", data, 0644)
}

func LoadAccessLogs() {
	data, err := os.ReadFile("access_logs.json")
	if err == nil {
		json.Unmarshal(data, &AccessLogs)
	}
}

func SaveAccessLogs() {
	AccessLogMu.RLock()
	data, _ := json.Marshal(AccessLogs)
	AccessLogMu.RUnlock()
	os.WriteFile("access_logs.json", data, 0644)
}

func GetFileType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	// HLS/transport stream — check before text to avoid .m3u8 being missed
	if ext == ".m3u8" {
		return "video"
	}
	if ext == "" {
		noExtTextFiles := []string{
			"makefile", "dockerfile", "rakefile", "gemfile", "procfile",
			"readme", "license", "authors", "changelog", "contributing",
			"manifest", "jenkinsfile", "vagrantfile",
		}
		lowerName := strings.ToLower(filename)
		for _, name := range noExtTextFiles {
			if lowerName == name || strings.HasPrefix(lowerName, name) {
				return "text"
			}
		}
	}
	textExts := []string{
		".txt", ".log", ".md", ".markdown", ".json", ".xml", ".html", ".htm", ".css", ".js",
		".jsx", ".ts", ".tsx", ".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg", ".config",
		".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1",
		".py", ".go", ".java", ".c", ".cpp", ".h", ".hpp",
		".php", ".rb", ".rs", ".sql", ".sqlite", ".db",
		".swift", ".kt", ".scala", ".groovy", ".r", ".lua",
		".dockerfile", ".makefile", ".cmake", ".proto",
		".graphql", ".vue", ".svelte", ".dart", ".ex", ".exs",
		".diff", ".patch", ".gitignore", ".env", ".properties",
		".csv", ".tsv",
	}
	for _, e := range textExts {
		if ext == e {
			return "text"
		}
	}
	imageExts := []string{
		".jpg", ".jpeg", ".jfif", ".jpe", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
		".tif", ".tiff", ".psd", ".ai", ".eps", ".raw", ".heic", ".avif",
	}
	for _, e := range imageExts {
		if ext == e {
			return "image"
		}
	}
	videoExts := []string{
		".mp4", ".webm", ".ogg", ".mov", ".avi", ".mkv", ".flv", ".wmv",
		".mpg", ".mpeg", ".3gp", ".vob", ".ts", ".m2ts", ".m3u8",
	}
	for _, e := range videoExts {
		if ext == e {
			return "video"
		}
	}
	audioExts := []string{
		".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".wma", ".aiff",
		".ape", ".mid", ".midi",
	}
	for _, e := range audioExts {
		if ext == e {
			return "audio"
		}
	}
	archiveExts := []string{
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst",
		".cab", ".iso", ".dmg", ".deb", ".rpm", ".apk",
	}
	for _, e := range archiveExts {
		if ext == e {
			return "archive"
		}
	}
	documentExts := []string{
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".odt", ".ods", ".odp", ".rtf", ".tex", ".epub",
	}
	for _, e := range documentExts {
		if ext == e {
			return "document"
		}
	}
	return "binary"
}

func IsTextContent(content []byte) bool {
	if len(content) == 0 {
		return true
	}
	for i := 0; i < len(content) && i < 8192; i++ {
		if content[i] == 0 {
			return false
		}
	}
	printableCount := 0
	sampleSize := len(content)
	if sampleSize > 8192 {
		sampleSize = 8192
	}
	for i := 0; i < sampleSize; i++ {
		b := content[i]
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}
	return float64(printableCount)/float64(sampleSize) > 0.95
}

func DetectFileType(filename string, content []byte) string {
	fileType := GetFileType(filename)
	if filepath.Ext(filename) == "" || fileType == "binary" {
		if IsTextContent(content) {
			return "text"
		}
		if len(content) >= 4 {
			if content[0] == 0x89 && content[1] == 0x50 {
				return "image"
			}
			if content[0] == 0xFF && content[1] == 0xD8 {
				return "image"
			}
			if content[0] == 0x47 && content[1] == 0x49 {
				return "image"
			}
			if content[0] == 0x25 && content[1] == 0x50 {
				return "document"
			}
			if content[0] == 0x50 && content[1] == 0x4B {
				return "archive"
			}
		}
	}
	return fileType
}

func RenderErrorPage(w http.ResponseWriter, statusCode int, title, message, details string) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	detailsHTML := ""
	if details != "" {
		detailsHTML = `<div class="error-details">` + details + `</div>`
	}
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>%d - %s</title>
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
        .error-container { max-width: 600px; text-align: center; }
        .error-code {
            font-size: 120px;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .error-title { font-size: 32px; font-weight: 600; margin-bottom: 16px; }
        .error-message { font-size: 18px; color: #999; margin-bottom: 24px; line-height: 1.6; }
        .error-details {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 32px;
            font-family: monospace;
            font-size: 13px;
            color: #ff6b6b;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            text-align: left;
        }
        .error-actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
        .btn {
            padding: 12px 24px;
            background: #fff;
            color: #000;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            font-size: 14px;
            border: 2px solid #fff;
        }
        .btn:hover { background: transparent; color: #fff; }
        .btn-secondary { background: transparent; color: #fff; border: 2px solid #333; }
        .btn-secondary:hover { border-color: #666; background: #1a1a1a; }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">%d</div>
        <h1 class="error-title">%s</h1>
        <p class="error-message">%s</p>
        %s
        <div class="error-actions">
            <a href="/" class="btn">Go Home</a>
            <a href="javascript:history.back()" class="btn btn-secondary">Go Back</a>
        </div>
    </div>
</body>
</html>`, statusCode, title, statusCode, title, message, detailsHTML)
	w.Write([]byte(html))
}
