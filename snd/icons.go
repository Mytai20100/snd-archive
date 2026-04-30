package snd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ─── Icon Config ──────────────────────────────────────────────────────────────

type IconConfig struct {
	TypeDefault  string            `yaml:"type_default"`
	TypeFolder   string            `yaml:"type_folder"`
	TypeImage    string            `yaml:"type_image"`
	TypeVideo    string            `yaml:"type_video"`
	TypeAudio    string            `yaml:"type_audio"`
	TypeText     string            `yaml:"type_text"`
	TypeArchive  string            `yaml:"type_archive"`
	TypeDocument string            `yaml:"type_document"`
	TypeFont     string            `yaml:"type_font"`
	TypeDatabase string            `yaml:"type_database"`
	Extensions   map[string]string `yaml:"extensions"`
}

var (
	IconCfg     IconConfig
	IconsDir    = "icons"
	builtinSVGs = map[string]string{
		"file":     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
		"folder":   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
		"image":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
		"video":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2"/></svg>`,
		"audio":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>`,
		"text":     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
		"code":     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
		"archive":  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>`,
		"document": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>`,
		"font":     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/></svg>`,
		"database": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
	}
)

func LoadIconConfig() {
	IconCfg = IconConfig{
		TypeDefault:  "file",
		TypeFolder:   "folder",
		TypeImage:    "image",
		TypeVideo:    "video",
		TypeAudio:    "audio",
		TypeText:     "text",
		TypeArchive:  "archive",
		TypeDocument: "document",
		TypeFont:     "font",
		TypeDatabase: "database",
		Extensions:   make(map[string]string),
	}
	data, err := os.ReadFile(filepath.Join(IconsDir, "config.yml"))
	if err == nil {
		yaml.Unmarshal(data, &IconCfg)
	}
}

// GetIconName returns the icon name for a given filename.
func GetIconName(filename string, isFolder bool) string {
	if isFolder {
		return IconCfg.TypeFolder
	}
	ext := strings.ToLower(filepath.Ext(filename))
	if icon, ok := IconCfg.Extensions[ext]; ok {
		return icon
	}
	// fall back to type
	ftype := GetFileType(filename)
	switch ftype {
	case "image":
		return IconCfg.TypeImage
	case "video":
		return IconCfg.TypeVideo
	case "audio":
		return IconCfg.TypeAudio
	case "text":
		return IconCfg.TypeText
	case "archive":
		return IconCfg.TypeArchive
	case "document":
		return IconCfg.TypeDocument
	case "font":
		return IconCfg.TypeFont
	case "database":
		return IconCfg.TypeDatabase
	}
	return IconCfg.TypeDefault
}

// GetIconSVG returns the SVG string for a given icon name.
func GetIconSVG(name string) string {
	// Try custom file first
	customPath := filepath.Join(IconsDir, name+".svg")
	if data, err := os.ReadFile(customPath); err == nil {
		return string(data)
	}
	// Fall back to built-in
	if svg, ok := builtinSVGs[name]; ok {
		return svg
	}
	return builtinSVGs["file"]
}

// HandleIconFile serves SVG files from the icons/ directory.
func HandleIconFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/icons/")
	name = strings.TrimSuffix(name, ".svg")
	// sanitize
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	svg := GetIconSVG(name)
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(svg))
}
