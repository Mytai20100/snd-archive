package snd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// HandleCSSFile serves static files from web/css/ using WorkDir for absolute path.
func HandleCSSFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/css/")
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		http.NotFound(w, r)
		return
	}

	data, err := os.ReadFile(filepath.Join(WorkDir, "web", "css", filepath.Clean(name)))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var ct string
	switch {
	case strings.HasSuffix(name, ".css"):
		ct = "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		ct = "application/javascript; charset=utf-8"
	default:
		ct = "text/plain; charset=utf-8"
	}

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
