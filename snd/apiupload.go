package snd

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func resolveAPIActor(token string) (uploadActor, bool) {
	if token == "" {
		return uploadActor{}, false
	}
	if tokenEqual(token, Cfg.APIToken) {
		return uploadActor{baseDir: PublicDir, owner: Cfg.Username}, true
	}
	if u := GetUserByToken(token); u != nil {
		return uploadActor{baseDir: UserPublicDir(u.UUID), user: u, owner: u.Username}, true
	}
	return uploadActor{}, false
}

func apiNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 page not found\n"))
}

const (
	apiAuthFailThreshold = 8
	apiAuthFailWindow    = 10 * time.Minute
	apiAuthBanDuration   = 30 * time.Minute
)

var (
	apiAuthFails   = make(map[string][]time.Time)
	apiAuthFailsMu sync.Mutex
)

func apiNoteAuthFailure(r *http.Request, reason string) {
	ip := GetClientIP(r)
	AppendSecurityEvent(ip, SecEvtAPIKeyFail, reason, "")

	now := time.Now()
	cutoff := now.Add(-apiAuthFailWindow)
	apiAuthFailsMu.Lock()
	times := apiAuthFails[ip]
	pruned := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	pruned = append(pruned, now)
	apiAuthFails[ip] = pruned
	count := len(pruned)
	if len(apiAuthFails) > 4096 {
		for k, v := range apiAuthFails {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(apiAuthFails, k)
			}
		}
	}
	apiAuthFailsMu.Unlock()

	if count < apiAuthFailThreshold {
		return
	}
	RecordTrafficAnomaly()
	DDoSBansMu.Lock()
	DDoSBans[ip] = &DDoSBannedIP{
		IP:        ip,
		BannedAt:  now,
		ExpiresAt: now.Add(apiAuthBanDuration),
		HitCount:  count,
		Reason:    "Repeated API key upload auth failures (key guessing)",
	}
	DDoSBansMu.Unlock()
	apiAuthFailsMu.Lock()
	delete(apiAuthFails, ip)
	apiAuthFailsMu.Unlock()
	go saveDDoSBans()
}

func cleanAPIPath(raw string) (string, bool) {
	p := strings.TrimSpace(raw)
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" || p == "." {
		return "", true
	}
	if strings.HasPrefix(p, "/") {
		return "", false
	}
	if len(p) > 1 && p[1] == ':' {
		return "", false
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", false
		}
		out = append(out, seg)
	}
	cleaned := strings.Join(out, "/")
	if cleaned == "" {
		return "", true
	}
	if isUUIDDir(strings.Split(cleaned, "/")[0]) {
		return "", false
	}
	return cleaned, true
}

func safeAPIPath(base, rel string) (string, bool) {
	full, ok := safePath(base, rel)
	if !ok {
		return "", false
	}
	resolvedBase, err1 := filepath.EvalSymlinks(base)
	resolvedFull, err2 := filepath.EvalSymlinks(full)
	if err1 == nil && err2 == nil {
		if resolvedFull != resolvedBase && !strings.HasPrefix(resolvedFull, resolvedBase+string(filepath.Separator)) {
			return "", false
		}
	}
	parentResolved, err3 := filepath.EvalSymlinks(filepath.Dir(full))
	if err3 != nil && !os.IsNotExist(err3) {
		return "", false
	}
	if err3 == nil {
		baseAbs, _ := filepath.Abs(base)
		parentAbs, _ := filepath.Abs(parentResolved)
		if parentAbs != baseAbs && !strings.HasPrefix(parentAbs, baseAbs+string(filepath.Separator)) {
			return "", false
		}
	}
	return full, true
}

func HandleAPIUpload(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-API-Token")
	actor, ok := resolveAPIActor(token)
	if !ok {
		apiNoteAuthFailure(r, "invalid key")
		apiNotFound(w)
		return
	}

	switch r.Method {
	case http.MethodPost, http.MethodPut:
	default:
		apiNotFound(w)
		return
	}

	relPath, pathOK := cleanAPIPath(r.URL.Query().Get("path"))
	if !pathOK {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")
	mediaType, params, cerr := mime.ParseMediaType(contentType)
	isMultipart := cerr == nil && strings.HasPrefix(mediaType, "multipart/")

	var stored []string
	var totalBytes int64

	q := r.URL.Query()
	_, hasOffset := q["offset"]
	_, hasTotal := q["total"]
	_, hasFinal := q["final"]
	chunkMode := hasOffset || hasTotal || hasFinal
	reqName := strings.TrimSpace(q.Get("filename"))

	switch {
	case isMultipart:
		var perr error
		stored, totalBytes, perr = apiUploadMultipart(w, r, actor, relPath, params["boundary"])
		if perr != nil {
			http.Error(w, perr.Error(), http.StatusBadRequest)
			return
		}
	case !chunkMode && reqName != "":
		name := filepath.Base(reqName)
		if strings.Contains(name, "..") || name == "." {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		total := r.ContentLength
		if total < 0 {
			total = 0
		}
		out, cerr := apiStoreChunk(actor, relPath, name, 0, total, true, q.Get("action"), r.Body)
		if cerr != nil {
			http.Error(w, cerr.Error(), cerrStatus(cerr))
			return
		}
		stored = append(stored, out.name)
		totalBytes = out.size
	default:
		name := filepath.Base(reqName)
		if strings.Contains(name, "..") || name == "" || name == "." {
			http.Error(w, "missing filename", http.StatusBadRequest)
			return
		}
		out, cerr := apiStoreChunk(actor, relPath, name, parseInt64Query(r, "offset"), parseInt64Query(r, "total"), q.Get("final") == "1", q.Get("action"), r.Body)
		if cerr != nil {
			http.Error(w, cerr.Error(), cerrStatus(cerr))
			return
		}
		if out.name != "" {
			stored = append(stored, out.name)
		}
		totalBytes = out.size
	}

	LogAccess(GetClientIP(r), "api-upload", "/up", r.UserAgent(), "")

	respPath := relPath
	if respPath == "" {
		respPath = "."
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"owner":     actor.owner,
		"is_admin":  actor.user == nil,
		"filenames": stored,
		"path":      respPath,
		"size":      totalBytes,
	})
}

func cerrStatus(err error) int {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "quota"):
		return http.StatusInsufficientStorage
	case strings.Contains(msg, "offset"):
		return http.StatusRequestedRangeNotSatisfiable
	case strings.Contains(msg, "Size mismatch"):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

type apiChunkResult struct {
	name string
	size int64
}

func apiUploadMultipart(w http.ResponseWriter, r *http.Request, actor uploadActor, relPath, boundary string) ([]string, int64, error) {
	if boundary == "" {
		return nil, 0, fmt.Errorf("missing multipart boundary")
	}
	if err := actor.ensureDir(); err != nil {
		return nil, 0, fmt.Errorf("cannot prepare storage")
	}
	mr := multipart.NewReader(r.Body, boundary)
	var stored []string
	var total int64
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		name := part.FileName()
		if name == "" {
			part.Close()
			continue
		}
		name = filepath.Base(strings.TrimSpace(name))
		if strings.Contains(name, "..") || name == "" || name == "." {
			part.Close()
			continue
		}
		target, ok := safeAPIPath(actor.baseDir, filepath.Join(relPath, name))
		if !ok {
			part.Close()
			return nil, total, fmt.Errorf("invalid path")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			part.Close()
			return nil, total, fmt.Errorf("cannot create directory")
		}
		remaining := actor.quotaRemaining()
		if remaining == 0 {
			part.Close()
			return nil, total, fmt.Errorf("Storage quota exceeded")
		}
		dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			part.Close()
			return nil, total, fmt.Errorf("cannot create file")
		}
		var src io.Reader = part
		if remaining > 0 {
			src = io.LimitReader(part, remaining+1)
		}
		written, cerr := io.Copy(dst, src)
		dst.Close()
		part.Close()
		if cerr != nil {
			os.Remove(target)
			return nil, total, fmt.Errorf("write error")
		}
		if remaining > 0 && written > remaining {
			os.Remove(target)
			return nil, total, fmt.Errorf("Storage quota exceeded")
		}
		total += written
		stored = append(stored, name)
		RecordUploadBytesNamed(written, name)
	}
	if actor.user != nil {
		recalc := CalcUserStorage(actor.user.UUID)
		UsersMu.Lock()
		actor.user.UsedStorage = recalc
		UsersMu.Unlock()
		go SaveUsers()
	}
	UpdateStats()
	return stored, total, nil
}

func apiStoreChunk(actor uploadActor, relPath, name string, offset, total int64, final bool, action string, body io.Reader) (apiChunkResult, error) {
	out := apiChunkResult{}
	if strings.Contains(name, "..") {
		return out, fmt.Errorf("invalid filename")
	}
	if err := actor.ensureDir(); err != nil {
		return out, fmt.Errorf("cannot prepare storage")
	}
	target, ok := safeAPIPath(actor.baseDir, filepath.Join(relPath, name))
	if !ok {
		return out, fmt.Errorf("invalid path")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return out, fmt.Errorf("cannot create directory")
	}
	tmpPath := target + ".upload_tmp"

	var curSize int64
	if st, err := os.Stat(tmpPath); err == nil {
		curSize = st.Size()
	}

	if offset == 0 {
		os.Remove(tmpPath)
		curSize = 0
		if actor.user != nil && actor.user.StorageLimit > 0 && total > 0 {
			used := CalcUserStorage(actor.user.UUID)
			if used+total > actor.user.StorageLimit {
				return out, fmt.Errorf("Storage quota exceeded")
			}
		}
	} else if curSize < offset {
		return out, fmt.Errorf("offset beyond uploaded data")
	} else if curSize > offset {
		if !final {
			out.name = name
			out.size = curSize
			return out, nil
		}
		if _, err := os.Stat(target); err == nil {
			out.name = name
			out.size = curSize
			return out, nil
		}
	}

	flag := os.O_WRONLY | os.O_CREATE
	if offset == 0 {
		flag |= os.O_TRUNC
	}
	f, err := os.OpenFile(tmpPath, flag, 0644)
	if err != nil {
		return out, fmt.Errorf("cannot open file for writing")
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return out, fmt.Errorf("seek error")
	}
	var limit int64 = -1
	if actor.user != nil && actor.user.StorageLimit > 0 {
		if remaining := actor.quotaRemaining(); remaining > 0 {
			limit = remaining
		}
	}
	var src io.Reader = body
	if limit >= 0 {
		src = io.LimitReader(body, limit+1)
	}
	written, cerr := io.Copy(f, src)
	f.Close()
	if cerr != nil {
		return out, fmt.Errorf("write error")
	}
	if limit >= 0 && written > limit {
		os.Remove(tmpPath)
		return out, fmt.Errorf("Storage quota exceeded")
	}
	if written > 0 {
		RecordUploadBytesNamed(written, name)
	}

	if !final {
		out.name = name
		if st, err := os.Stat(tmpPath); err == nil {
			out.size = st.Size()
		}
		return out, nil
	}

	st, err := os.Stat(tmpPath)
	if err != nil {
		return out, fmt.Errorf("finalize error")
	}
	if total > 0 && st.Size() != total {
		os.Remove(tmpPath)
		return out, fmt.Errorf("Size mismatch: expected %d got %d", total, st.Size())
	}
	finalName := name
	if action == "rename" {
		ext := filepath.Ext(target)
		base := target[:len(target)-len(ext)]
		for i := 1; i < 1000; i++ {
			candidate := fmt.Sprintf("%s (%d)%s", base, i, ext)
			if _, err := os.Stat(candidate); os.IsNotExist(err) {
				target = candidate
				finalName = filepath.Base(candidate)
				break
			}
		}
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return out, fmt.Errorf("finalize error")
	}
	if actor.user != nil {
		recalc := CalcUserStorage(actor.user.UUID)
		UsersMu.Lock()
		actor.user.UsedStorage = recalc
		actor.user.RequestCount++
		UsersMu.Unlock()
		go SaveUsers()
	}
	UpdateStats()
	out.name = finalName
	out.size = st.Size()
	return out, nil
}
