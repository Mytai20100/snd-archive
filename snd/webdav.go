package snd

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HandleWebDAV is the main WebDAV handler at /dav/
// Authentication: HTTP Basic Auth (admin username/password from config, or sub-user creds)
// Scope: Admin sees public/, sub-user sees public/<uuid>/
func HandleWebDAV(w http.ResponseWriter, r *http.Request) {
	// HTTP Basic Auth
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="snd-archive WebDAV"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	isAdmin := username == Cfg.Username && password == Cfg.Password
	var davUser *UserAccount
	if !isAdmin {
		u := GetUserByUsername(username)
		if u == nil || !u.IsActive || !CheckPassword(u.PasswordHash, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="snd-archive WebDAV"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		davUser = u
	}

	// Determine filesystem root for this user
	var fsRoot string
	if isAdmin {
		fsRoot = PublicDir
	} else {
		fsRoot = UserPublicDir(davUser.UUID)
		if err := EnsureUserDir(davUser.UUID); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Strip /dav prefix to get the resource path
	resourcePath := strings.TrimPrefix(r.URL.Path, "/dav")
	if resourcePath == "" {
		resourcePath = "/"
	}

	// Clean and join
	cleanPath := filepath.Clean(resourcePath)
	if strings.Contains(cleanPath, "..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	fullPath := filepath.Join(fsRoot, cleanPath)

	// Add WebDAV compliance headers to all responses
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	w.Header().Set("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK")

	switch r.Method {
	case "OPTIONS":
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)

	case "PROPFIND":
		davPropfind(w, r, fullPath, resourcePath, fsRoot)

	case "GET", "HEAD":
		davGet(w, r, fullPath)

	case "PUT":
		davPut(w, r, fullPath, davUser)

	case "DELETE":
		davDelete(w, r, fullPath)

	case "MKCOL":
		davMkcol(w, r, fullPath)

	case "COPY":
		davCopyMove(w, r, fullPath, fsRoot, false)

	case "MOVE":
		davCopyMove(w, r, fullPath, fsRoot, true)

	case "LOCK":
		// Return a fake lock (needed for Windows WebDAV write support)
		davLock(w, r)

	case "UNLOCK":
		w.WriteHeader(http.StatusNoContent)

	case "PROPPATCH":
		// Return 207 with success (we don't actually store custom props)
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"></D:multistatus>`)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// ─── PROPFIND ────────────────────────────────────────────────────────────────

type davPropfindResp struct {
	XMLName   xml.Name    `xml:"D:multistatus"`
	XMLNS     string      `xml:"xmlns:D,attr"`
	Responses []davRespEl `xml:"D:response"`
}

type davRespEl struct {
	Href     string      `xml:"D:href"`
	Propstat davPropstat `xml:"D:propstat"`
}

type davPropstat struct {
	Prop   davProp `xml:"D:prop"`
	Status string  `xml:"D:status"`
}

type davProp struct {
	DisplayName     string        `xml:"D:displayname"`
	ContentLength   string        `xml:"D:getcontentlength,omitempty"`
	LastModified    string        `xml:"D:getlastmodified"`
	ContentType     string        `xml:"D:getcontenttype,omitempty"`
	ResourceType    *davResType   `xml:"D:resourcetype"`
	ETag            string        `xml:"D:getetag,omitempty"`
	CreationDate    string        `xml:"D:creationdate"`
	SupportedLock   *davSuppLock  `xml:"D:supportedlock"`
}

type davResType struct {
	Collection *struct{} `xml:"D:collection"`
}

type davSuppLock struct {
	LockEntry davLockEntry `xml:"D:lockentry"`
}

type davLockEntry struct {
	LockScope davLockScope `xml:"D:lockscope"`
	LockType  davLockType  `xml:"D:locktype"`
}

type davLockScope struct {
	Exclusive *struct{} `xml:"D:exclusive"`
}

type davLockType struct {
	Write *struct{} `xml:"D:write"`
}

func davPropfind(w http.ResponseWriter, r *http.Request, fullPath, resourcePath, fsRoot string) {
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	var responses []davRespEl

	// Add the resource itself
	href := "/dav" + resourcePath
	if !strings.HasSuffix(href, "/") && info.IsDir() {
		href += "/"
	}
	responses = append(responses, makeDAVResponse(href, info))

	// If depth=1 and it's a directory, list children
	if depth != "0" && info.IsDir() {
		children, err := os.ReadDir(fullPath)
		if err == nil {
			for _, child := range children {
				childHref := href + child.Name()
				childInfo, err := child.Info()
				if err != nil {
					continue
				}
				if child.IsDir() {
					childHref += "/"
				}
				responses = append(responses, makeDAVResponse(childHref, childInfo))
			}
		}
	}

	resp := davPropfindResp{
		XMLNS:     "DAV:",
		Responses: responses,
	}

	out, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	w.Write([]byte(xml.Header))
	w.Write(out)
}

func makeDAVResponse(href string, info os.FileInfo) davRespEl {
	modTime := info.ModTime().UTC().Format(time.RFC1123)
	createDate := info.ModTime().UTC().Format(time.RFC3339)

	prop := davProp{
		DisplayName:  info.Name(),
		LastModified: modTime,
		CreationDate: createDate,
		SupportedLock: &davSuppLock{
			LockEntry: davLockEntry{
				LockScope: davLockScope{Exclusive: &struct{}{}},
				LockType:  davLockType{Write: &struct{}{}},
			},
		},
	}

	if info.IsDir() {
		prop.ResourceType = &davResType{Collection: &struct{}{}}
		prop.ContentType = "httpd/unix-directory"
	} else {
		prop.ResourceType = &davResType{}
		prop.ContentLength = fmt.Sprintf("%d", info.Size())
		prop.ContentType = "application/octet-stream"
		prop.ETag = fmt.Sprintf(`"%x-%x"`, info.ModTime().Unix(), info.Size())
	}

	return davRespEl{
		Href: href,
		Propstat: davPropstat{
			Prop:   prop,
			Status: "HTTP/1.1 200 OK",
		},
	}
}

// ─── GET/HEAD ────────────────────────────────────────────────────────────────

func davGet(w http.ResponseWriter, r *http.Request, fullPath string) {
	info, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if info.IsDir() {
		// Return simple directory listing XML
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		return
	}
	f, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// ─── PUT ─────────────────────────────────────────────────────────────────────

func davPut(w http.ResponseWriter, r *http.Request, fullPath string, u *UserAccount) {
	// Check quota
	if u != nil && u.StorageLimit > 0 {
		used := CalcUserStorage(u.UUID)
		if used >= u.StorageLimit {
			http.Error(w, "Insufficient Storage", http.StatusInsufficientStorage)
			return
		}
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, existed := os.Stat(fullPath)
	f, err := os.Create(fullPath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	written, _ := io.Copy(f, r.Body)

	if u != nil {
		UsersMu.Lock()
		u.UsedStorage = CalcUserStorage(u.UUID)
		u.RequestCount++
		UsersMu.Unlock()
		go SaveUsers()
	}

	if os.IsNotExist(existed) {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
	_ = written
}

// ─── DELETE ──────────────────────────────────────────────────────────────────

func davDelete(w http.ResponseWriter, r *http.Request, fullPath string) {
	err := os.RemoveAll(fullPath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── MKCOL ───────────────────────────────────────────────────────────────────

func davMkcol(w http.ResponseWriter, r *http.Request, fullPath string) {
	if _, err := os.Stat(fullPath); err == nil {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := os.Mkdir(fullPath, 0755); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Conflict", http.StatusConflict)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// ─── COPY/MOVE ───────────────────────────────────────────────────────────────

func davCopyMove(w http.ResponseWriter, r *http.Request, srcPath, fsRoot string, isMove bool) {
	destHeader := r.Header.Get("Destination")
	if destHeader == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Extract path from full URL in Destination header
	destURL := destHeader
	davPrefix := "/dav"
	if idx := strings.Index(destURL, davPrefix); idx != -1 {
		destURL = destURL[idx+len(davPrefix):]
	}
	destClean := filepath.Clean(destURL)
	if strings.Contains(destClean, "..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	destPath := filepath.Join(fsRoot, destClean)

	overwrite := r.Header.Get("Overwrite") != "F"
	if _, err := os.Stat(destPath); err == nil && !overwrite {
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		return
	}

	if isMove {
		if err := os.Rename(srcPath, destPath); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		if err := copyPath(srcPath, destPath); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
}

func copyPath(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if srcInfo.IsDir() {
		if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyPath(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ─── LOCK ────────────────────────────────────────────────────────────────────

func davLock(w http.ResponseWriter, r *http.Request) {
	lockToken := fmt.Sprintf("urn:uuid:%s", NewUUID())
	timeout := "Second-3600"
	if t := r.Header.Get("Timeout"); t != "" {
		timeout = t
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Lock-Token", "<"+lockToken+">")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>infinity</D:depth>
      <D:timeout>%s</D:timeout>
      <D:locktoken><D:href>%s</D:href></D:locktoken>
      <D:lockroot><D:href>%s</D:href></D:lockroot>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>`, timeout, lockToken, r.URL.Path)
}
