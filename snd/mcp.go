package snd

// mcp.go — Model Context Protocol (MCP) server endpoint
//
// Security model:
//   - Admin MCP (/mcp/admin/*): uses the server API token from config.yml ONLY.
//     Admin token is NEVER exposed to users. Requires admin session or config token.
//   - User MCP  (/mcp/user/*):  uses the calling user's own API token ONLY.
//     User token cannot access admin-only operations.
//     Permissions are clamped by admin-defined UserMCPDefaultPerms.
//
// Tool Graph:
//   Tools declare their dependencies via the ToolGraph so the MCP client can
//   batch related calls. E.g. "storage_info" depends on "list_files" only when
//   the client needs both — the graph lets the agent avoid redundant round-trips.
//
// Rate limiting:
//   Per-session token bucket (AdminMCPSettings.RateLimit / UserMCPSettings.RateLimit).
//   Default 60 calls/minute. Prevents agent loops from abusing the server.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── Helper shims ──────────────────────────────────────────────────────────────

// GetSession returns the raw session cookie value (used as rate-limit key).
// Returns empty string if no session cookie present.
func GetSession(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil || cookie == nil {
		return r.RemoteAddr // fallback to IP
	}
	return cookie.Value
}

// DiskUsage returns (totalBytes, usedBytes) for the given directory path.
// On error, returns (0, 0).
func DiskUsage(root string) (total int64, used int64) {
	var size int64
	filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil { return nil }
		if !info.IsDir() { size += info.Size() }
		return nil
	})
	// We don't have syscall.Statfs here for portability;
	// return 0 for total so callers show "N used / unknown total".
	return 0, size
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

type mcpRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*rateBucket
}

type rateBucket struct {
	tokens    int
	lastReset time.Time
	limit     int // calls per minute
}

var mcpLimiter = &mcpRateLimiter{buckets: make(map[string]*rateBucket)}

// Allow returns true if the caller (keyed by session/token) is within the rate limit.
func (rl *mcpRateLimiter) Allow(key string, limit int) bool {
	if limit <= 0 {
		limit = 60
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	if !ok {
		b = &rateBucket{tokens: limit, lastReset: time.Now(), limit: limit}
		rl.buckets[key] = b
	}
	// Refill if a minute has passed
	if time.Since(b.lastReset) >= time.Minute {
		b.tokens    = limit
		b.lastReset = time.Now()
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// ── Tool Graph ───────────────────────────────────────────────────────────────
//
// The tool graph tells the MCP client which tools can be batched together and
// which results a tool depends on. This lets an AI agent plan multi-step
// operations without redundant round-trips.
//
// Format: tool_name → list of tools whose output feeds into this tool.
// An empty dependency list means the tool is a leaf (no prior calls needed).

type ToolGraphNode struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	DependsOn   []string `json:"depends_on"`   // tools whose output this tool may consume
	// Batchable: true = this tool can run in parallel with its sibling non-dependent tools
	Batchable   bool     `json:"batchable"`
}

// buildToolGraph returns the tool graph appropriate for the given permissions.
// Admin gets extra nodes (manage_users, etc.).
func buildToolGraph(perms MCPPermissions, isAdmin bool) []ToolGraphNode {
	nodes := []ToolGraphNode{}

	if perms.CanRead {
		nodes = append(nodes,
			ToolGraphNode{
				Name: "list_files", Description: "List files and folders at a path",
				DependsOn: []string{}, Batchable: true,
			},
			ToolGraphNode{
				Name: "get_file_info", Description: "Get metadata for a specific file",
				DependsOn: []string{"list_files"}, Batchable: true,
			},
		)
	}
	if perms.CanStorage {
		nodes = append(nodes, ToolGraphNode{
			Name: "storage_info", Description: "Get total/used/free storage and quota",
			// storage_info doesn't depend on list_files but can run in parallel
			DependsOn: []string{}, Batchable: true,
		})
	}
	if perms.CanUpload {
		nodes = append(nodes, ToolGraphNode{
			Name: "upload_file", Description: "Upload a file to a given path",
			DependsOn: []string{"list_files"}, Batchable: false,
		})
	}
	if perms.CanCreate {
		nodes = append(nodes, ToolGraphNode{
			Name: "create_folder", Description: "Create a new folder",
			DependsOn: []string{}, Batchable: false,
		})
	}
	if perms.CanRename {
		nodes = append(nodes, ToolGraphNode{
			Name: "rename", Description: "Rename or move a file or folder",
			DependsOn: []string{"list_files"}, Batchable: false,
		})
	}
	if perms.CanDelete {
		nodes = append(nodes, ToolGraphNode{
			Name: "delete_file", Description: "Delete a file",
			// delete_file should come AFTER list_files + get_file_info so the agent
			// confirms the file exists before deleting
			DependsOn: []string{"list_files", "get_file_info"}, Batchable: false,
		})
		nodes = append(nodes, ToolGraphNode{
			Name: "delete_folder", Description: "Delete a folder recursively",
			DependsOn: []string{"list_files"}, Batchable: false,
		})
	}
	if isAdmin && perms.CanUsers {
		nodes = append(nodes,
			ToolGraphNode{
				Name: "list_users", Description: "List all sub-user accounts",
				DependsOn: []string{}, Batchable: true,
			},
			ToolGraphNode{
				Name: "storage_report", Description: "Per-user storage usage report",
				DependsOn: []string{"list_users", "storage_info"}, Batchable: true,
			},
		)
	}
	return nodes
}

// ── Tool dispatch ─────────────────────────────────────────────────────────────

type mcpRequest struct {
	Tool   string          `json:"tool"`
	Params json.RawMessage `json:"params"`
}

type mcpResponse struct {
	OK     bool            `json:"ok"`
	Result interface{}     `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// sanitizePath ensures the path stays within the server's root dir.
// Returns an error if the path escapes via traversal.
func sanitizePath(raw string) (string, error) {
	// Strip leading slash or dot-dot
	clean := filepath.Clean("/" + strings.TrimPrefix(raw, "/"))
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("invalid path")
	}
	return clean, nil
}

// dispatchTool executes a single MCP tool call.
// rootDir is the FS root this session is allowed to access.
// isAdmin controls whether admin-only tools are available.
func dispatchTool(tool string, params json.RawMessage, perms MCPPermissions, rootDir string, isAdmin bool) (interface{}, error) {
	switch tool {

	// ── list_files ────────────────────────────────────────────────────────
	case "list_files":
		if !perms.CanRead {
			return nil, fmt.Errorf("permission denied: can_read required")
		}
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(params, &p)
		dir := filepath.Join(rootDir, filepath.Clean("/"+p.Path))
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("cannot read directory: %v", err)
		}
		type entry struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
			Size  int64  `json:"size"`
		}
		var list []entry
		for _, e := range entries {
			info, _ := e.Info()
			sz := int64(0)
			if info != nil { sz = info.Size() }
			list = append(list, entry{Name: e.Name(), IsDir: e.IsDir(), Size: sz})
		}
		return list, nil

	// ── get_file_info ─────────────────────────────────────────────────────
	case "get_file_info":
		if !perms.CanRead {
			return nil, fmt.Errorf("permission denied: can_read required")
		}
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(params, &p)
		fp := filepath.Join(rootDir, filepath.Clean("/"+p.Path))
		info, err := os.Stat(fp)
		if err != nil {
			return nil, fmt.Errorf("file not found")
		}
		return map[string]interface{}{
			"name":    info.Name(),
			"size":    info.Size(),
			"is_dir":  info.IsDir(),
			"mod_time": info.ModTime().UTC(),
		}, nil

	// ── storage_info ──────────────────────────────────────────────────────
	case "storage_info":
		if !perms.CanStorage {
			return nil, fmt.Errorf("permission denied: can_storage required")
		}
		total, used := DiskUsage(rootDir)
		return map[string]interface{}{
			"root":       rootDir,
			"used_bytes": used,
			"total_bytes": total,
			"free_bytes": total - used,
		}, nil

	// ── create_folder ─────────────────────────────────────────────────────
	case "create_folder":
		if !perms.CanCreate {
			return nil, fmt.Errorf("permission denied: can_create required")
		}
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(params, &p)
		clean, err := sanitizePath(p.Path)
		if err != nil { return nil, err }
		dir := filepath.Join(rootDir, clean)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("cannot create folder: %v", err)
		}
		return map[string]bool{"created": true}, nil

	// ── rename ────────────────────────────────────────────────────────────
	case "rename":
		if !perms.CanRename {
			return nil, fmt.Errorf("permission denied: can_rename required")
		}
		var p struct {
			From string `json:"from"`
			To   string `json:"to"`
		}
		json.Unmarshal(params, &p)
		from, err1 := sanitizePath(p.From)
		to,   err2 := sanitizePath(p.To)
		if err1 != nil { return nil, err1 }
		if err2 != nil { return nil, err2 }
		src := filepath.Join(rootDir, from)
		dst := filepath.Join(rootDir, to)
		if err := os.Rename(src, dst); err != nil {
			return nil, fmt.Errorf("rename failed: %v", err)
		}
		return map[string]bool{"renamed": true}, nil

	// ── delete_file ───────────────────────────────────────────────────────
	case "delete_file":
		if !perms.CanDelete {
			return nil, fmt.Errorf("permission denied: can_delete required")
		}
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(params, &p)
		clean, err := sanitizePath(p.Path)
		if err != nil { return nil, err }
		fp := filepath.Join(rootDir, clean)
		info, err := os.Stat(fp)
		if err != nil { return nil, fmt.Errorf("file not found") }
		if info.IsDir() { return nil, fmt.Errorf("use delete_folder for directories") }
		if err := os.Remove(fp); err != nil {
			return nil, fmt.Errorf("delete failed: %v", err)
		}
		return map[string]bool{"deleted": true}, nil

	// ── delete_folder ─────────────────────────────────────────────────────
	case "delete_folder":
		if !perms.CanDelete {
			return nil, fmt.Errorf("permission denied: can_delete required")
		}
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(params, &p)
		clean, err := sanitizePath(p.Path)
		if err != nil { return nil, err }
		dir := filepath.Join(rootDir, clean)
		if err := os.RemoveAll(dir); err != nil {
			return nil, fmt.Errorf("delete failed: %v", err)
		}
		return map[string]bool{"deleted": true}, nil

	// ── list_users (admin only) ───────────────────────────────────────────
	case "list_users":
		if !isAdmin || !perms.CanUsers {
			return nil, fmt.Errorf("permission denied: admin + can_users required")
		}
		UsersMu.RLock()
		defer UsersMu.RUnlock()
		type userSummary struct {
			UUID         string `json:"uuid"`
			Username     string `json:"username"`
			Email        string `json:"email"`
			IsActive     bool   `json:"is_active"`
			StorageLimit int64  `json:"storage_limit"`
			UsedStorage  int64  `json:"used_storage"`
		}
		var list []userSummary
		for _, u := range Users {
			list = append(list, userSummary{
				UUID: u.UUID, Username: u.Username, Email: u.Email,
				IsActive: u.IsActive, StorageLimit: u.StorageLimit, UsedStorage: u.UsedStorage,
			})
		}
		return list, nil

	// ── storage_report (admin only) ───────────────────────────────────────
	case "storage_report":
		if !isAdmin || !perms.CanUsers {
			return nil, fmt.Errorf("permission denied: admin + can_users required")
		}
		UsersMu.RLock()
		defer UsersMu.RUnlock()
		type row struct {
			Username     string `json:"username"`
			UsedStorage  int64  `json:"used_storage"`
			StorageLimit int64  `json:"storage_limit"`
		}
		var report []row
		for _, u := range Users {
			report = append(report, row{
				Username: u.Username, UsedStorage: u.UsedStorage, StorageLimit: u.StorageLimit,
			})
		}
		return report, nil

	default:
		return nil, fmt.Errorf("unknown tool: %s", tool)
	}
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

// HandleAdminMCPInfo returns the admin MCP tool graph + enabled status.
// GET /mcp/admin/info
func HandleAdminMCPInfo(w http.ResponseWriter, r *http.Request) {
	SiteSettingsMu.RLock()
	cfg := SiteSettingsData.AdminMCP
	SiteSettingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":    cfg.Enabled,
		"rate_limit": cfg.RateLimit,
		"tool_graph": buildToolGraph(cfg.Permissions, true),
		"permissions": cfg.Permissions,
	})
}

// HandleAdminMCPCall executes an MCP tool call as admin.
// POST /mcp/admin/call
func HandleAdminMCPCall(w http.ResponseWriter, r *http.Request) {
	SiteSettingsMu.RLock()
	cfg := SiteSettingsData.AdminMCP
	SiteSettingsMu.RUnlock()

	if !cfg.Enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(mcpResponse{Error: "admin mcp disabled"})
		return
	}

	// Rate limit by session ID
	sess := GetSession(r)
	sessKey := "admin:" + sess
	rl := cfg.RateLimit
	if rl <= 0 { rl = 60 }
	if !mcpLimiter.Allow(sessKey, rl) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(mcpResponse{Error: "rate limit exceeded"})
		return
	}

	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mcpResponse{Error: "invalid request"})
		return
	}

	result, err := dispatchTool(req.Tool, req.Params, cfg.Permissions, ".", true)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("[MCP/ADMIN] tool=%s error=%v", req.Tool, err)
		json.NewEncoder(w).Encode(mcpResponse{Error: err.Error()})
		return
	}
	log.Printf("[MCP/ADMIN] tool=%s ok", req.Tool)
	json.NewEncoder(w).Encode(mcpResponse{OK: true, Result: result})
}

// HandleUserMCPInfo returns the user's MCP tool graph + enabled status.
// GET /mcp/user/info  (requires auth)
func HandleUserMCPInfo(w http.ResponseWriter, r *http.Request) {
	u := GetSessionUser(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	SiteSettingsMu.RLock()
	allowMCP    := SiteSettingsData.AllowUserMCP
	maxPerms    := SiteSettingsData.UserMCPDefaultPerms
	SiteSettingsMu.RUnlock()

	if !allowMCP {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"enabled": false, "reason": "disabled by admin"})
		return
	}

	UsersMu.RLock()
	var mcpCfg UserMCPSettings
	if live, ok := Users[u.UUID]; ok {
		mcpCfg = live.Settings.MCP
	}
	UsersMu.RUnlock()

	// Clamp effective permissions
	eff := MCPPermissions{
		CanRead:    mcpCfg.Permissions.CanRead    && maxPerms.CanRead,
		CanUpload:  mcpCfg.Permissions.CanUpload  && maxPerms.CanUpload,
		CanDelete:  mcpCfg.Permissions.CanDelete  && maxPerms.CanDelete,
		CanCreate:  mcpCfg.Permissions.CanCreate  && maxPerms.CanCreate,
		CanRename:  mcpCfg.Permissions.CanRename  && maxPerms.CanRename,
		CanStorage: mcpCfg.Permissions.CanStorage && maxPerms.CanStorage,
		CanUsers:   false, // users never get user-management access
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":     mcpCfg.Enabled,
		"rate_limit":  mcpCfg.RateLimit,
		"tool_graph":  buildToolGraph(eff, false),
		"permissions": eff,
	})
}

// HandleUserMCPCall executes an MCP tool call as the current user.
// POST /mcp/user/call  (requires auth)
func HandleUserMCPCall(w http.ResponseWriter, r *http.Request) {
	u := GetSessionUser(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	SiteSettingsMu.RLock()
	allowMCP := SiteSettingsData.AllowUserMCP
	maxPerms := SiteSettingsData.UserMCPDefaultPerms
	SiteSettingsMu.RUnlock()

	if !allowMCP {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(mcpResponse{Error: "user mcp disabled by admin"})
		return
	}

	UsersMu.RLock()
	var mcpCfg UserMCPSettings
	if live, ok := Users[u.UUID]; ok {
		mcpCfg = live.Settings.MCP
	}
	UsersMu.RUnlock()

	if !mcpCfg.Enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(mcpResponse{Error: "mcp not enabled for this account"})
		return
	}

	// Rate limit by user UUID
	rl := mcpCfg.RateLimit
	if rl <= 0 { rl = 30 } // lower default for users
	if !mcpLimiter.Allow("user:"+u.UUID, rl) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(mcpResponse{Error: "rate limit exceeded"})
		return
	}

	// Clamp permissions
	eff := MCPPermissions{
		CanRead:    mcpCfg.Permissions.CanRead    && maxPerms.CanRead,
		CanUpload:  mcpCfg.Permissions.CanUpload  && maxPerms.CanUpload,
		CanDelete:  mcpCfg.Permissions.CanDelete  && maxPerms.CanDelete,
		CanCreate:  mcpCfg.Permissions.CanCreate  && maxPerms.CanCreate,
		CanRename:  mcpCfg.Permissions.CanRename  && maxPerms.CanRename,
		CanStorage: mcpCfg.Permissions.CanStorage && maxPerms.CanStorage,
		CanUsers:   false,
	}

	// User MCP root is scoped to their own directory — NEVER the full server root
	userRoot := filepath.Join("files", "users", u.UUID)

	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mcpResponse{Error: "invalid request"})
		return
	}

	result, err := dispatchTool(req.Tool, req.Params, eff, userRoot, false)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("[MCP/USER:%s] tool=%s error=%v", u.Username, req.Tool, err)
		json.NewEncoder(w).Encode(mcpResponse{Error: err.Error()})
		return
	}
	log.Printf("[MCP/USER:%s] tool=%s ok", u.Username, req.Tool)
	json.NewEncoder(w).Encode(mcpResponse{OK: true, Result: result})
}

// HandleAdminMCPSaveSettings saves admin MCP configuration.
// POST /admin/mcp/settings  (admin only)
func HandleAdminMCPSaveSettings(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AdminMCP            AdminMCPSettings `json:"admin_mcp"`
		AllowUserMCP        bool             `json:"allow_user_mcp"`
		UserMCPDefaultPerms MCPPermissions   `json:"user_mcp_default_perms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	// SECURITY: Users can NEVER manage users via MCP — hard-enforce at save time
	payload.UserMCPDefaultPerms.CanUsers = false

	SiteSettingsMu.Lock()
	SiteSettingsData.AdminMCP            = payload.AdminMCP
	SiteSettingsData.AllowUserMCP        = payload.AllowUserMCP
	SiteSettingsData.UserMCPDefaultPerms = payload.UserMCPDefaultPerms
	SiteSettingsMu.Unlock()
	go SaveSiteSettings()
	log.Printf("[MCP] Admin saved MCP settings: admin_enabled=%v allow_user=%v",
		payload.AdminMCP.Enabled, payload.AllowUserMCP)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// HandleAdminMCPGetSettings returns current MCP configuration for admin panel.
// GET /admin/mcp/settings  (admin only)
func HandleAdminMCPGetSettings(w http.ResponseWriter, r *http.Request) {
	SiteSettingsMu.RLock()
	defer SiteSettingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"admin_mcp":             SiteSettingsData.AdminMCP,
		"allow_user_mcp":        SiteSettingsData.AllowUserMCP,
		"user_mcp_default_perms": SiteSettingsData.UserMCPDefaultPerms,
	})
}
