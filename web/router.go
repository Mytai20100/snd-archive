package web

import (
	"net/http"

	"snd-archive/snd"
	"snd-archive/web/pages/admin"
	"snd-archive/web/pages/dashboard"
	"snd-archive/web/pages/login"
	"snd-archive/web/pages/userdash"
)

// securityHeaders wraps a handler and adds common security response headers.
// LOW-3 FIX: Prevents MIME-sniffing, clickjacking, and referrer leaks.
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "same-origin")
		next(w, r)
	}
}

func SetupRoutes() {
	http.HandleFunc("/favicon.ico", snd.HandleFavicon)
	http.HandleFunc("/lib/", snd.HandleLibFile)
	http.HandleFunc("/css/", snd.HandleCSSFile)
	http.HandleFunc("/icons/", snd.HandleIconFile)
	http.HandleFunc("/error", snd.HandleErrorPage)

	if snd.Cfg.CloudflareChallenge {
		// FIX: Apply CF challenge to all browser-facing routes
		cf := snd.CfChallengeMiddleware
		http.HandleFunc("/", securityHeaders(cf(dashboard.Handler)))
		http.HandleFunc("/my", securityHeaders(cf(snd.RequireAuth(userdash.Handler))))
		http.HandleFunc("/cf-challenge", snd.HandleCFChallenge)

		// HIGH-9 FIX: File endpoints also require the CF challenge.
		// Token-authenticated requests (automation/direct links) bypass the challenge
		// via RequireTokenOrChallenge; browser sessions must have passed the challenge.
		http.HandleFunc("/download/",  snd.RequireTokenOrChallenge(cf, snd.RequireTokenOrAuth(snd.HandleDownload)))
		http.HandleFunc("/view/",      snd.RequireTokenOrChallenge(cf, snd.RequireTokenOrAuth(snd.HandleView)))
		http.HandleFunc("/stream/",    snd.RequireTokenOrChallenge(cf, snd.RequireTokenOrAuth(snd.HandleStream)))
		http.HandleFunc("/play/",      snd.RequireTokenOrChallenge(cf, snd.RequireTokenOrAuth(snd.HandleStreamPage)))
		http.HandleFunc("/embed/",     snd.RequireTokenOrChallenge(cf, snd.RequireTokenOrAuth(snd.HandleEmbedPreview)))
		http.HandleFunc("/api/view/",  snd.RequireTokenOrChallenge(cf, snd.RequireTokenOrAuth(snd.HandleAPIView)))
		http.HandleFunc("/thumbnail/", snd.RequireTokenOrChallenge(cf, snd.RequireTokenOrAuth(snd.HandleThumbnail)))
		http.HandleFunc("/raw/",       cf(snd.HandleRawDispatch))
		http.HandleFunc("/folder/",    cf(snd.HandleFolderView))
		http.HandleFunc("/zip-view/",  cf(snd.HandleZipView))
		http.HandleFunc("/public-files", cf(snd.HandlePublicFiles))
		http.HandleFunc("/files",      cf(snd.ObfuscateHandler(snd.HandleListFiles)))
	} else {
		http.HandleFunc("/", securityHeaders(dashboard.Handler))
		http.HandleFunc("/my", securityHeaders(snd.RequireAuth(userdash.Handler)))

		http.HandleFunc("/download/",  snd.RequireTokenOrAuth(snd.HandleDownload))
		http.HandleFunc("/view/",      snd.RequireTokenOrAuth(snd.HandleView))
		http.HandleFunc("/stream/",    snd.RequireTokenOrAuth(snd.HandleStream))
		http.HandleFunc("/play/",      snd.RequireTokenOrAuth(snd.HandleStreamPage))
		http.HandleFunc("/embed/",     snd.RequireTokenOrAuth(snd.HandleEmbedPreview))
		http.HandleFunc("/api/view/",  snd.RequireTokenOrAuth(snd.HandleAPIView))
		http.HandleFunc("/thumbnail/", snd.RequireTokenOrAuth(snd.HandleThumbnail))
		http.HandleFunc("/raw/",       snd.HandleRawDispatch)
		http.HandleFunc("/folder/",    snd.HandleFolderView)
		http.HandleFunc("/zip-view/",  snd.HandleZipView)
		http.HandleFunc("/public-files", snd.HandlePublicFiles)
		http.HandleFunc("/files",      snd.ObfuscateHandler(snd.HandleListFiles))
	}

	// /share is deprecated — redirect to root
	http.HandleFunc("/share", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	})

	http.HandleFunc("/ac", securityHeaders(login.Handler))
	http.HandleFunc("/login", snd.HandleLoginSubmit)
	http.HandleFunc("/logout", snd.HandleLogout)

	// Admin panel — admin sees full panel, users see their info
	http.HandleFunc("/ad", securityHeaders(snd.RequireAuth(admin.Handler)))

	// ─── User management API (admin only) ────────────────────────────────────
	http.HandleFunc("/admin/users", snd.RequireAdmin(snd.HandleListUsers))
	http.HandleFunc("/admin/users/create", snd.RequireAdmin(snd.HandleCreateUser))
	http.HandleFunc("/admin/users/update", snd.RequireAdmin(snd.HandleUpdateUser))
	http.HandleFunc("/admin/users/delete", snd.RequireAdmin(snd.HandleDeleteUser))

	// ─── Session & Auth ───────────────────────────────────────────────────────
	http.HandleFunc("/sessions", snd.RequireAdmin(snd.HandleSessions))
	http.HandleFunc("/kick-session", snd.RequireAdmin(snd.HandleKickSession))
	http.HandleFunc("/access-logs", snd.RequireAdmin(snd.HandleAccessLogs))

	// ─── File operations ──────────────────────────────────────────────────────
	// MED-1 FIX: /files and /public-files are now registered inside the
	// CloudflareChallenge if/else block above so the correct middleware chain
	// is applied in both modes.  Only non-file-serving operations remain here.
	http.HandleFunc("/upload", snd.ObfuscateHandler(snd.RequireAuth(snd.HandleUpload)))
	http.HandleFunc("/upload-chunk", snd.ObfuscateHandler(snd.RequireAuth(snd.HandleUploadChunk)))
	http.HandleFunc("/check-exists", snd.ObfuscateHandler(snd.RequireAuth(snd.HandleCheckExists)))
	http.HandleFunc("/create-folder", snd.RequireAuth(snd.HandleCreateFolder))
	http.HandleFunc("/delete-folder/", snd.RequireAuth(snd.HandleDeleteFolder))
	http.HandleFunc("/rename-folder/", snd.RequireAuth(snd.HandleRenameFolder))
	http.HandleFunc("/set-permission", snd.RequireAuth(snd.HandleSetPermission))
	http.HandleFunc("/set-folder-permission", snd.RequireAuth(snd.HandleSetFolderPermission))
	http.HandleFunc("/set-chmod", snd.RequireAuth(snd.HandleSetChmod))

	http.HandleFunc("/folder-info/", snd.RequireAuth(snd.HandleFolderInfo))
	http.HandleFunc("/edit/", snd.RequireAuth(snd.HandleEdit))
	http.HandleFunc("/save/", snd.RequireAuth(snd.HandleSave))

	// ─── New: API lang & QR (no file serving — no challenge needed) ──────────
	http.HandleFunc("/api/lang", snd.HandleLangStrings)
	http.HandleFunc("/api/qr", snd.HandleQR)

	http.HandleFunc("/delete/", snd.RequireAuth(snd.HandleDelete))
	http.HandleFunc("/rename/", snd.RequireAuth(snd.HandleRename))
	http.HandleFunc("/duplicate/", snd.RequireAuth(snd.HandleDuplicate))
	http.HandleFunc("/zip-multiple", snd.HandleZipMultiple) // guest: only public files; auth: all files
	// /zip-view/ is registered in the CloudflareChallenge if/else block above.
	http.HandleFunc("/extract-zip/", snd.RequireAuth(snd.HandleExtractZip))
	// HIGH-6 FIX: download-url, stream-info, stream-download trigger heavy server-side
	// operations (yt-dlp, arbitrary URL fetch). Restrict to admin to prevent abuse.
	http.HandleFunc("/download-url", snd.RequireAdmin(snd.HandleDownloadByURL))
	http.HandleFunc("/stream-info", snd.RequireAdmin(snd.HandleStreamInfo))
	http.HandleFunc("/stream-download", snd.RequireAdmin(snd.HandleStreamDownload))

	// ─── Benchmarks ───────────────────────────────────────────────────────────
	// M1 FIX: All benchmark endpoints now require at least a valid auth session.
	// /benchmark/disk remains RequireAdmin (more sensitive: writes to disk).
	http.HandleFunc("/benchmark/ping", snd.RequireAuth(snd.HandleBenchmarkPing))
	http.HandleFunc("/benchmark/download", snd.RequireAuth(snd.HandleBenchmarkDownload))
	http.HandleFunc("/benchmark/upload", snd.RequireAuth(snd.HandleBenchmarkUpload))
	http.HandleFunc("/benchmark/disk", snd.RequireAdmin(snd.HandleBenchmarkDisk))
	// HIGH-6 FIX: CPU/memory/network benchmarks and stream/download-url endpoints
	// restricted to admin — regular users can spam these to DoS the server.
	http.HandleFunc("/benchmark/cpu", snd.RequireAdmin(snd.HandleBenchmarkCPU))
	http.HandleFunc("/benchmark/memory", snd.RequireAdmin(snd.HandleBenchmarkMemory))
	http.HandleFunc("/benchmark/network", snd.RequireAdmin(snd.HandleBenchmarkNetwork))

	// ─── WebDAV (Windows Network Locations) ──────────────────────────────────
	http.HandleFunc("/dav/", snd.HandleWebDAV)
	http.HandleFunc("/dav", snd.HandleWebDAV)

	// ─── User account self-service ────────────────────────────────────────────
	http.HandleFunc("/user/change-password", snd.RequireAuth(snd.HandleChangePassword))

	// ─── Storage Node Management (admin) ─────────────────────────────────────
	http.HandleFunc("/admin/nodes", snd.RequireAdmin(snd.HandleListNodes))
	http.HandleFunc("/admin/nodes/create", snd.RequireAdmin(snd.HandleCreateNode))
	http.HandleFunc("/admin/nodes/update", snd.RequireAdmin(snd.HandleUpdateNode))
	http.HandleFunc("/admin/nodes/delete", snd.RequireAdmin(snd.HandleDeleteNode))
	http.HandleFunc("/admin/nodes/set-primary", snd.RequireAdmin(snd.HandleSetPrimaryNode))
	http.HandleFunc("/api/v9/connect", snd.HandleNodeConnect)
	http.HandleFunc("/admin/nodes/info", snd.RequireAdmin(snd.HandleNodeInfo))

	// ─── Anti-DDoS (admin) ───────────────────────────────────────────────────
	http.HandleFunc("/admin/ddos/config", snd.RequireAdmin(snd.HandleDDoSConfig))
	http.HandleFunc("/admin/ddos/stats", snd.RequireAdmin(snd.HandleDDoSStats))
	http.HandleFunc("/admin/ddos/unban", snd.RequireAdmin(snd.HandleDDoSUnban))
	http.HandleFunc("/admin/ddos/ban", snd.RequireAdmin(snd.HandleDDoSManualBan))
	http.HandleFunc("/admin/security-logs", snd.RequireAdmin(snd.HandleSecurityLogs))
	http.HandleFunc("/admin/allowlist", snd.RequireAdmin(snd.HandleListAllowlist))
	http.HandleFunc("/admin/allowlist/add", snd.RequireAdmin(snd.HandleAddAllowlist))
	http.HandleFunc("/admin/allowlist/update", snd.RequireAdmin(snd.HandleUpdateAllowlist))
	http.HandleFunc("/admin/allowlist/delete", snd.RequireAdmin(snd.HandleDeleteAllowlist))

	// ─── Settings ─────────────────────────────────────────────────────────────
	http.HandleFunc("/admin/settings", snd.RequireAdmin(snd.HandleAdminGetSettings))
	http.HandleFunc("/admin/settings/save", snd.RequireAdmin(snd.HandleAdminSaveSettings))
	http.HandleFunc("/user/settings", snd.RequireAuth(snd.HandleUserGetSettings))
	http.HandleFunc("/user/settings/save", snd.RequireAuth(snd.HandleUserSaveSettings))

	// ─── MCP Server ───────────────────────────────────────────────────────────
	// Admin MCP: uses server API token from config.yml, never a user token.
	// Requires active admin session.
	http.HandleFunc("/admin/mcp/settings", snd.RequireAdmin(snd.HandleAdminMCPGetSettings))
	http.HandleFunc("/admin/mcp/settings/save", snd.RequireAdmin(snd.HandleAdminMCPSaveSettings))
	http.HandleFunc("/mcp/admin/info", snd.RequireAdmin(snd.HandleAdminMCPInfo))
	http.HandleFunc("/mcp/admin/call", snd.RequireAdmin(snd.HandleAdminMCPCall))

	// User MCP: uses the user's own API token, scoped to their own directory.
	// Permissions are clamped by admin-defined UserMCPDefaultPerms.
	http.HandleFunc("/mcp/user/info", snd.RequireAuth(snd.HandleUserMCPInfo))
	http.HandleFunc("/mcp/user/call", snd.RequireAuth(snd.HandleUserMCPCall))
}

