package web

import (
	"net/http"

	"snd-archive/snd"
	"snd-archive/web/pages/admin"
	"snd-archive/web/pages/dashboard"
	"snd-archive/web/pages/login"
	"snd-archive/web/pages/share"
	"snd-archive/web/pages/userdash"
)

func SetupRoutes() {
	http.HandleFunc("/favicon.ico", snd.HandleFavicon)
	http.HandleFunc("/lib/", snd.HandleLibFile)
	http.HandleFunc("/icons/", snd.HandleIconFile)
	http.HandleFunc("/error", snd.HandleErrorPage)

	if snd.Cfg.CloudflareChallenge {
		// FIX: Apply CF challenge to all browser-facing routes
		cf := snd.CfChallengeMiddleware
		http.HandleFunc("/", cf(dashboard.Handler))
		http.HandleFunc("/share", cf(share.Handler))
		http.HandleFunc("/my", cf(snd.RequireAuth(userdash.Handler)))
		http.HandleFunc("/cf-challenge", snd.HandleCFChallenge)
	} else {
		http.HandleFunc("/", dashboard.Handler)
		http.HandleFunc("/share", share.Handler)
		http.HandleFunc("/my", snd.RequireAuth(userdash.Handler))
	}

	http.HandleFunc("/ac", login.Handler)
	http.HandleFunc("/login", snd.HandleLoginSubmit)
	http.HandleFunc("/logout", snd.HandleLogout)

	// Admin panel — admin sees full panel, users see their info
	http.HandleFunc("/ad", snd.RequireAuth(admin.Handler))

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
	http.HandleFunc("/files", snd.ObfuscateHandler(snd.HandleListFiles))
	http.HandleFunc("/public-files", snd.HandlePublicFiles)
	http.HandleFunc("/upload", snd.ObfuscateHandler(snd.RequireAuth(snd.HandleUpload)))
	http.HandleFunc("/upload-chunk", snd.ObfuscateHandler(snd.RequireAuth(snd.HandleUploadChunk)))
	http.HandleFunc("/create-folder", snd.RequireAuth(snd.HandleCreateFolder))
	http.HandleFunc("/delete-folder/", snd.RequireAuth(snd.HandleDeleteFolder))
	http.HandleFunc("/rename-folder/", snd.RequireAuth(snd.HandleRenameFolder))
	http.HandleFunc("/set-permission", snd.RequireAuth(snd.HandleSetPermission))
	http.HandleFunc("/set-folder-permission", snd.RequireAuth(snd.HandleSetFolderPermission))
	http.HandleFunc("/set-chmod", snd.RequireAuth(snd.HandleSetChmod))

	http.HandleFunc("/folder/", snd.HandleFolderView)
	http.HandleFunc("/folder-info/", snd.RequireAuth(snd.HandleFolderInfo))
	http.HandleFunc("/view/", snd.RequireTokenOrAuth(snd.HandleView))
	http.HandleFunc("/stream/", snd.RequireTokenOrAuth(snd.HandleStream))
	http.HandleFunc("/play/", snd.RequireTokenOrAuth(snd.HandleStreamPage))
	http.HandleFunc("/embed/", snd.RequireTokenOrAuth(snd.HandleEmbedPreview))
	http.HandleFunc("/edit/", snd.RequireAuth(snd.HandleEdit))
	http.HandleFunc("/save/", snd.RequireAuth(snd.HandleSave))
	http.HandleFunc("/raw/", snd.HandleRawDispatch)
	http.HandleFunc("/download/", snd.RequireTokenOrAuth(snd.HandleDownload))

	// ─── New: API view & thumbnail ────────────────────────────────────────────
	http.HandleFunc("/api/view/", snd.RequireTokenOrAuth(snd.HandleAPIView))
	http.HandleFunc("/api/lang", snd.HandleLangStrings)
	http.HandleFunc("/thumbnail/", snd.RequireTokenOrAuth(snd.HandleThumbnail))

	http.HandleFunc("/delete/", snd.RequireAuth(snd.HandleDelete))
	http.HandleFunc("/rename/", snd.RequireAuth(snd.HandleRename))
	http.HandleFunc("/duplicate/", snd.RequireAuth(snd.HandleDuplicate))
	http.HandleFunc("/zip-multiple", snd.RequireAuth(snd.HandleZipMultiple))
	http.HandleFunc("/zip-view/", snd.HandleZipView)
	http.HandleFunc("/extract-zip/", snd.RequireAuth(snd.HandleExtractZip))

	// ─── Benchmarks ───────────────────────────────────────────────────────────
	http.HandleFunc("/benchmark/ping", snd.HandleBenchmarkPing)
	http.HandleFunc("/benchmark/download", snd.HandleBenchmarkDownload)
	http.HandleFunc("/benchmark/upload", snd.HandleBenchmarkUpload)
	http.HandleFunc("/benchmark/disk", snd.RequireAdmin(snd.HandleBenchmarkDisk))
	http.HandleFunc("/benchmark/cpu", snd.HandleBenchmarkCPU)
	http.HandleFunc("/benchmark/memory", snd.HandleBenchmarkMemory)
	http.HandleFunc("/benchmark/network", snd.HandleBenchmarkNetwork)

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

	// ─── Anti-DDoS (admin) ───────────────────────────────────────────────────
	http.HandleFunc("/admin/ddos/config", snd.RequireAdmin(snd.HandleDDoSConfig))
	http.HandleFunc("/admin/ddos/stats", snd.RequireAdmin(snd.HandleDDoSStats))
	http.HandleFunc("/admin/ddos/unban", snd.RequireAdmin(snd.HandleDDoSUnban))
	http.HandleFunc("/admin/ddos/ban", snd.RequireAdmin(snd.HandleDDoSManualBan))

	// ─── Settings ─────────────────────────────────────────────────────────────
	http.HandleFunc("/admin/settings", snd.RequireAdmin(snd.HandleAdminGetSettings))
	http.HandleFunc("/admin/settings/save", snd.RequireAdmin(snd.HandleAdminSaveSettings))
	http.HandleFunc("/user/settings", snd.RequireAuth(snd.HandleUserGetSettings))
	http.HandleFunc("/user/settings/save", snd.RequireAuth(snd.HandleUserSaveSettings))
}

