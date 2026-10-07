package web

import (
	"net/http"

	"snd-archive/snd"
	"snd-archive/web/pages/admin"
	"snd-archive/web/pages/dashboard"
	"snd-archive/web/pages/login"
	"snd-archive/web/pages/userdash"
)

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

	http.HandleFunc("/", securityHeaders(dashboard.Handler))
	http.HandleFunc("/my", securityHeaders(snd.RequireAuth(userdash.Handler)))

	http.HandleFunc("/download/", snd.RequireTokenOrAuth(snd.HandleDownload))
	http.HandleFunc("/view/", snd.RequireTokenOrAuth(snd.HandleView))
	http.HandleFunc("/stream/", snd.RequireTokenOrAuth(snd.HandleStream))
	http.HandleFunc("/play/", snd.RequireTokenOrAuth(snd.HandleStreamPage))
	http.HandleFunc("/embed/", snd.RequireTokenOrAuth(snd.HandleEmbedPreview))
	http.HandleFunc("/api/view/", snd.RequireTokenOrAuth(snd.HandleAPIView))
	http.HandleFunc("/thumbnail/", snd.RequireTokenOrAuth(snd.HandleThumbnail))
	http.HandleFunc("/raw/", snd.HandleRawDispatch)
	http.HandleFunc("/folder/", snd.HandleFolderView)
	http.HandleFunc("/zip-view/", snd.HandleZipView)
	http.HandleFunc("/public-files", snd.HandlePublicFiles)
	http.HandleFunc("/files", snd.ObfuscateHandler(snd.HandleListFiles))

	http.HandleFunc("/share", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	})

	http.HandleFunc("/ac", securityHeaders(login.Handler))
	http.HandleFunc("/login", snd.HandleLoginSubmit)
	http.HandleFunc("/logout", snd.HandleLogout)

	http.HandleFunc("/ad", securityHeaders(snd.RequireAuth(admin.Handler)))

	http.HandleFunc("/admin/users", snd.RequireAdmin(snd.HandleListUsers))
	http.HandleFunc("/admin/users/create", snd.RequireAdmin(snd.HandleCreateUser))
	http.HandleFunc("/admin/users/update", snd.RequireAdmin(snd.HandleUpdateUser))
	http.HandleFunc("/admin/users/delete", snd.RequireAdmin(snd.HandleDeleteUser))

	http.HandleFunc("/sessions", snd.RequireAdmin(snd.HandleSessions))
	http.HandleFunc("/kick-session", snd.RequireAdmin(snd.HandleKickSession))
	http.HandleFunc("/access-logs", snd.RequireAdmin(snd.HandleAccessLogs))

	http.HandleFunc("/up", snd.HandleAPIUpload)
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

	http.HandleFunc("/api/lang", snd.HandleLangStrings)
	http.HandleFunc("/api/qr", snd.HandleQR)
	http.HandleFunc("/api/challenge/verify", snd.HandleChallengeVerify)
	http.HandleFunc("/api/challenge/config", snd.HandleChallengeConfig)

	http.HandleFunc("/delete/", snd.RequireAuth(snd.HandleDelete))
	http.HandleFunc("/rename/", snd.RequireAuth(snd.HandleRename))
	http.HandleFunc("/duplicate/", snd.RequireAuth(snd.HandleDuplicate))
	http.HandleFunc("/zip-multiple", snd.HandleZipMultiple)
	http.HandleFunc("/extract-zip/", snd.RequireAuth(snd.HandleExtractZip))
	http.HandleFunc("/download-url", snd.RequireAdmin(snd.HandleDownloadByURL))
	http.HandleFunc("/stream-info", snd.RequireAdmin(snd.HandleStreamInfo))
	http.HandleFunc("/stream-download", snd.RequireAdmin(snd.HandleStreamDownload))

	http.HandleFunc("/benchmark/ping", snd.RequireAuth(snd.HandleBenchmarkPing))
	http.HandleFunc("/benchmark/download", snd.RequireAuth(snd.HandleBenchmarkDownload))
	http.HandleFunc("/benchmark/upload", snd.RequireAuth(snd.HandleBenchmarkUpload))
	http.HandleFunc("/benchmark/disk", snd.RequireAdmin(snd.HandleBenchmarkDisk))
	http.HandleFunc("/benchmark/cpu", snd.RequireAdmin(snd.HandleBenchmarkCPU))
	http.HandleFunc("/benchmark/memory", snd.RequireAdmin(snd.HandleBenchmarkMemory))
	http.HandleFunc("/benchmark/network", snd.RequireAdmin(snd.HandleBenchmarkNetwork))

	http.HandleFunc("/dav/", snd.HandleWebDAV)
	http.HandleFunc("/dav", snd.HandleWebDAV)

	http.HandleFunc("/user/change-password", snd.RequireAuth(snd.HandleChangePassword))

	http.HandleFunc("/admin/nodes", snd.RequireAdmin(snd.HandleListNodes))
	http.HandleFunc("/admin/nodes/create", snd.RequireAdmin(snd.HandleCreateNode))
	http.HandleFunc("/admin/nodes/update", snd.RequireAdmin(snd.HandleUpdateNode))
	http.HandleFunc("/admin/nodes/delete", snd.RequireAdmin(snd.HandleDeleteNode))
	http.HandleFunc("/admin/nodes/set-primary", snd.RequireAdmin(snd.HandleSetPrimaryNode))
	http.HandleFunc("/api/v9/connect", snd.HandleNodeConnect)
	http.HandleFunc("/admin/nodes/info", snd.RequireAdmin(snd.HandleNodeInfo))

	http.HandleFunc("/admin/ddos/config", snd.RequireAdmin(snd.HandleDDoSConfig))
	http.HandleFunc("/admin/ddos/stats", snd.RequireAdmin(snd.HandleDDoSStats))
	http.HandleFunc("/admin/ddos/unban", snd.RequireAdmin(snd.HandleDDoSUnban))
	http.HandleFunc("/admin/ddos/ban", snd.RequireAdmin(snd.HandleDDoSManualBan))
	http.HandleFunc("/admin/security-logs", snd.RequireAdmin(snd.HandleSecurityLogs))
	http.HandleFunc("/admin/allowlist", snd.RequireAdmin(snd.HandleListAllowlist))
	http.HandleFunc("/admin/allowlist/add", snd.RequireAdmin(snd.HandleAddAllowlist))
	http.HandleFunc("/admin/allowlist/update", snd.RequireAdmin(snd.HandleUpdateAllowlist))
	http.HandleFunc("/admin/allowlist/delete", snd.RequireAdmin(snd.HandleDeleteAllowlist))

	http.HandleFunc("/admin/settings", snd.RequireAdmin(snd.HandleAdminGetSettings))
	http.HandleFunc("/admin/settings/save", snd.RequireAdmin(snd.HandleAdminSaveSettings))
	http.HandleFunc("/user/settings", snd.RequireAuth(snd.HandleUserGetSettings))
	http.HandleFunc("/user/settings/save", snd.RequireAuth(snd.HandleUserSaveSettings))
}
