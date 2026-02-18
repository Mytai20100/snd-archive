package web

import (
	"net/http"

	"snd-archive/snd"
	"snd-archive/web/pages/admin"
	"snd-archive/web/pages/dashboard"
	"snd-archive/web/pages/login"
	"snd-archive/web/pages/share"
)

func SetupRoutes() {
	// Static assets
	http.HandleFunc("/favicon.ico", snd.HandleFavicon)

	// Error page
	http.HandleFunc("/error", snd.HandleErrorPage)

	// Cloudflare challenge
	if snd.Cfg.CloudflareChallenge {
		http.HandleFunc("/", snd.CfChallengeMiddleware(dashboard.Handler))
		http.HandleFunc("/cf-challenge", snd.HandleCFChallenge)
	} else {
		http.HandleFunc("/", dashboard.Handler)
	}

	// Auth pages
	http.HandleFunc("/ac", login.Handler)
	http.HandleFunc("/login", snd.HandleLoginSubmit)
	http.HandleFunc("/logout", snd.HandleLogout)

	// Share page (public)
	http.HandleFunc("/share", share.Handler)

	// Admin page
	http.HandleFunc("/ad", snd.RequireAuth(admin.Handler))

	// Session management
	http.HandleFunc("/sessions", snd.RequireAuth(snd.HandleSessions))
	http.HandleFunc("/kick-session", snd.RequireAuth(snd.HandleKickSession))
	http.HandleFunc("/access-logs", snd.RequireAuth(snd.HandleAccessLogs))

	// File API
	http.HandleFunc("/files", snd.ObfuscateHandler(snd.HandleListFiles))
	http.HandleFunc("/upload", snd.ObfuscateHandler(snd.RequireAuth(snd.HandleUpload)))
	http.HandleFunc("/create-folder", snd.RequireAuth(snd.HandleCreateFolder))
	http.HandleFunc("/delete-folder/", snd.RequireAuth(snd.HandleDeleteFolder))
	http.HandleFunc("/rename-folder/", snd.RequireAuth(snd.HandleRenameFolder))
	http.HandleFunc("/set-permission", snd.RequireAuth(snd.HandleSetPermission))
	http.HandleFunc("/set-folder-permission", snd.RequireAuth(snd.HandleSetFolderPermission))
	http.HandleFunc("/set-chmod", snd.RequireAuth(snd.HandleSetChmod))

	// Folder operations
	http.HandleFunc("/folder/", snd.HandleFolderView)
	http.HandleFunc("/folder-info/", snd.RequireAuth(snd.HandleFolderInfo))
	http.HandleFunc("/view/", snd.RequireTokenOrAuth(snd.HandleView))
	http.HandleFunc("/stream/", snd.RequireTokenOrAuth(snd.HandleStream))
	http.HandleFunc("/edit/", snd.RequireAuth(snd.HandleEdit))
	http.HandleFunc("/save/", snd.RequireAuth(snd.HandleSave))
	http.HandleFunc("/raw/", snd.RequireTokenOrAuth(snd.HandleRaw))
	http.HandleFunc("/download/", snd.RequireTokenOrAuth(snd.HandleDownload))

	// File operations
	http.HandleFunc("/delete/", snd.RequireAuth(snd.HandleDelete))
	http.HandleFunc("/rename/", snd.RequireAuth(snd.HandleRename))
	http.HandleFunc("/duplicate/", snd.RequireAuth(snd.HandleDuplicate))
	http.HandleFunc("/zip-multiple", snd.RequireAuth(snd.HandleZipMultiple))
	http.HandleFunc("/zip-view/", snd.HandleZipView)
	http.HandleFunc("/extract-zip/", snd.RequireAuth(snd.HandleExtractZip))

	// Benchmark
	http.HandleFunc("/benchmark/ping", snd.HandleBenchmarkPing)
	http.HandleFunc("/benchmark/download", snd.HandleBenchmarkDownload)
	http.HandleFunc("/benchmark/upload", snd.HandleBenchmarkUpload)
	http.HandleFunc("/benchmark/disk", snd.RequireAuth(snd.HandleBenchmarkDisk))
	http.HandleFunc("/benchmark/cpu", snd.HandleBenchmarkCPU)
	http.HandleFunc("/benchmark/memory", snd.HandleBenchmarkMemory)
	http.HandleFunc("/benchmark/network", snd.HandleBenchmarkNetwork)
}
