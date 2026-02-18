package snd

import "sync"

var (
	Debug      bool
	PublicDir  = "public"
	ConfigFile = "config.yml"

	Cfg Config

	Sessions  = make(map[string]*SessionInfo)
	SessionMu sync.RWMutex

	DownloadCounts = make(map[string]int)
	DownloadMu     sync.RWMutex

	FilePermissions   = make(map[string]FilePermission)
	FolderPermissions = make(map[string]FolderPermission)
	PermissionMu      sync.RWMutex

	TwoFACodes = make(map[string]TwoFACode)
	TwoFAMu    sync.RWMutex

	AccessLogs  []AccessLog
	AccessLogMu sync.RWMutex

	GlobalStats   Stats
	GlobalStatsMu sync.RWMutex
)
