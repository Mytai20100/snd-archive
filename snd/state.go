package snd

import "sync"

var (
	Debug      bool
	WorkDir    = "." // set to directory of the binary at startup
	PublicDir  = "public"
	ConfigFile = "config.yml"
	UsersFile  = "users.yml"

	Cfg Config

	Sessions  = make(map[string]*SessionInfo)
	SessionMu sync.RWMutex

	// Users map: UUID → UserAccount
	Users   = make(map[string]*UserAccount)
	UsersMu sync.RWMutex

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

	// AdminLoginBans tracks brute-force attempts per IP for admin login.
	AdminLoginBans = make(map[string]*AdminLoginBan)
	AdminLoginMu   sync.RWMutex

	// L2 FIX: UserLoginBans tracks brute-force attempts per "ip:username" for sub-user logins.
	UserLoginBans = make(map[string]*AdminLoginBan)
	UserLoginMu   sync.RWMutex
)
