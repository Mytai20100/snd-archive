package snd

import "time"

const VERSION = "1.3.3"

type Config struct {
	IP                  string `yaml:"ip"`
	Port                string `yaml:"port"`
	SiteName            string `yaml:"site_name"`
	IconURL             string `yaml:"icon_url"`
	Username            string `yaml:"username"`
	Password            string `yaml:"password"`
	UseHTTPS            bool   `yaml:"use_https"`
	CertFile            string `yaml:"cert_file"`
	KeyFile             string `yaml:"key_file"`
	APIToken            string `yaml:"api_token"`
	Enable2FA           bool   `yaml:"enable_2fa"`
	DiscordWebhook      string `yaml:"discord_webhook"`
	SFTPEnabled         bool   `yaml:"sftp_enabled"`
	SFTPPort            string `yaml:"sftp_port"`
	SFTPKeyPath         string `yaml:"sftp_key_path"`
	CloudflareChallenge bool   `yaml:"cloudflare_challenge"`
}

type FilePermission struct {
	IsPublic bool   `json:"is_public"`
	Token    string `json:"token,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
}

type FolderPermission struct {
	IsPublic bool   `json:"is_public"`
	Token    string `json:"token,omitempty"`
}

type FileMetadata struct {
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Size          int64     `json:"size"`
	ModTime       time.Time `json:"mod_time"`
	DownloadCount int       `json:"download_count"`
	Mode          uint32    `json:"mode"`
}

type FileMetadataWithPermission struct {
	FileMetadata
	IsPublic bool `json:"is_public"`
}

type TwoFACode struct {
	Code      string
	ExpiresAt time.Time
	Used      bool
}

type SessionInfo struct {
	SessionID  string
	IP         string
	UserAgent  string
	OS         string
	Browser    string
	LoginTime  time.Time
	LastAccess time.Time
	ExpiresAt  time.Time
}

type AccessLog struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Action    string    `json:"action"`
	Path      string    `json:"path"`
	UserAgent string    `json:"user_agent"`
}

type Stats struct {
	TotalFiles    int64
	TotalSize     int64
	TotalRequests int64
}
