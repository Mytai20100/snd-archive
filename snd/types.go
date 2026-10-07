package snd

import "time"

const VERSION = "1.3.0a"

type Config struct {
	IP                  string   `yaml:"ip"`
	Port                string   `yaml:"port"`
	SiteName            string   `yaml:"site_name"`
	IconURL             string   `yaml:"icon_url"`
	Username            string   `yaml:"username"`
	Password            string   `yaml:"password"`
	UseHTTPS            bool     `yaml:"use_https"`
	CertFile            string   `yaml:"cert_file"`
	KeyFile             string   `yaml:"key_file"`
	APIToken            string   `yaml:"api_token"`
	Enable2FA           bool     `yaml:"enable_2fa"`
	DiscordWebhook      string   `yaml:"discord_webhook"`
	SFTPEnabled         bool     `yaml:"sftp_enabled"`
	SFTPPort            string   `yaml:"sftp_port"`
	SFTPKeyPath         string   `yaml:"sftp_key_path"`
	FTPEnabled          bool     `yaml:"ftp_enabled"`
	FTPPort             string   `yaml:"ftp_port"`
	FTPPassivePortStart int      `yaml:"ftp_passive_port_start"`
	FTPPassivePortEnd   int      `yaml:"ftp_passive_port_end"`
	CloudflareChallenge bool     `yaml:"cloudflare_challenge"`
	TrustedProxy        bool     `yaml:"trusted_proxy"`
	TrustedProxies      []string `yaml:"trusted_proxies"`
	PublicBaseURL       string   `yaml:"public_base_url"`
	EmbedTitle          string   `yaml:"embed_title"`
	EmbedDescription    string   `yaml:"embed_description"`
	EmbedImageURL       string   `yaml:"embed_image_url"`
	WebDAVEnabled       bool     `yaml:"webdav_enabled"`
	NodePrivateKey      string   `yaml:"node_private_key"`
	NodePublicKey       string   `yaml:"node_public_key"`
}

type AdminLoginBan struct {
	FailCount   int
	BanExpires  time.Time
	BanDuration time.Duration
}

func BanLevel(failCount int) time.Duration {
	switch {
	case failCount <= 3:
		return 0
	case failCount == 4:
		return 5 * time.Minute
	case failCount == 5:
		return 35 * time.Minute
	case failCount == 6:
		return 1 * time.Hour
	case failCount == 7:
		return 24 * time.Hour
	case failCount == 8:
		return 7 * 24 * time.Hour
	default:
		return 30 * 24 * time.Hour
	}
}

type TwoFACode struct {
	Code      string
	ExpiresAt time.Time
	Used      bool
}

type SessionInfo struct {
	SessionID  string
	IP         string
	WebRTCIP   string
	UserAgent  string
	OS         string
	Browser    string
	LoginTime  time.Time
	LastAccess time.Time
	ExpiresAt  time.Time
	IsAdmin    bool
	UserUUID   string
}

type UserSettings struct {
	Theme           string `yaml:"theme"             json:"theme"`
	BackgroundURL   string `yaml:"background_url"    json:"background_url"`
	BgMusicURL      string `yaml:"bg_music_url"      json:"bg_music_url"`
	Language        string `yaml:"language"          json:"language"`
	ShowDirectLinks bool   `yaml:"show_direct_links" json:"show_direct_links"`
	EnableQR        bool   `yaml:"enable_qr"         json:"enable_qr"`
}

type UserAccount struct {
	UUID         string       `yaml:"uuid"`
	Username     string       `yaml:"username"`
	Email        string       `yaml:"email"`
	PasswordHash string       `yaml:"password_hash"`
	APIToken     string       `yaml:"api_token"`
	StorageLimit int64        `yaml:"storage_limit"`
	UsedStorage  int64        `yaml:"used_storage"`
	RequestCount int64        `yaml:"request_count"`
	CreatedAt    time.Time    `yaml:"created_at"`
	IsActive     bool         `yaml:"is_active"`
	IsAdmin      bool         `yaml:"is_admin"`
	Settings     UserSettings `yaml:"settings"`
}

type FilePermission struct {
	IsPublic    bool   `json:"is_public"`
	Token       string `json:"token,omitempty"`
	Mode        uint32 `json:"mode,omitempty"`
	PublicToken string `json:"public_token,omitempty"`
}

type FolderPermission struct {
	IsPublic    bool   `json:"is_public"`
	Token       string `json:"token,omitempty"`
	PublicToken string `json:"public_token,omitempty"`
}

type FileMetadata struct {
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Icon          string    `json:"icon"`
	Size          int64     `json:"size"`
	ModTime       time.Time `json:"mod_time"`
	DownloadCount int       `json:"download_count"`
	Mode          uint32    `json:"mode"`
}

type FileMetadataWithPermission struct {
	FileMetadata
	IsPublic    bool   `json:"is_public"`
	PublicToken string `json:"public_token,omitempty"`
	Owner       string `json:"owner,omitempty"`
	UserUUID    string `json:"user_uuid,omitempty"`
	RawPath     string `json:"raw_path,omitempty"`
}

type AccessLog struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	WebRTCIP  string    `json:"webrtc_ip,omitempty"`
	Action    string    `json:"action"`
	Path      string    `json:"path"`
	UserAgent string    `json:"user_agent"`
}

type Stats struct {
	TotalFiles    int64
	TotalSize     int64
	TotalRequests int64
}
