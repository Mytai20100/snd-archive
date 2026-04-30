package snd

import "time"

const VERSION = "1.3.0a"

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
	FTPEnabled          bool   `yaml:"ftp_enabled"`
	FTPPort             string `yaml:"ftp_port"`
	FTPPassivePortStart int    `yaml:"ftp_passive_port_start"`
	FTPPassivePortEnd   int    `yaml:"ftp_passive_port_end"`
	CloudflareChallenge bool   `yaml:"cloudflare_challenge"`
	EmbedTitle          string `yaml:"embed_title"`
	EmbedDescription    string `yaml:"embed_description"`
	EmbedImageURL       string `yaml:"embed_image_url"`
	WebDAVEnabled       bool   `yaml:"webdav_enabled"`
	NodePrivateKey      string `yaml:"node_private_key"` // AES-256 key for node auth
	NodePublicKey       string `yaml:"node_public_key"`  // public key returned to child nodes
}

// AdminLoginBan tracks brute-force attempts for the admin account per IP.
type AdminLoginBan struct {
	FailCount   int       // total consecutive failures
	BanExpires  time.Time // when the current ban lifts
	BanDuration time.Duration // duration of the CURRENT ban (for escalation)
}

// BanLevel returns the ban duration for the given consecutive failure count.
// Schedule: 3 fails→5m, +fails→35m, +fails→1h, +fails→1d, +fails→7d, +fails→30d
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

// UserAccount represents a sub-user account managed by admin.
type UserAccount struct {
	UUID         string       `yaml:"uuid"`
	Username     string       `yaml:"username"`
	Email        string       `yaml:"email"`
	PasswordHash string       `yaml:"password_hash"`
	APIToken     string       `yaml:"api_token"`
	StorageLimit int64        `yaml:"storage_limit"` // bytes; -1 = unlimited
	UsedStorage  int64        `yaml:"used_storage"`
	RequestCount int64        `yaml:"request_count"`
	CreatedAt    time.Time    `yaml:"created_at"`
	IsActive     bool         `yaml:"is_active"`
	IsAdmin      bool         `yaml:"is_admin"` // grants admin-level privileges
	Settings     UserSettings `yaml:"settings"`
}

type FilePermission struct {
	IsPublic    bool   `json:"is_public"`
	Token       string `json:"token,omitempty"`
	Mode        uint32 `json:"mode,omitempty"`
	PublicToken string `json:"public_token,omitempty"` // anonymous-access token; set when IsPublic=true, cleared when private
}

type FolderPermission struct {
	IsPublic    bool   `json:"is_public"`
	Token       string `json:"token,omitempty"`
	PublicToken string `json:"public_token,omitempty"` // anonymous-access token; set when IsPublic=true, cleared when private
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
	IsPublic    bool   `json:"is_public"`
	PublicToken string `json:"public_token,omitempty"` // only set when IsPublic=true
	Owner       string `json:"owner,omitempty"`        // "admin" or username of sub-user
	UserUUID    string `json:"user_uuid,omitempty"`    // non-empty for user files
	RawPath     string `json:"raw_path,omitempty"`     // full relative path for user files
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
	IsAdmin    bool   // true = admin account from config
	UserUUID   string // set for sub-user accounts
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
