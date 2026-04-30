package snd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadConfig() Config {
	// M3 FIX: Generate a random password for the first run.
	// This prevents brute-force attacks against the default admin/admin credential.
	// The generated password is printed to the terminal at startup.
	initialPassword := generateInitialPassword()

	cfg := Config{
		IP:                  "0.0.0.0",
		Port:                "8080",
		SiteName:            "servernotdie",
		IconURL:             "https://cdn-icons-png.flaticon.com/512/716/716784.png",
		Username:            "admin",
		Password:            initialPassword,
		UseHTTPS:            true,
		CertFile:            "server.crt",
		KeyFile:             "server.key",
		APIToken:            GenerateRandomToken(32),
		Enable2FA:           false,
		DiscordWebhook:      "",
		SFTPEnabled:         false,
		SFTPPort:            "2022",
		SFTPKeyPath:         "sftp_key.pem",
		FTPEnabled:          false,
		FTPPort:             "2121",
		FTPPassivePortStart: 50000,
		FTPPassivePortEnd:   50100,
		CloudflareChallenge: false,
		EmbedTitle:          "",
		EmbedDescription:    "File sharing powered by servernotdie",
		EmbedImageURL:       "",
	}

	data, err := os.ReadFile(ConfigFile)
	if err == nil {
		yaml.Unmarshal(data, &cfg)
	} else {
		data, _ := yaml.Marshal(cfg)
		os.WriteFile(ConfigFile, data, 0644)
		fmt.Printf("Created default config file: %s\n", ConfigFile)
		fmt.Printf("Default API Token: %s\n", cfg.APIToken)
		fmt.Printf("==========================================================\n")
		fmt.Printf("FIRST RUN — Auto-generated admin password: %s\n", cfg.Password)
		fmt.Printf("Please change this password after logging in!\n")
		fmt.Printf("==========================================================\n")
	}

	// Auto-generate NodePrivateKey if missing (required for --cf node auth)
	changed := false
	if cfg.NodePrivateKey == "" {
		cfg.NodePrivateKey = GenerateRandomToken(32)
		changed = true
		fmt.Printf("Generated NodePrivateKey: %s\n", cfg.NodePrivateKey)
	}
	if cfg.NodePublicKey == "" {
		cfg.NodePublicKey = GenerateRandomToken(32)
		changed = true
	}
	if changed {
		d2, _ := yaml.Marshal(cfg)
		os.WriteFile(ConfigFile, d2, 0600)
	}

	return cfg
}

// GenerateRandomToken produces a cryptographically secure hex token.
// byteLen specifies how many random bytes; returned string is byteLen*2 hex chars.
func GenerateRandomToken(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func GetProtocol() string {
	if Cfg.UseHTTPS {
		return "https"
	}
	return "http"
}

func Init() {
	Cfg = LoadConfig()
	LoadUsers()
	LoadDownloadCounts()
	LoadFilePermissions()
	LoadFolderPermissions()
	LoadAccessLogs()
	UpdateStats()
	LoadNodes()
	LoadDDoSConfig()
	LoadTrafficStats()
	LoadSiteSettings()
	LoadIconConfig()
}

// SaveConfig writes the current Cfg back to ConfigFile.
func SaveConfig() {
	data, err := yaml.Marshal(&Cfg)
	if err != nil {
		return
	}
	os.WriteFile(ConfigFile, data, 0600)
}

// generateInitialPassword creates a random 16-character alphanumeric password
// used on first boot instead of the insecure "admin" default.
func generateInitialPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
