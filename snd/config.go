package snd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadConfig() Config {
	cfg := Config{
		IP:                  "0.0.0.0",
		Port:                "8080",
		SiteName:            "servernotdie",
		IconURL:             "https://cdn-icons-png.flaticon.com/512/716/716784.png",
		Username:            "admin",
		Password:            "admin",
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
