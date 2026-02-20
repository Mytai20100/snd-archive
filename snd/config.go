package snd

import (
	"fmt"
	"os"
	"time"

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
		APIToken:            GenerateRandomToken(82),
		Enable2FA:           false,
		DiscordWebhook:      "",
		SFTPEnabled:         false,
		SFTPPort:            "2022",
		SFTPKeyPath:         "sftp_key.pem",
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

func GenerateRandomToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func GetProtocol() string {
	if Cfg.UseHTTPS {
		return "https"
	}
	return "http"
}

func Init() {
	Cfg = LoadConfig()
	LoadDownloadCounts()
	LoadFilePermissions()
	LoadFolderPermissions()
	LoadAccessLogs()
	UpdateStats()
}
