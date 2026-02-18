package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"snd-archive/snd"
	"snd-archive/web"
)

func main() {
	debugFlag := flag.Bool("debug", false, "Enable debug mode")
	dFlag := flag.Bool("d", false, "Enable debug mode (short)")
	flag.Parse()

	snd.Debug = *debugFlag || *dFlag

	if snd.Debug {
		log.Println("[DEBUG] Debug mode enabled")
	}

	if err := os.MkdirAll(snd.PublicDir, 0755); err != nil {
		log.Fatalf("Failed to create public directory: %v", err)
	}

	snd.Init()
	web.SetupRoutes()

	addr := snd.Cfg.IP + ":" + snd.Cfg.Port

	fmt.Printf("ServerNotDie v%s\n", snd.VERSION)
	fmt.Printf("Server starting on %s://%s\n", snd.GetProtocol(), addr)
	fmt.Printf("API Token: `%s`\n", snd.Cfg.APIToken)
	fmt.Printf("2FA Enabled: %v\n", snd.Cfg.Enable2FA)
	fmt.Printf("Cloudflare Challenge: %v\n", snd.Cfg.CloudflareChallenge)
	if snd.Debug {
		fmt.Println("Debug Mode: ENABLED")
	}

	if snd.Cfg.SFTPEnabled {
		go snd.StartSFTPServer()
	}

	if snd.Cfg.UseHTTPS {
		if err := http.ListenAndServeTLS(addr, snd.Cfg.CertFile, snd.Cfg.KeyFile, nil); err != nil {
			log.Fatalf("HTTPS Server failed: %v", err)
		}
	} else {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("HTTP Server failed: %v", err)
		}
	}
}
