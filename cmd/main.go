package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"snd-archive/snd"
	"snd-archive/web"
)

func generateSelfSignedCert(certFile, keyFile string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "servernotdie"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	cf, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	kf, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	return nil
}

func main() {
	debug := flag.Bool("debug", false, "Enable debug logging")
	configFile := flag.String("config", "config.yml", "Path to config file")
	usersFile := flag.String("users", "users.yml", "Path to users file")
	publicDir := flag.String("dir", "public", "Path to public files directory")
	cfMode := flag.Bool("cf", false, "Run as child node (connect to main node)")
	cfKey := flag.String("key", "", "Private key (AES-256) for node authentication")
	cfNode := flag.String("node", "", "Main node URL (e.g. https://example.com or 192.168.1.9:8080)")
	flag.Parse()

	if *cfMode {
		if *cfKey == "" || *cfNode == "" {
			fmt.Fprintln(os.Stderr, "[CF] --key and --node are required with --cf")
			os.Exit(1)
		}

		snd.ConfigFile = *configFile
		snd.UsersFile = *usersFile
		snd.PublicDir = *publicDir
		snd.Init()

		nodeURL := *cfNode
		if len(nodeURL) > 0 && nodeURL[:4] != "http" {
			nodeURL = "http://" + nodeURL
		}
		connectURL := strings.TrimRight(nodeURL, "/") + "/api/v9/connect"
		fmt.Printf("[CF] Connecting to main node at %s ...\n", connectURL)

		selfIP := snd.Cfg.IP
		if selfIP == "" || selfIP == "0.0.0.0" {
			selfIP = "this-node"
		}

		payload, _ := json.Marshal(map[string]string{
			"key":  *cfKey,
			"node": selfIP,
			"name": snd.Cfg.SiteName,
		})

		resp, err := http.Post(connectURL, "application/json", bytes.NewReader(payload))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[CF] Connection failed: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "[CF] Main node rejected connection (status %d)\n", resp.StatusCode)
			os.Exit(1)
		}

		var reply struct {
			PublicKey string `json:"public_key"`
			Status    string `json:"status"`
		}
		json.NewDecoder(resp.Body).Decode(&reply)

		snd.Cfg.NodePrivateKey = *cfKey
		snd.Cfg.NodePublicKey = reply.PublicKey
		snd.SaveConfig()

		fmt.Printf("[CF] Connected! Public key received and saved. Status: %s\n", reply.Status)
		fmt.Println("[CF] This node will auto-connect on every restart.")
		return
	}

	snd.Debug = *debug
	snd.ConfigFile = *configFile
	snd.UsersFile = *usersFile
	snd.PublicDir = *publicDir

	if exePath, err := os.Executable(); err == nil {
		snd.WorkDir = filepath.Dir(exePath)
	} else {
		if cwd, err := os.Getwd(); err == nil {
			snd.WorkDir = cwd
		}
	}

	if snd.Cfg.NodePrivateKey != "" && snd.Cfg.NodePublicKey == "" {
		log.Printf("[CF] Node private key configured — attempting auto-connect...")
	}

	snd.Init()

	if err := os.MkdirAll(snd.PublicDir, 0755); err != nil {
		log.Fatalf("[ERROR] Cannot create public directory %q: %v", snd.PublicDir, err)
	}

	if snd.ChallengeMisconfigured() {
		log.Printf("[CHALLENGE] WARNING: challenge is enabled but Turnstile keys are missing - visitors will see a 'not configured' message until keys are set in /ad Settings")
	}

	web.SetupRoutes()

	if snd.Cfg.SFTPEnabled {
		go func() {
			log.Printf("[SFTP] Starting on port %s (key: %s)", snd.Cfg.SFTPPort, snd.Cfg.SFTPKeyPath)
			snd.StartSFTPServer()
		}()
	}

	if snd.Cfg.FTPEnabled {
		go func() {
			log.Printf("[FTP] Starting on port %s", snd.Cfg.FTPPort)
			snd.StartFTPServer()
		}()
	}

	addr := snd.Cfg.IP + ":" + snd.Cfg.Port

	server := &http.Server{
		Addr:              addr,
		Handler:           snd.ChallengeGate(snd.DDoSHandler(http.DefaultServeMux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if snd.Cfg.UseHTTPS {
		certMissing := false
		if _, err := os.Stat(snd.Cfg.CertFile); os.IsNotExist(err) {
			certMissing = true
		}
		keyMissing := false
		if _, err := os.Stat(snd.Cfg.KeyFile); os.IsNotExist(err) {
			keyMissing = true
		}

		if certMissing || keyMissing {
			log.Printf("[TLS] Cert/key not found — generating self-signed certificate...")
			if err := generateSelfSignedCert(snd.Cfg.CertFile, snd.Cfg.KeyFile); err != nil {
				log.Printf("[TLS] Failed to generate cert: %v — falling back to HTTP", err)
				goto serveHTTP
			}
			log.Printf("[TLS] Generated %s and %s (self-signed, valid 10 years)", snd.Cfg.CertFile, snd.Cfg.KeyFile)
		}

		fmt.Printf("[SND v%s] Listening on https://%s\n", snd.VERSION, addr)
		log.Fatal(server.ListenAndServeTLS(snd.Cfg.CertFile, snd.Cfg.KeyFile))
		return
	}

serveHTTP:
	fmt.Printf("[SND v%s] Listening on http://%s\n", snd.VERSION, addr)
	log.Fatal(server.ListenAndServe())
}
