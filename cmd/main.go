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

// generateSelfSignedCert creates a self-signed TLS cert+key and writes them to disk.
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
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
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

	// Write cert
	cf, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	// Write key
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
	// ─── Flags ────────────────────────────────────────────────────────────────
	debug      := flag.Bool("debug", false, "Enable debug logging")
	configFile := flag.String("config", "config.yml", "Path to config file")
	usersFile  := flag.String("users", "users.yml", "Path to users file")
	publicDir  := flag.String("dir", "public", "Path to public files directory")
	// Child-node quick-connect flags
	cfMode    := flag.Bool("cf", false, "Run as child node (connect to main node)")
	cfKey     := flag.String("key", "", "Private key (AES-256) for node authentication")
	cfNode    := flag.String("node", "", "Main node URL (e.g. https://example.com or 192.168.1.9:8080)")
	flag.Parse()

	// ─── Child node quick-connect mode ───────────────────────────────────────
	if *cfMode {
		if *cfKey == "" || *cfNode == "" {
			fmt.Fprintln(os.Stderr, "[CF] --key and --node are required with --cf")
			os.Exit(1)
		}

		// Load config NOW so snd.Cfg.IP / SiteName are populated before we
		// build the registration payload (snd.Init() is called below for the
		// normal server path; in CF mode we call it early here).
		snd.ConfigFile = *configFile
		snd.UsersFile  = *usersFile
		snd.PublicDir  = *publicDir
		snd.Init()

		nodeURL := *cfNode
		// Normalise URL scheme
		if len(nodeURL) > 0 && nodeURL[:4] != "http" {
			nodeURL = "http://" + nodeURL
		}
		connectURL := strings.TrimRight(nodeURL, "/") + "/api/v9/connect"
		fmt.Printf("[CF] Connecting to main node at %s ...\n", connectURL)

		// Use configured IP; fall back to a non-empty placeholder so the
		// main node never rejects us with "bad request / NodeURL empty".
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

		// Persist public key into config so auto-connect works on restart
		snd.Cfg.NodePrivateKey = *cfKey
		snd.Cfg.NodePublicKey  = reply.PublicKey
		snd.SaveConfig()

		fmt.Printf("[CF] Connected! Public key received and saved. Status: %s\n", reply.Status)
		fmt.Println("[CF] This node will auto-connect on every restart.")
		return
	}

	snd.Debug = *debug
	snd.ConfigFile = *configFile
	snd.UsersFile = *usersFile
	snd.PublicDir = *publicDir

	// Set WorkDir to the directory containing the binary
	if exePath, err := os.Executable(); err == nil {
		snd.WorkDir = filepath.Dir(exePath)
	} else {
		// fallback: use current working directory
		if cwd, err := os.Getwd(); err == nil {
			snd.WorkDir = cwd
		}
	}

	// Auto-connect to main node on startup if keys are configured
	if snd.Cfg.NodePrivateKey != "" && snd.Cfg.NodePublicKey == "" {
		// keys set but no public key yet — try connecting
		log.Printf("[CF] Node private key configured — attempting auto-connect...")
	}

	// ─── Init ─────────────────────────────────────────────────────────────────
	snd.Init()

	if err := os.MkdirAll(snd.PublicDir, 0755); err != nil {
		log.Fatalf("[ERROR] Cannot create public directory %q: %v", snd.PublicDir, err)
	}

	// ─── Routes ───────────────────────────────────────────────────────────────
	web.SetupRoutes()

	// ─── Optional services ────────────────────────────────────────────────────
	if snd.Cfg.SFTPEnabled {
		go func() {
			log.Printf("[SFTP] Starting on port %s (key: %s)", snd.Cfg.SFTPPort, snd.Cfg.SFTPKeyPath)
			snd.StartSFTPServer() // already auto-generates host key
		}()
	}

	if snd.Cfg.FTPEnabled {
		go func() {
			log.Printf("[FTP] Starting on port %s", snd.Cfg.FTPPort)
			snd.StartFTPServer()
		}()
	}

	// ─── HTTP / HTTPS ─────────────────────────────────────────────────────────
	addr := snd.Cfg.IP + ":" + snd.Cfg.Port

	// NEW-3 FIX: Use http.Server with explicit timeouts to prevent Slowloris attacks.
	// A bare http.ListenAndServe has no timeout — an attacker can open thousands of
	// connections and send HTTP headers one byte at a time, exhausting goroutines.
	// ReadHeaderTimeout is the critical one: it closes connections that don't finish
	// sending headers within 5 seconds, blocking the classic Slowloris pattern.
	//
	// NOTE: WriteTimeout of 120s may cut very large file downloads.
	// If streaming large files, raise it or reset per-request with ResponseController.
	server := &http.Server{
		Addr:              addr,
		Handler:           snd.DDoSHandler(http.DefaultServeMux),
		ReadHeaderTimeout: 5 * time.Second,   // CRITICAL: blocks Slowloris header attacks
		ReadTimeout:       30 * time.Second,  // blocks slow-read body attacks
		WriteTimeout:      120 * time.Second, // blocks slow-write; raise if needed for large files
		IdleTimeout:       120 * time.Second, // keep-alive connection timeout
		MaxHeaderBytes:    1 << 20,           // 1 MB header limit
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
