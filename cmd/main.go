package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
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
	debug := flag.Bool("debug", false, "Enable debug logging")
	configFile := flag.String("config", "config.yml", "Path to config file")
	usersFile := flag.String("users", "users.yml", "Path to users file")
	publicDir := flag.String("dir", "public", "Path to public files directory")
	flag.Parse()

	snd.Debug = *debug
	snd.ConfigFile = *configFile
	snd.UsersFile = *usersFile
	snd.PublicDir = *publicDir

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
		log.Fatal(http.ListenAndServeTLS(addr, snd.Cfg.CertFile, snd.Cfg.KeyFile, snd.DDoSHandler(http.DefaultServeMux)))
		return
	}

serveHTTP:
	fmt.Printf("[SND v%s] Listening on http://%s\n", snd.VERSION, addr)
	log.Fatal(http.ListenAndServe(addr, snd.DDoSHandler(http.DefaultServeMux)))
}
