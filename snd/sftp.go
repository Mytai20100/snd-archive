package snd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func loadOrGenerateHostKey(keyPath string) (ssh.Signer, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				return ssh.NewSignerFromKey(key)
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(keyPath, pemBlock, 0600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	log.Printf("[SFTP] Generated new host key: %s", keyPath)
	return ssh.NewSignerFromKey(key)
}

func StartSFTPServer() {
	signer, err := loadOrGenerateHostKey(Cfg.SFTPKeyPath)
	if err != nil {
		log.Printf("[SFTP] Failed to load/generate host key: %v", err)
		return
	}

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == Cfg.Username && string(pass) == Cfg.Password {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"user": c.User(),
					},
				}, nil
			}
			return nil, fmt.Errorf("invalid credentials for user %q", c.User())
		},
	}
	sshConfig.AddHostKey(signer)

	addr := Cfg.IP + ":" + Cfg.SFTPPort
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[SFTP] Failed to listen on %s: %v", addr, err)
		return
	}
	log.Printf("[SFTP] Server listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[SFTP] Accept error: %v", err)
			continue
		}
		go handleSFTPConn(conn, sshConfig)
	}
}

func handleSFTPConn(conn net.Conn, sshConfig *ssh.ServerConfig) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[SFTP] Connection from %s", remoteAddr)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("[SFTP] SSH handshake failed from %s: %v", remoteAddr, err)
		return
	}
	defer sshConn.Close()

	log.Printf("[SFTP] Authenticated user %q from %s", sshConn.User(), remoteAddr)
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, requests, err := newChan.Accept()
		if err != nil {
			log.Printf("[SFTP] Accept channel error: %v", err)
			continue
		}

		go func(ch ssh.Channel, requests <-chan *ssh.Request) {
			defer ch.Close()

			for req := range requests {
				switch req.Type {
				case "subsystem":
					if len(req.Payload) >= 4 {
						subsystem := string(req.Payload[4:])
						if subsystem == "sftp" {
							req.Reply(true, nil)
							handleSFTPSession(ch)
							return
						}
					}
					req.Reply(false, nil)
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(ch, requests)
	}
}

func handleSFTPSession(ch ssh.Channel) {
	root := &sftpHandler{root: PublicDir}
	server := sftp.NewRequestServer(ch, sftp.Handlers{
		FileGet:  root,
		FilePut:  root,
		FileCmd:  root,
		FileList: root,
	})

	if err := server.Serve(); err != nil && err != io.EOF {
		log.Printf("[SFTP] Session ended: %v", err)
	}
}

type sftpHandler struct {
	root string
}

func (h *sftpHandler) realPath(p string) (string, error) {
	p = filepath.Clean("/" + p)
	real := filepath.Join(h.root, p)
	abs, err := filepath.Abs(real)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(h.root)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, rootAbs) {
		return "", fmt.Errorf("path escapes root: %s", p)
	}
	return abs, nil
}

func (h *sftpHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path, err := h.realPath(r.Filepath)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (h *sftpHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path, err := h.realPath(r.Filepath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (h *sftpHandler) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Setstat":
		return nil
	case "Rename":
		old, err := h.realPath(r.Filepath)
		if err != nil {
			return err
		}
		newPath, err := h.realPath(r.Target)
		if err != nil {
			return err
		}
		return os.Rename(old, newPath)
	case "Rmdir":
		path, err := h.realPath(r.Filepath)
		if err != nil {
			return err
		}
		return os.RemoveAll(path)
	case "Remove":
		path, err := h.realPath(r.Filepath)
		if err != nil {
			return err
		}
		return os.Remove(path)
	case "Mkdir":
		path, err := h.realPath(r.Filepath)
		if err != nil {
			return err
		}
		return os.MkdirAll(path, 0755)
	case "Link", "Symlink":
		return fmt.Errorf("symlinks not supported")
	}
	return fmt.Errorf("unsupported command: %s", r.Method)
}

func (h *sftpHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := h.realPath(r.Filepath)
	if err != nil {
		return nil, err
	}

	switch r.Method {
	case "List":
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		infos := make([]os.FileInfo, 0, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			infos = append(infos, info)
		}
		return listAt(infos), nil

	case "Stat":
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return listAt([]os.FileInfo{info}), nil

	case "Readlink":
		target, err := os.Readlink(path)
		if err != nil {
			return nil, err
		}
		return listAt([]os.FileInfo{&syntheticFileInfo{name: target}}), nil
	}

	return nil, fmt.Errorf("unsupported list method: %s", r.Method)
}

type listAt []os.FileInfo

func (l listAt) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

type syntheticFileInfo struct {
	name string
}

func (s *syntheticFileInfo) Name() string      { return s.name }
func (s *syntheticFileInfo) Size() int64       { return 0 }
func (s *syntheticFileInfo) Mode() os.FileMode { return 0444 }
func (s *syntheticFileInfo) ModTime() time.Time { return time.Time{} }
func (s *syntheticFileInfo) IsDir() bool       { return false }
func (s *syntheticFileInfo) Sys() interface{}  { return nil }
