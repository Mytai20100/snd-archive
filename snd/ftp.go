package snd

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StartFTPServer starts a minimal FTP server bound to Cfg.FTPPort.
// Supports: USER, PASS, QUIT, SYST, FEAT, PWD, CWD, CDUP, TYPE,
//           PASV, LIST, NLST, RETR, STOR, DELE, MKD, RMD, RNFR, RNTO, NOOP, SIZE, MDTM
func StartFTPServer() {
	addr := Cfg.IP + ":" + Cfg.FTPPort
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[FTP] Failed to listen on %s: %v", addr, err)
		return
	}
	log.Printf("[FTP] Server listening on %s (passive ports %d-%d)",
		addr, Cfg.FTPPassivePortStart, Cfg.FTPPassivePortEnd)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[FTP] Accept error: %v", err)
			continue
		}
		go handleFTPConn(conn)
	}
}

type ftpSession struct {
	conn       net.Conn
	cwd        string // virtual cwd, relative to baseDir
	loggedIn   bool
	username   string
	userUUID   string // empty = admin, non-empty = sub-user UUID
	passiveLn  net.Listener
	renameFrom string
	binaryMode bool
}

// baseDir returns the filesystem root for this session.
// Admin → PublicDir, sub-user → UserPublicDir(uuid).
func (s *ftpSession) baseDir() string {
	if s.userUUID != "" {
		return UserPublicDir(s.userUUID)
	}
	return PublicDir
}

func (s *ftpSession) rootedPath(p string) (string, error) {
	if p == "" || p == "." {
		p = s.cwd
	} else if !filepath.IsAbs(p) {
		p = filepath.Join(s.cwd, p)
	}
	p = filepath.Clean(p)
	base := s.baseDir()
	real := filepath.Join(base, p)
	abs, err := filepath.Abs(real)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, rootAbs) {
		return "", fmt.Errorf("path escapes root")
	}
	return abs, nil
}

func (s *ftpSession) send(code int, msg string) {
	line := fmt.Sprintf("%d %s\r\n", code, msg)
	s.conn.Write([]byte(line))
}

func (s *ftpSession) openPassive() (net.Listener, error) {
	for port := Cfg.FTPPassivePortStart; port <= Cfg.FTPPassivePortEnd; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", Cfg.IP, port))
		if err == nil {
			return ln, nil
		}
	}
	return nil, fmt.Errorf("no passive ports available")
}

func handleFTPConn(conn net.Conn) {
	defer conn.Close()
	s := &ftpSession{conn: conn, cwd: "/"}
	s.send(220, "ServerNotDie FTP server ready")

	buf := make([]byte, 4096)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		line := strings.TrimRight(string(buf[:n]), "\r\n")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		if Debug {
			log.Printf("[FTP] CMD: %s %s", cmd, arg)
		}

		switch cmd {
		case "USER":
			s.username = arg
			s.send(331, "Password required")

		case "PASS":
			if s.username == Cfg.Username && arg == Cfg.Password {
				// Admin login
				s.loggedIn = true
				s.send(230, "Login successful")
			} else {
				// Sub-user login: look up by username and verify bcrypt hash
				u := GetUserByUsername(s.username)
				if u != nil && u.IsActive && CheckPassword(u.PasswordHash, arg) {
					s.userUUID = u.UUID
					// Ensure user directory exists
					EnsureUserDir(u.UUID)
					s.loggedIn = true
					s.send(230, "Login successful")
				} else {
					s.send(530, "Login incorrect")
					return
				}
			}

		case "QUIT":
			s.send(221, "Goodbye")
			return

		case "NOOP":
			s.send(200, "OK")

		case "SYST":
			s.send(215, "UNIX Type: L8")

		case "FEAT":
			conn.Write([]byte("211-Features:\r\n PASV\r\n SIZE\r\n MDTM\r\n UTF8\r\n211 End\r\n"))

		case "OPTS":
			s.send(200, "OK")

		case "TYPE":
			s.binaryMode = strings.ToUpper(arg) == "I"
			s.send(200, "Type set")

		case "PWD":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			s.send(257, fmt.Sprintf("%q is current directory", s.cwd))

		case "CWD":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			var newDir string
			if filepath.IsAbs(arg) {
				newDir = arg
			} else {
				newDir = filepath.Join(s.cwd, arg)
			}
			real, err := s.rootedPath(newDir)
			if err != nil {
				s.send(550, "No such directory")
				continue
			}
			info, err := os.Stat(real)
			if err != nil || !info.IsDir() {
				s.send(550, "No such directory")
				continue
			}
			s.cwd = filepath.Clean(newDir)
			s.send(250, "Directory changed")

		case "CDUP":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			s.cwd = filepath.Dir(s.cwd)
			if s.cwd == "." {
				s.cwd = "/"
			}
			s.send(200, "OK")

		case "PASV":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			if s.passiveLn != nil {
				s.passiveLn.Close()
				s.passiveLn = nil
			}
			ln, err := s.openPassive()
			if err != nil {
				s.send(425, "Cannot open passive connection")
				continue
			}
			s.passiveLn = ln
			addr := ln.Addr().(*net.TCPAddr)
			// Use 127.0.0.1 for loopback connections, otherwise use server IP.
			ip := Cfg.IP
			if ip == "0.0.0.0" {
				// Try to get the local IP from the control connection.
				localAddr := conn.LocalAddr().(*net.TCPAddr)
				ip = localAddr.IP.String()
				if ip == "" || ip == "<nil>" {
					ip = "127.0.0.1"
				}
			}
			ipParts := strings.Split(ip, ".")
			if len(ipParts) != 4 {
				ipParts = []string{"127", "0", "0", "1"}
			}
			port := addr.Port
			p1 := port / 256
			p2 := port % 256
			s.send(227, fmt.Sprintf("Entering Passive Mode (%s,%s,%s,%s,%d,%d)",
				ipParts[0], ipParts[1], ipParts[2], ipParts[3], p1, p2))

		case "LIST", "NLST":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			if s.passiveLn == nil {
				s.send(425, "Use PASV first")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			entries, err := os.ReadDir(real)
			if err != nil {
				s.send(550, "Cannot list directory")
				continue
			}
			s.send(150, "Opening data connection")
			dataConn, err := s.passiveLn.Accept()
			s.passiveLn.Close()
			s.passiveLn = nil
			if err != nil {
				s.send(425, "Data connection failed")
				continue
			}
			dataConn.SetDeadline(time.Now().Add(30 * time.Second))
			for _, e := range entries {
				info, err := e.Info()
				if err != nil {
					continue
				}
				if cmd == "NLST" {
					dataConn.Write([]byte(info.Name() + "\r\n"))
				} else {
					// Unix-style listing
					mode := info.Mode()
					typeChar := "-"
					if info.IsDir() {
						typeChar = "d"
					}
					dataConn.Write([]byte(fmt.Sprintf("%s%s 1 ftp ftp %12d %s %s\r\n",
						typeChar, mode.String()[1:],
						info.Size(),
						info.ModTime().Format("Jan _2 15:04"),
						info.Name(),
					)))
				}
			}
			dataConn.Close()
			s.send(226, "Transfer complete")

		case "RETR":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			if s.passiveLn == nil {
				s.send(425, "Use PASV first")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			f, err := os.Open(real)
			if err != nil {
				s.send(550, "File not found")
				continue
			}
			s.send(150, "Opening data connection")
			dataConn, err := s.passiveLn.Accept()
			s.passiveLn.Close()
			s.passiveLn = nil
			if err != nil {
				f.Close()
				s.send(425, "Data connection failed")
				continue
			}
			dataConn.SetDeadline(time.Now().Add(10 * time.Minute))
			buf := make([]byte, 256*1024)
			io.CopyBuffer(dataConn, f, buf)
			f.Close()
			dataConn.Close()
			s.send(226, "Transfer complete")

		case "STOR":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			if s.passiveLn == nil {
				s.send(425, "Use PASV first")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			if err := os.MkdirAll(filepath.Dir(real), 0755); err != nil {
				s.send(550, "Cannot create directory")
				continue
			}
			s.send(150, "Opening data connection")
			dataConn, err := s.passiveLn.Accept()
			s.passiveLn.Close()
			s.passiveLn = nil
			if err != nil {
				s.send(425, "Data connection failed")
				continue
			}
			dataConn.SetDeadline(time.Now().Add(10 * time.Minute))
			f, err := os.Create(real)
			if err != nil {
				dataConn.Close()
				s.send(550, "Cannot create file")
				continue
			}
			buf2 := make([]byte, 256*1024)
			io.CopyBuffer(f, dataConn, buf2)
			f.Close()
			dataConn.Close()
			UpdateStats()
			s.send(226, "Transfer complete")

		case "DELE":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			if err := os.Remove(real); err != nil {
				s.send(550, "Delete failed")
				continue
			}
			s.send(250, "Deleted")

		case "MKD":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			if err := os.MkdirAll(real, 0755); err != nil {
				s.send(550, "Cannot create directory")
				continue
			}
			s.send(257, fmt.Sprintf("%q created", arg))

		case "RMD":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			if err := os.RemoveAll(real); err != nil {
				s.send(550, "Remove failed")
				continue
			}
			s.send(250, "Removed")

		case "RNFR":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			if _, err := os.Stat(real); err != nil {
				s.send(550, "File not found")
				continue
			}
			s.renameFrom = real
			s.send(350, "Ready for RNTO")

		case "RNTO":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			if s.renameFrom == "" {
				s.send(503, "Send RNFR first")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			if err := os.Rename(s.renameFrom, real); err != nil {
				s.send(550, "Rename failed")
				continue
			}
			s.renameFrom = ""
			s.send(250, "Renamed")

		case "SIZE":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			info, err := os.Stat(real)
			if err != nil {
				s.send(550, "File not found")
				continue
			}
			s.send(213, strconv.FormatInt(info.Size(), 10))

		case "MDTM":
			if !s.loggedIn {
				s.send(530, "Not logged in")
				continue
			}
			real, err := s.rootedPath(arg)
			if err != nil {
				s.send(550, "Permission denied")
				continue
			}
			info, err := os.Stat(real)
			if err != nil {
				s.send(550, "File not found")
				continue
			}
			s.send(213, info.ModTime().UTC().Format("20060102150405"))

		default:
			s.send(502, "Command not implemented")
		}
	}
}
