package snd

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	trustedProxyNets []netip.Prefix
	trustedProxyOnce sync.Once
	trustedProxyMu   sync.Mutex
)

var defaultTrustedProxyCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

func resetTrustedProxyCache() {
	trustedProxyMu.Lock()
	trustedProxyNets = nil
	trustedProxyOnce = sync.Once{}
	trustedProxyMu.Unlock()
}

func loadTrustedProxyNets() {
	trustedProxyMu.Lock()
	defer trustedProxyMu.Unlock()
	trustedProxyOnce.Do(func() {
		list := Cfg.TrustedProxies
		if len(list) == 0 && Cfg.TrustedProxy {
			list = defaultTrustedProxyCIDRs
		}
		for _, entry := range list {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if pfx, err := netip.ParsePrefix(entry); err == nil {
				trustedProxyNets = append(trustedProxyNets, pfx.Masked())
				continue
			}
			if addr, err := netip.ParseAddr(entry); err == nil {
				trustedProxyNets = append(trustedProxyNets, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
	})
}

func isTrustedProxyAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	loadTrustedProxyNets()
	for _, pfx := range trustedProxyNets {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func parseIPValue(raw string) netip.Addr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}
	}
	if strings.HasPrefix(raw, "[") {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			raw = host
		} else {
			raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
		}
	} else if strings.Count(raw, ":") == 1 {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			raw = host
		}
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func remotePeerAddr(r *http.Request) netip.Addr {
	if r == nil {
		return netip.Addr{}
	}
	return parseIPValue(r.RemoteAddr)
}

func GetPeerIP(r *http.Request) netip.Addr {
	return remotePeerAddr(r)
}

func IsLoopbackIP(s string) bool {
	addr := parseIPValue(s)
	return addr.IsValid() && addr.IsLoopback()
}

func IsPrivateIP(s string) bool {
	addr := parseIPValue(s)
	if !addr.IsValid() {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

func GetClientIP(r *http.Request) string {
	peer := remotePeerAddr(r)
	if !peer.IsValid() {
		return ""
	}
	if !isTrustedProxyAddr(peer) {
		return peer.String()
	}
	for _, hdr := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if v := parseIPValue(r.Header.Get(hdr)); v.IsValid() {
			return v.String()
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			v := parseIPValue(parts[i])
			if !v.IsValid() {
				continue
			}
			if isTrustedProxyAddr(v) {
				continue
			}
			return v.String()
		}
	}
	return peer.String()
}

func requestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	peer := remotePeerAddr(r)
	if !isTrustedProxyAddr(peer) {
		return false
	}
	proto := strings.TrimSpace(strings.ToLower(r.Header.Get("X-Forwarded-Proto")))
	if idx := strings.Index(proto, ","); idx >= 0 {
		proto = strings.TrimSpace(proto[:idx])
	}
	return proto == "https"
}

func trustedHeader(r *http.Request, name string) string {
	if r == nil {
		return ""
	}
	peer := remotePeerAddr(r)
	if !isTrustedProxyAddr(peer) {
		return ""
	}
	v := strings.TrimSpace(r.Header.Get(name))
	if v == "" {
		return ""
	}
	if idx := strings.IndexAny(v, " \t,"); idx >= 0 {
		v = v[:idx]
	}
	if strings.ContainsAny(v, "/\\") {
		return ""
	}
	return v
}

func baseURLForRequest(r *http.Request) string {
	if Cfg.PublicBaseURL != "" {
		return strings.TrimRight(Cfg.PublicBaseURL, "/")
	}
	scheme := "http"
	if requestIsHTTPS(r) {
		scheme = "https"
	}
	host := trustedHeader(r, "X-Forwarded-Host")
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func setRequestDeadline(w http.ResponseWriter, d time.Duration) {
	if d <= 0 {
		return
	}
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Now().Add(d))
	rc.SetReadDeadline(time.Now().Add(d))
}

func extendMediaDeadlines(w http.ResponseWriter) {
	setRequestDeadline(w, 12*time.Hour)
}

func setFileETag(w http.ResponseWriter, stat os.FileInfo) {
	if stat == nil || w.Header().Get("ETag") != "" {
		return
	}
	tag := fmt.Sprintf(`"%x-%x"`, stat.ModTime().UnixNano(), stat.Size())
	w.Header().Set("ETag", tag)
}
