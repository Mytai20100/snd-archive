package snd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type DDoSConfig struct {
	Enabled              bool     `yaml:"enabled"               json:"enabled"`
	RateWindowSec        int      `yaml:"rate_window_sec"        json:"rate_window_sec"`
	MaxRequestsPerWindow int      `yaml:"max_requests_per_window" json:"max_requests_per_window"`
	BanDurationMin       int      `yaml:"ban_duration_min"       json:"ban_duration_min"`
	WhitelistIPs         []string `yaml:"whitelist_ips"          json:"whitelist_ips"`
	GlobalMaxRPS         int      `yaml:"global_max_rps" json:"global_max_rps"`

	BlockEmptyUA bool `yaml:"block_empty_ua" json:"block_empty_ua"`

	MaxBodyMB int `yaml:"max_body_mb" json:"max_body_mb"`

	BlockSuspiciousUA bool `yaml:"block_suspicious_ua" json:"block_suspicious_ua"`

	ConnectionsPerIP int `yaml:"connections_per_ip" json:"connections_per_ip"`
}

type DDoSBannedIP struct {
	IP        string    `yaml:"ip"         json:"ip"`
	BannedAt  time.Time `yaml:"banned_at"  json:"banned_at"`
	ExpiresAt time.Time `yaml:"expires_at" json:"expires_at"`
	HitCount  int       `yaml:"hit_count"  json:"hit_count"`
	Reason    string    `yaml:"reason"     json:"reason"`
}

type DailyTrafficSample struct {
	Date     string `json:"date"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Anomaly  int64  `json:"anomaly"`
}

var (
	DDoSCfg         DDoSConfig
	DDoSCfgMu       sync.RWMutex
	DDoSBans        = make(map[string]*DDoSBannedIP)
	DDoSBansMu      sync.RWMutex
	DDoSFile        = "ddos.yml"
	DDoSBansFile    = "ddos_bans.yml"
	DDoSTrafficFile = "ddos_traffic.json"

	ddosCounters   = make(map[string][]time.Time)
	ddosCountersMu sync.Mutex

	globalRPSTimestamps []time.Time
	globalRPSMu         sync.Mutex

	connPerIP   = make(map[string]int)
	connPerIPMu sync.Mutex

	trafficStats   = make(map[string]*DailyTrafficSample)
	trafficStatsMu sync.Mutex
)

func LoadDDoSConfig() {
	DDoSCfg = DDoSConfig{
		Enabled:              true,
		RateWindowSec:        60,
		MaxRequestsPerWindow: 300,
		BanDurationMin:       60,
		WhitelistIPs:         []string{"127.0.0.1", "::1"},
	}
	data, err := os.ReadFile(DDoSFile)
	if err == nil {
		yaml.Unmarshal(data, &DDoSCfg)
	} else {
		saveDDoSConfig()
	}
	loadDDoSBans()
	loadAllowList()
	go startDDoSCounterCleanup()
}

func startDDoSCounterCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		cutoff := time.Now().Add(-time.Duration(DDoSCfg.RateWindowSec) * time.Second)
		ddosCountersMu.Lock()
		for ip, times := range ddosCounters {
			pruned := times[:0]
			for _, t := range times {
				if t.After(cutoff) {
					pruned = append(pruned, t)
				}
			}
			if len(pruned) == 0 {
				delete(ddosCounters, ip)
			} else {
				ddosCounters[ip] = pruned
			}
		}
		ddosCountersMu.Unlock()
	}
}

func saveDDoSConfig() {
	data, _ := yaml.Marshal(DDoSCfg)
	os.WriteFile(DDoSFile, data, 0644)
}

func loadDDoSBans() {
	DDoSBansMu.Lock()
	defer DDoSBansMu.Unlock()
	data, err := os.ReadFile(DDoSBansFile)
	if err != nil {
		return
	}
	var list []*DDoSBannedIP
	yaml.Unmarshal(data, &list)
	DDoSBans = make(map[string]*DDoSBannedIP)
	now := time.Now()
	for _, b := range list {
		if b.ExpiresAt.After(now) {
			DDoSBans[b.IP] = b
		}
	}
}

func saveDDoSBans() {
	DDoSBansMu.RLock()
	list := make([]*DDoSBannedIP, 0, len(DDoSBans))
	for _, b := range DDoSBans {
		list = append(list, b)
	}
	DDoSBansMu.RUnlock()
	data, _ := yaml.Marshal(list)
	os.WriteFile(DDoSBansFile, data, 0644)
}

func DDoSMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		DDoSCfgMu.RLock()
		enabled := DDoSCfg.Enabled
		maxReqs := DDoSCfg.MaxRequestsPerWindow
		windowSec := DDoSCfg.RateWindowSec
		banMin := DDoSCfg.BanDurationMin
		whitelist := DDoSCfg.WhitelistIPs
		globalMaxRPS := DDoSCfg.GlobalMaxRPS
		DDoSCfgMu.RUnlock()

		if !enabled {
			handler(w, r)
			return
		}

		if globalMaxRPS > 0 {
			now2 := time.Now()
			cutoff2 := now2.Add(-time.Second)
			globalRPSMu.Lock()
			pruned2 := globalRPSTimestamps[:0]
			for _, t := range globalRPSTimestamps {
				if t.After(cutoff2) {
					pruned2 = append(pruned2, t)
				}
			}
			pruned2 = append(pruned2, now2)
			globalRPSTimestamps = pruned2
			globalCount := len(pruned2)
			globalRPSMu.Unlock()
			if globalCount > globalMaxRPS {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Server busy — try again shortly.", http.StatusServiceUnavailable)
				return
			}
		}

		DDoSCfgMu.RLock()
		blockEmptyUA := DDoSCfg.BlockEmptyUA
		blockSuspUA := DDoSCfg.BlockSuspiciousUA
		maxBodyMB := DDoSCfg.MaxBodyMB
		connLimit := DDoSCfg.ConnectionsPerIP
		DDoSCfgMu.RUnlock()

		ip := GetClientIP(r)
		uaExempt := isUAExemptPath(r) || IsAllowlisted(ip)
		previewBot := isPreviewBot(r)
		if previewBot && isPreviewBotPublicPath(r) {
			uaExempt = true
		}

		if blockEmptyUA && !uaExempt && r.Header.Get("User-Agent") == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if blockSuspUA && !uaExempt {
			ua := r.Header.Get("User-Agent")
			if isSuspiciousUA(ua) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		if maxBodyMB > 0 && r.ContentLength > int64(maxBodyMB)*1024*1024 {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}

		if connLimit > 0 {
			connPerIPMu.Lock()
			connPerIP[ip]++
			current := connPerIP[ip]
			connPerIPMu.Unlock()
			defer func() {
				connPerIPMu.Lock()
				if connPerIP[ip] > 0 {
					connPerIP[ip]--
				}
				if connPerIP[ip] == 0 {
					delete(connPerIP, ip)
				}
				connPerIPMu.Unlock()
			}()
			if current > connLimit {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Too many concurrent requests from your IP", http.StatusTooManyRequests)
				return
			}
		}

		if IsAllowlisted(ip) {
			handler(w, r)
			return
		}

		if whitelistMatch(r, ip, whitelist) {
			handler(w, r)
			return
		}

		DDoSBansMu.RLock()
		ban, banned := DDoSBans[ip]
		DDoSBansMu.RUnlock()
		if banned {
			if time.Now().Before(ban.ExpiresAt) {
				w.Header().Set("Retry-After", "3600")
				http.Error(w, "Access denied: your IP has been temporarily blocked.", http.StatusForbidden)
				return
			}
			DDoSBansMu.Lock()
			delete(DDoSBans, ip)
			DDoSBansMu.Unlock()
		}

		now := time.Now()
		window := time.Duration(windowSec) * time.Second
		cutoff := now.Add(-window)

		ddosCountersMu.Lock()
		times := ddosCounters[ip]
		pruned := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				pruned = append(pruned, t)
			}
		}
		pruned = append(pruned, now)
		ddosCounters[ip] = pruned
		count := len(pruned)
		ddosCountersMu.Unlock()

		if !uaExempt && count > maxReqs {
			banDur := time.Duration(banMin) * time.Minute
			DDoSBansMu.Lock()
			DDoSBans[ip] = &DDoSBannedIP{
				IP:        ip,
				BannedAt:  now,
				ExpiresAt: now.Add(banDur),
				HitCount:  count,
				Reason:    "Rate limit exceeded (auto-ban)",
			}
			DDoSBansMu.Unlock()
			go saveDDoSBans()

			go AppendSecurityEvent(ip, SecEvtDDoSBan, fmt.Sprintf("Rate limit exceeded: %d req in window, banned %d min", count, banMin), "")

			RecordTrafficAnomaly()

			w.Header().Set("Retry-After", "3600")
			http.Error(w, "Access denied: rate limit exceeded.", http.StatusForbidden)
			return
		}

		handler(w, r)
	}
}

func todayKey() string {
	return time.Now().Format("2006-01-02")
}

func HandleDDoSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var newCfg DDoSConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		DDoSCfgMu.Lock()
		newCfg.WhitelistIPs = DDoSCfg.WhitelistIPs
		prevEnabled := DDoSCfg.Enabled
		DDoSCfg = newCfg
		DDoSCfgMu.Unlock()
		saveDDoSConfig()
		if prevEnabled != newCfg.Enabled {
			status := "DISABLED"
			if newCfg.Enabled {
				status = "ENABLED"
			}
			log.Printf("[DDOS] Protection %s by admin", status)
		} else {
			log.Printf("[DDOS] Config updated: window=%ds max=%d ban=%dmin enabled=%v",
				newCfg.RateWindowSec, newCfg.MaxRequestsPerWindow, newCfg.BanDurationMin, newCfg.Enabled)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DDoSCfg)
}

func DDoSHandler(next http.Handler) http.Handler {
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		DDoSMiddleware(next.ServeHTTP)(w, r)
	})
	return ServeTraffic(wrapped)
}
func HandleDDoSManualBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.IP == "" {
		http.Error(w, `{"error":"ip required"}`, http.StatusBadRequest)
		return
	}
	banDur := time.Duration(DDoSCfg.BanDurationMin) * time.Minute
	now := time.Now()
	DDoSBansMu.Lock()
	DDoSBans[req.IP] = &DDoSBannedIP{
		IP:        req.IP,
		BannedAt:  now,
		ExpiresAt: now.Add(banDur),
		HitCount:  0,
		Reason:    req.Reason,
	}
	DDoSBansMu.Unlock()
	go saveDDoSBans()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

type SecurityEventType string

const (
	SecEvtLoginFail     SecurityEventType = "login_fail"
	SecEvtLoginBan      SecurityEventType = "login_ban"
	SecEvtDDoSBlock     SecurityEventType = "ddos_block"
	SecEvtDDoSBan       SecurityEventType = "ddos_ban"
	SecEvtArchiveBomb   SecurityEventType = "archive_bomb"
	SecEvtChallengeFail SecurityEventType = "challenge_fail"
	SecEvtAPIKeyFail    SecurityEventType = "api_key_fail"
)

type SecurityEvent struct {
	Time      time.Time         `json:"time"`
	IP        string            `json:"ip"`
	EventType SecurityEventType `json:"event_type"`
	Reason    string            `json:"reason"`
	Username  string            `json:"username,omitempty"`
}

const maxSecurityEvents = 500

var (
	securityLog   []*SecurityEvent
	securityLogMu sync.Mutex
)

func AppendSecurityEvent(ip string, evtType SecurityEventType, reason string, username string) {
	evt := &SecurityEvent{
		Time:      time.Now(),
		IP:        ip,
		EventType: evtType,
		Reason:    reason,
		Username:  username,
	}
	securityLogMu.Lock()
	securityLog = append(securityLog, evt)
	if len(securityLog) > maxSecurityEvents {
		securityLog = securityLog[len(securityLog)-maxSecurityEvents:]
	}
	securityLogMu.Unlock()
	log.Printf("[SECURITY] %s ip=%s reason=%s user=%s", evtType, ip, reason, username)
}

func HandleSecurityLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	securityLogMu.Lock()
	out := make([]*SecurityEvent, len(securityLog))
	for i, e := range securityLog {
		out[len(securityLog)-1-i] = e
	}
	securityLogMu.Unlock()
	json.NewEncoder(w).Encode(out)
}

type AllowEntry struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	allowList     []*AllowEntry
	allowListMu   sync.RWMutex
	allowListFile = "allowlist.yml"
)

func loadAllowList() {
	data, err := os.ReadFile(allowListFile)
	if err != nil {
		return
	}
	var list []*AllowEntry
	if err := yaml.Unmarshal(data, &list); err == nil {
		allowListMu.Lock()
		allowList = list
		allowListMu.Unlock()
	}
}

func saveAllowList() {
	allowListMu.RLock()
	data, _ := yaml.Marshal(allowList)
	allowListMu.RUnlock()
	os.WriteFile(allowListFile, data, 0644)
}

func IsAllowlisted(ip string) bool {
	allowListMu.RLock()
	defer allowListMu.RUnlock()
	for _, e := range allowList {
		pat := e.IP
		if pat == "" {
			continue
		}
		if ip == pat {
			return true
		}
		if len(pat) < len(ip) && ip[:len(pat)] == pat {
			return true
		}
	}
	return false
}

func HandleListAllowlist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	allowListMu.RLock()
	out := make([]*AllowEntry, len(allowList))
	copy(out, allowList)
	allowListMu.RUnlock()
	json.NewEncoder(w).Encode(out)
}

func HandleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		IP    string `json:"ip"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, `{"error":"ip required"}`, http.StatusBadRequest)
		return
	}
	entry := &AllowEntry{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		IP:        req.IP,
		Label:     req.Label,
		CreatedAt: time.Now(),
	}
	allowListMu.Lock()
	allowList = append(allowList, entry)
	allowListMu.Unlock()
	go saveAllowList()
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "entry": entry})
}

func HandleUpdateAllowlist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		ID    string `json:"id"`
		IP    string `json:"ip"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	allowListMu.Lock()
	for _, e := range allowList {
		if e.ID == req.ID {
			e.IP = req.IP
			e.Label = req.Label
			break
		}
	}
	allowListMu.Unlock()
	go saveAllowList()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func HandleDeleteAllowlist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	allowListMu.Lock()
	filtered := allowList[:0]
	for _, e := range allowList {
		if e.ID != req.ID {
			filtered = append(filtered, e)
		}
	}
	allowList = filtered
	allowListMu.Unlock()
	go saveAllowList()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func isSuspiciousUA(ua string) bool {
	if ua == "" {
		return false
	}
	lua := strings.ToLower(ua)
	badPrefixes := []string{
		"python-requests", "go-http-client/1", "curl/", "wget/",
		"masscan", "nmap", "nikto", "sqlmap", "dirbuster", "gobuster",
		"wfuzz", "hydra", "medusa", "zgrab", "zmap",
		"nuclei", "acunetix", "nessus", "openvas",
		"scrapy", "phantomjs", "headlesschrome", "python/",
		"ahrefsbot", "semrushbot", "mj12bot", "dotbot",
	}
	for _, prefix := range badPrefixes {
		if strings.HasPrefix(lua, prefix) {
			return true
		}
	}
	attackSigs := []string{"sqlmap", "nikto", "nessus", "acunetix", "masscan", "zgrab"}
	for _, sig := range attackSigs {
		if strings.Contains(lua, sig) {
			return true
		}
	}
	return false
}

func whitelistMatch(r *http.Request, ip string, whitelist []string) bool {
	for _, entry := range whitelist {
		entry = strings.TrimSpace(entry)
		if entry == "" || entry != ip {
			continue
		}
		if IsLoopbackIP(entry) {
			peer := GetPeerIP(r)
			if !peer.IsValid() || !peer.IsLoopback() {
				continue
			}
		}
		return true
	}
	return false
}

func isUAExemptPath(r *http.Request) bool {
	p := r.URL.Path
	return p == "/up" || strings.HasPrefix(p, "/up/")
}

var previewBotTokens = []string{
	"discordbot",
	"facebookexternalhit",
	"facebot",
	"twitterbot",
	"telegrambot",
	"slackbot",
	"whatsapp",
	"zalo",
	"zalobot",
	"linkedinbot",
}

func isPreviewBot(r *http.Request) bool {
	if r == nil {
		return false
	}
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return false
	}
	for _, tok := range previewBotTokens {
		if strings.Contains(ua, tok) {
			return true
		}
	}
	return false
}

var previewBotPrefixes = []string{"/embed/", "/raw/", "/stream/", "/thumbnail/", "/api/view/", "/view/", "/download/", "/play/"}

func isPreviewBotPublicPath(r *http.Request) bool {
	p := r.URL.Path
	for _, pre := range previewBotPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}
