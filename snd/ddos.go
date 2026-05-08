package snd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── Config ───────────────────────────────────────────────────────────────────

type DDoSConfig struct {
	Enabled             bool     `yaml:"enabled"               json:"enabled"`
	RateWindowSec       int      `yaml:"rate_window_sec"        json:"rate_window_sec"`
	MaxRequestsPerWindow int     `yaml:"max_requests_per_window" json:"max_requests_per_window"`
	BanDurationMin      int      `yaml:"ban_duration_min"       json:"ban_duration_min"`
	WhitelistIPs        []string `yaml:"whitelist_ips"          json:"whitelist_ips"`
}

type DDoSBannedIP struct {
	IP        string    `yaml:"ip"         json:"ip"`
	BannedAt  time.Time `yaml:"banned_at"  json:"banned_at"`
	ExpiresAt time.Time `yaml:"expires_at" json:"expires_at"`
	HitCount  int       `yaml:"hit_count"  json:"hit_count"`
	Reason    string    `yaml:"reason"     json:"reason"`
}

// DailyTrafficSample stores upload/download bytes and anomaly count per day
type DailyTrafficSample struct {
	Date     string `json:"date"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Anomaly  int64  `json:"anomaly"`
}

// ─── State ────────────────────────────────────────────────────────────────────

var (
	DDoSCfg       DDoSConfig
	DDoSCfgMu     sync.RWMutex
	DDoSBans      = make(map[string]*DDoSBannedIP)
	DDoSBansMu    sync.RWMutex
	DDoSFile      = "ddos.yml"
	DDoSBansFile  = "ddos_bans.yml"
	DDoSTrafficFile = "ddos_traffic.json"

	// Per-IP request counters: ip → []timestamp
	ddosCounters   = make(map[string][]time.Time)
	ddosCountersMu sync.Mutex

	// Traffic stats: date string → sample
	trafficStats   = make(map[string]*DailyTrafficSample)
	trafficStatsMu sync.Mutex
)

// ─── Init ─────────────────────────────────────────────────────────────────────

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

// ─── Middleware ───────────────────────────────────────────────────────────────

// DDoSMiddleware checks rate limits and bans for every request.
func DDoSMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		DDoSCfgMu.RLock()
		enabled := DDoSCfg.Enabled
		maxReqs := DDoSCfg.MaxRequestsPerWindow
		windowSec := DDoSCfg.RateWindowSec
		banMin := DDoSCfg.BanDurationMin
		whitelist := DDoSCfg.WhitelistIPs
		DDoSCfgMu.RUnlock()

		if !enabled {
			handler(w, r)
			return
		}

		ip := GetClientIP(r)

		// Allowlist check (trusted IPs bypass all rate-limiting)
		if IsAllowlisted(ip) {
			handler(w, r)
			return
		}

		// Legacy whitelist check (from ddos.yml)
		for _, wip := range whitelist {
			if ip == wip {
				handler(w, r)
				return
			}
		}

		// Ban check
		DDoSBansMu.RLock()
		ban, banned := DDoSBans[ip]
		DDoSBansMu.RUnlock()
		if banned {
			if time.Now().Before(ban.ExpiresAt) {
				w.Header().Set("Retry-After", "3600")
				http.Error(w, "Access denied: your IP has been temporarily blocked.", http.StatusForbidden)
				return
			}
			// Ban expired
			DDoSBansMu.Lock()
			delete(DDoSBans, ip)
			DDoSBansMu.Unlock()
		}

		// Rate-limit check
		now := time.Now()
		window := time.Duration(windowSec) * time.Second
		cutoff := now.Add(-window)

		ddosCountersMu.Lock()
		times := ddosCounters[ip]
		// Prune old
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

		if count > maxReqs {
			// Auto-ban
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

			// Record security event
			go AppendSecurityEvent(ip, SecEvtDDoSBan, fmt.Sprintf("Rate limit exceeded: %d req in window, banned %d min", count, banMin), "")

			// Record anomaly
			RecordTrafficAnomaly()

			w.Header().Set("Retry-After", "3600")
			http.Error(w, "Access denied: rate limit exceeded.", http.StatusForbidden)
			return
		}

		handler(w, r)
	}
}

// ─── Traffic tracking ────────────────────────────────────────────────────────

func todayKey() string {
	return time.Now().Format("2006-01-02")
}

func RecordUploadBytes(n int64) {
	trafficStatsMu.Lock()
	d := todayKey()
	if trafficStats[d] == nil {
		trafficStats[d] = &DailyTrafficSample{Date: d}
	}
	trafficStats[d].Upload += n
	trafficStatsMu.Unlock()
	go saveTrafficStats()
}

func RecordDownloadBytes(n int64) {
	trafficStatsMu.Lock()
	d := todayKey()
	if trafficStats[d] == nil {
		trafficStats[d] = &DailyTrafficSample{Date: d}
	}
	trafficStats[d].Download += n
	trafficStatsMu.Unlock()
	go saveTrafficStats()
}

func RecordTrafficAnomaly() {
	trafficStatsMu.Lock()
	d := todayKey()
	if trafficStats[d] == nil {
		trafficStats[d] = &DailyTrafficSample{Date: d}
	}
	trafficStats[d].Anomaly++
	trafficStatsMu.Unlock()
}

func GetTrafficSamples(days int) []DailyTrafficSample {
	trafficStatsMu.Lock()
	defer trafficStatsMu.Unlock()
	var out []DailyTrafficSample
	for i := days - 1; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		if s, ok := trafficStats[d]; ok {
			out = append(out, *s)
		} else {
			out = append(out, DailyTrafficSample{Date: d})
		}
	}
	return out
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

func HandleDDoSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var newCfg DDoSConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		DDoSCfgMu.Lock()
		newCfg.WhitelistIPs = DDoSCfg.WhitelistIPs // preserve whitelist
		prevEnabled := DDoSCfg.Enabled
		DDoSCfg = newCfg
		DDoSCfgMu.Unlock()
		saveDDoSConfig()
		if prevEnabled != newCfg.Enabled {
			status := "DISABLED"
			if newCfg.Enabled { status = "ENABLED" }
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

func HandleDDoSStats(w http.ResponseWriter, r *http.Request) {
	samples := GetTrafficSamples(14)
	DDoSBansMu.RLock()
	bans := make([]*DDoSBannedIP, 0, len(DDoSBans))
	now := time.Now()
	for _, b := range DDoSBans {
		if b.ExpiresAt.After(now) {
			bans = append(bans, b)
		}
	}
	DDoSBansMu.RUnlock()

	DDoSCfgMu.RLock()
	cfgSnapshot := DDoSCfg
	DDoSCfgMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"traffic": samples,
		"bans":    bans,
		"config":  cfgSnapshot,
	})
}

func HandleDDoSUnban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	DDoSBansMu.Lock()
	delete(DDoSBans, req.IP)
	DDoSBansMu.Unlock()
	go saveDDoSBans()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}


// ─── Traffic persistence ──────────────────────────────────────────────────────

func LoadTrafficStats() {
	data, err := os.ReadFile(DDoSTrafficFile)
	if err != nil {
		return
	}
	var list []DailyTrafficSample
	if err := json.Unmarshal(data, &list); err != nil {
		return
	}
	trafficStatsMu.Lock()
	for _, s := range list {
		s := s
		trafficStats[s.Date] = &s
	}
	trafficStatsMu.Unlock()
}

func saveTrafficStats() {
	trafficStatsMu.Lock()
	list := make([]DailyTrafficSample, 0, len(trafficStats))
	for _, s := range trafficStats {
		list = append(list, *s)
	}
	trafficStatsMu.Unlock()
	data, _ := json.Marshal(list)
	os.WriteFile(DDoSTrafficFile, data, 0644)
}

// DDoSHandler wraps a standard http.Handler (e.g. http.DefaultServeMux) with DDoS protection.
// Use this in main.go instead of DDoSMiddleware.
func DDoSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		DDoSMiddleware(next.ServeHTTP)(w, r)
	})
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

// ─── Security Event Log ───────────────────────────────────────────────────────

// SecurityEventType enumerates the kinds of security events we record.
type SecurityEventType string

const (
	SecEvtLoginFail  SecurityEventType = "login_fail"
	SecEvtLoginBan   SecurityEventType = "login_ban"
	SecEvtDDoSBlock  SecurityEventType = "ddos_block"
	SecEvtDDoSBan    SecurityEventType = "ddos_ban"
	SecEvtArchiveBomb SecurityEventType = "archive_bomb"
)

// SecurityEvent is one entry in the security log ring buffer.
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

// AppendSecurityEvent records a new security event (thread-safe, ring buffer).
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

// HandleSecurityLogs — GET /admin/security-logs
// Returns the security event ring buffer (newest first).
func HandleSecurityLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	securityLogMu.Lock()
	// copy in reverse (newest first)
	out := make([]*SecurityEvent, len(securityLog))
	for i, e := range securityLog {
		out[len(securityLog)-1-i] = e
	}
	securityLogMu.Unlock()
	json.NewEncoder(w).Encode(out)
}

// ─── Allowlist (Trusted IPs) ──────────────────────────────────────────────────

// AllowEntry is one trusted IP or CIDR with an optional label.
type AllowEntry struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`    // IP, CIDR, or prefix like "192.168."
	Label     string    `json:"label"` // human-friendly note
	CreatedAt time.Time `json:"created_at"`
}

var (
	allowList   []*AllowEntry
	allowListMu sync.RWMutex
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

// IsAllowlisted returns true if ip matches any AllowEntry.
// The DDoS middleware calls this before rate-limiting.
func IsAllowlisted(ip string) bool {
	allowListMu.RLock()
	defer allowListMu.RUnlock()
	for _, e := range allowList {
		pat := e.IP
		if pat == "" {
			continue
		}
		// Exact match
		if ip == pat {
			return true
		}
		// Prefix match (e.g. "192.168.")
		if len(pat) < len(ip) && ip[:len(pat)] == pat {
			return true
		}
	}
	return false
}

// HandleListAllowlist — GET /admin/allowlist
func HandleListAllowlist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	allowListMu.RLock()
	out := make([]*AllowEntry, len(allowList))
	copy(out, allowList)
	allowListMu.RUnlock()
	json.NewEncoder(w).Encode(out)
}

// HandleAddAllowlist — POST /admin/allowlist/add  body: {ip, label}
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

// HandleUpdateAllowlist — POST /admin/allowlist/update  body: {id, ip, label}
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

// HandleDeleteAllowlist — POST /admin/allowlist/delete  body: {id}
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
