package snd

import (
	"encoding/json"
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

		// Whitelist check
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
