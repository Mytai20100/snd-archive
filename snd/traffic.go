package snd

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	trafficRetentionDays  = 14
	trafficMaxFilesPerDir = 40
	trafficMaxIPsPerHour  = 60
	trafficSaveInterval   = 45 * time.Second
)

type TrafficFileStat struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Count int64  `json:"count"`
}

type TrafficFileBucket struct {
	Upload   []TrafficFileStat `json:"upload"`
	Download []TrafficFileStat `json:"download"`
}

type TrafficIPStat struct {
	IP       string `json:"ip"`
	Bytes    int64  `json:"bytes"`
	Requests int64  `json:"requests"`
}

type TrafficClassStat struct {
	Dashboard int64 `json:"dashboard"`
	Admin     int64 `json:"admin"`
	API       int64 `json:"api"`
	Asset     int64 `json:"asset"`
}

type TrafficBucket struct {
	Hour     string                      `json:"hour"`
	Upload   int64                       `json:"upload"`
	Download int64                       `json:"download"`
	Requests int64                       `json:"requests"`
	Files    map[string]*TrafficFileStat `json:"files"`
	IPs      []*TrafficIPStat            `json:"ips"`
	Classes  TrafficClassStat            `json:"classes"`
}

type trafficV2 struct {
	Buckets []*TrafficBucket `json:"buckets"`
}

var (
	trafficV2Mu   sync.Mutex
	trafficV2Data = make(map[string]*TrafficBucket)
)

func classifyRequestPath(p string) string {
	switch {
	case p == "/" || p == "/public-files" || p == "/files" ||
		p == "/folder" || strings.HasPrefix(p, "/folder/") ||
		p == "/raw" || strings.HasPrefix(p, "/raw/") ||
		p == "/view" || strings.HasPrefix(p, "/view/") ||
		p == "/stream" || strings.HasPrefix(p, "/stream/") ||
		p == "/embed" || strings.HasPrefix(p, "/embed/") ||
		p == "/play" || strings.HasPrefix(p, "/play/") ||
		p == "/thumbnail" || strings.HasPrefix(p, "/thumbnail/") ||
		p == "/api/view" || strings.HasPrefix(p, "/api/view/") ||
		p == "/zip-view" || strings.HasPrefix(p, "/zip-view/") ||
		p == "/up" || strings.HasPrefix(p, "/up/") ||
		p == "/upload" || p == "/upload-chunk" || p == "/check-exists":
		return "dashboard"
	case p == "/ad" || p == "/my" ||
		p == "/sessions" || p == "/access-logs" ||
		p == "/logout" || p == "/ac" || p == "/login" || p == "/admin" ||
		strings.HasPrefix(p, "/admin/") ||
		strings.HasPrefix(p, "/users") || strings.HasPrefix(p, "/nodes") ||
		strings.HasPrefix(p, "/security-logs"):
		return "admin"
	case p == "/api/lang" || p == "/api/qr" || p == "/api/v9/connect":
		return "api"
	default:
		return "asset"
	}
}

func isStaticAssetPath(p string) bool {
	switch classifyRequestPath(p) {
	case "asset", "api":
		return true
	}
	return false
}

func trafficFileKey(p string) string {
	low := strings.ToLower(p)
	switch {
	case strings.HasPrefix(low, "/thumbnail/"):
		return "thumbnail/" + strings.TrimPrefix(p, "/thumbnail/")
	case strings.HasPrefix(low, "/api/view/"):
		return "thumbnail/" + strings.TrimPrefix(p, "/api/view/")
	case strings.HasPrefix(low, "/embed/"):
		return strings.TrimPrefix(p, "/embed/")
	case strings.HasPrefix(low, "/stream/"):
		return strings.TrimPrefix(p, "/stream/")
	case strings.HasPrefix(low, "/raw/"):
		return strings.TrimPrefix(p, "/raw/")
	case strings.HasPrefix(low, "/view/"):
		return strings.TrimPrefix(p, "/view/")
	case strings.HasPrefix(low, "/download/"):
		return strings.TrimPrefix(p, "/download/")
	case p == "/up" || strings.HasPrefix(p, "/up/"):
		return strings.TrimPrefix(strings.TrimPrefix(p, "/up"), "/")
	}
	return ""
}

func trafficHourKey(t time.Time) string {
	return t.UTC().Format("2006-01-02T15")
}

func trafficBucketLocked(hour string) *TrafficBucket {
	b := trafficV2Data[hour]
	if b == nil {
		b = &TrafficBucket{Hour: hour, Files: make(map[string]*TrafficFileStat)}
		trafficV2Data[hour] = b
	}
	return b
}

func trafficPruneLocked(now time.Time) {
	cutoff := now.UTC().Add(-trafficRetentionDays * 24 * time.Hour).Truncate(time.Hour)
	for k, b := range trafficV2Data {
		if b.Hour < cutoff.Format("2006-01-02T15") {
			delete(trafficV2Data, k)
		}
	}
}

func bumpFileStat(b *TrafficBucket, dir, name string, bytes int64) {
	if name == "" {
		return
	}
	key := dir + ":" + name
	st := b.Files[key]
	if st == nil {
		if len(b.Files) >= trafficMaxFilesPerDir*2 {
			smallest := ""
			var smallestBytes int64
			for k, v := range b.Files {
				if smallest == "" || v.Bytes < smallestBytes {
					smallest = k
					smallestBytes = v.Bytes
				}
			}
			if smallest != "" && smallestBytes < bytes {
				return
			}
			if smallest != "" {
				delete(b.Files, smallest)
			}
		}
		st = &TrafficFileStat{Name: name}
		b.Files[key] = st
	}
	st.Bytes += bytes
	st.Count++
}

func bumpIPStat(b *TrafficBucket, ip string, bytes int64) {
	if ip == "" {
		return
	}
	for _, e := range b.IPs {
		if e.IP == ip {
			e.Bytes += bytes
			e.Requests++
			return
		}
	}
	if len(b.IPs) >= trafficMaxIPsPerHour {
		var smallestIdx = -1
		var smallestBytes int64
		for i, e := range b.IPs {
			if smallestIdx == -1 || e.Bytes < smallestBytes {
				smallestIdx = i
				smallestBytes = e.Bytes
			}
		}
		if smallestIdx >= 0 && b.IPs[smallestIdx].Bytes < bytes {
			b.IPs[smallestIdx] = &TrafficIPStat{IP: ip, Bytes: bytes, Requests: 1}
		}
		return
	}
	b.IPs = append(b.IPs, &TrafficIPStat{IP: ip, Bytes: bytes, Requests: 1})
}

func recordRequestBytes(ip, path, fileName, direction string, bytes int64, t time.Time) {
	class := classifyRequestPath(path)
	trafficV2Mu.Lock()
	defer trafficV2Mu.Unlock()
	now := t
	if now.IsZero() {
		now = time.Now()
	}
	hour := trafficHourKey(now)
	b := trafficBucketLocked(hour)
	trafficPruneLocked(now)
	b.Requests++
	switch class {
	case "dashboard":
		b.Classes.Dashboard++
	case "admin":
		b.Classes.Admin++
	case "api":
		b.Classes.API++
		b.Classes.Asset++
	default:
		b.Classes.Asset++
	}
	bumpIPStat(b, ip, bytes)
	addDailyDownload(bytes)
	if isStaticAssetPath(path) {
		if bytes > 0 {
			b.Download += bytes
		}
		return
	}
	switch direction {
	case "upload":
		b.Upload += bytes
		bumpFileStat(b, "up", fileName, bytes)
	case "download":
		b.Download += bytes
		bumpFileStat(b, "down", fileName, bytes)
	default:
		if bytes > 0 {
			b.Download += bytes
		}
	}
}

func addDailyDownload(n int64) {
	if n <= 0 {
		return
	}
	trafficStatsMu.Lock()
	d := todayKey()
	if trafficStats[d] == nil {
		trafficStats[d] = &DailyTrafficSample{Date: d}
	}
	trafficStats[d].Download += n
	trafficStatsMu.Unlock()
	markTrafficDirty()
}

func recordUploadTransfer(fileName string, bytes int64) {
	if bytes <= 0 {
		return
	}
	now := time.Now()
	trafficV2Mu.Lock()
	defer trafficV2Mu.Unlock()
	b := trafficBucketLocked(trafficHourKey(now))
	trafficPruneLocked(now)
	b.Upload += bytes
	bumpFileStat(b, "up", fileName, bytes)
}

func GetTrafficBuckets(days, topFiles, topIPs int) []*TrafficBucket {
	if days <= 0 || days > trafficRetentionDays {
		days = trafficRetentionDays
	}
	now := time.Now().UTC()
	start := now.Add(-time.Duration(days-1) * 24 * time.Hour).Truncate(time.Hour)

	trafficV2Mu.Lock()
	out := make([]*TrafficBucket, 0, days*24)
	for h := start; !h.After(now); h = h.Add(time.Hour) {
		key := h.Format("2006-01-02T15")
		src := trafficV2Data[key]
		cp := &TrafficBucket{Hour: key}
		if src != nil {
			cp.Upload = src.Upload
			cp.Download = src.Download
			cp.Requests = src.Requests
			cp.Classes = src.Classes
			for _, e := range src.IPs {
				cp.IPs = append(cp.IPs, &TrafficIPStat{IP: e.IP, Bytes: e.Bytes, Requests: e.Requests})
			}
			cp.Files = make(map[string]*TrafficFileStat, len(src.Files))
			keys := make([]string, 0, len(src.Files))
			for k := range src.Files {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) > topFiles*2 {
				sorted := append([]string(nil), keys...)
				sort.Slice(sorted, func(i, j int) bool {
					return src.Files[sorted[i]].Bytes > src.Files[sorted[j]].Bytes
				})
				kept := sorted[:topFiles*2]
				keys = kept
			}
			for _, k := range keys {
				f := src.Files[k]
				fc := TrafficFileStat{Name: f.Name, Bytes: f.Bytes, Count: f.Count}
				cp.Files[k] = &fc
			}
		}
		if cp.IPs == nil {
			cp.IPs = []*TrafficIPStat{}
		}
		if cp.Files == nil {
			cp.Files = map[string]*TrafficFileStat{}
		}
		out = append(out, cp)
	}
	trafficV2Mu.Unlock()
	return out
}

func RecordUploadBytes(n int64) {
	RecordUploadBytesNamed(n, "")
}

func RecordUploadBytesNamed(n int64, name string) {
	if n <= 0 {
		return
	}
	trafficStatsMu.Lock()
	d := todayKey()
	if trafficStats[d] == nil {
		trafficStats[d] = &DailyTrafficSample{Date: d}
	}
	trafficStats[d].Upload += n
	trafficStatsMu.Unlock()
	markTrafficDirty()
	recordUploadTransfer(name, n)
}

func RecordDownloadBytes(n int64) {
	RecordDownloadBytesNamed(n, "")
}

func RecordDownloadBytesNamed(n int64, name string) {
	if n <= 0 {
		return
	}
	trafficStatsMu.Lock()
	d := todayKey()
	if trafficStats[d] == nil {
		trafficStats[d] = &DailyTrafficSample{Date: d}
	}
	trafficStats[d].Download += n
	trafficStatsMu.Unlock()
	markTrafficDirty()
}

func RecordTrafficAnomaly() {
	trafficStatsMu.Lock()
	d := todayKey()
	if trafficStats[d] == nil {
		trafficStats[d] = &DailyTrafficSample{Date: d}
	}
	trafficStats[d].Anomaly++
	trafficStatsMu.Unlock()
	markTrafficDirty()
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

func HandleDDoSStats(w http.ResponseWriter, r *http.Request) {
	samples := GetTrafficSamples(trafficRetentionDays)
	buckets := GetTrafficBuckets(trafficRetentionDays, trafficMaxFilesPerDir, trafficMaxIPsPerHour)

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
		"buckets": buckets,
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

func LoadTrafficStats() {
	data, err := os.ReadFile(DDoSTrafficFile)
	if err != nil {
		return
	}
	var list []DailyTrafficSample
	if err := json.Unmarshal(data, &list); err == nil {
		trafficStatsMu.Lock()
		for _, s := range list {
			s := s
			trafficStats[s.Date] = &s
		}
		trafficStatsMu.Unlock()
		return
	}
	var v2 trafficV2
	if err := json.Unmarshal(data, &v2); err == nil && len(v2.Buckets) > 0 {
		trafficV2Mu.Lock()
		for _, b := range v2.Buckets {
			if b == nil || b.Hour == "" {
				continue
			}
			if b.Files == nil {
				b.Files = make(map[string]*TrafficFileStat)
			}
			if b.IPs == nil {
				b.IPs = []*TrafficIPStat{}
			}
			trafficV2Data[b.Hour] = b
		}
		trafficV2Mu.Unlock()
	}
}

func saveTrafficStats() {
	trafficStatsMu.Lock()
	list := make([]DailyTrafficSample, 0, len(trafficStats))
	for _, s := range trafficStats {
		list = append(list, *s)
	}
	trafficStatsMu.Unlock()

	trafficV2Mu.Lock()
	v2 := trafficV2{Buckets: make([]*TrafficBucket, 0, len(trafficV2Data))}
	for _, b := range trafficV2Data {
		v2.Buckets = append(v2.Buckets, b)
	}
	trafficV2Mu.Unlock()

	legacy, err1 := json.Marshal(list)
	detail, err2 := json.Marshal(v2)
	if err1 != nil || err2 != nil {
		return
	}
	os.WriteFile(DDoSTrafficFile+"_detail.json", detail, 0644)
	os.WriteFile(DDoSTrafficFile, legacy, 0644)
}

func loadTrafficDetail() {
	data, err := os.ReadFile(DDoSTrafficFile + "_detail.json")
	if err != nil {
		return
	}
	var v2 trafficV2
	if err := json.Unmarshal(data, &v2); err != nil {
		return
	}
	trafficV2Mu.Lock()
	for _, b := range v2.Buckets {
		if b == nil || b.Hour == "" {
			continue
		}
		if b.Files == nil {
			b.Files = make(map[string]*TrafficFileStat)
		}
		if b.IPs == nil {
			b.IPs = []*TrafficIPStat{}
		}
		trafficV2Data[b.Hour] = b
	}
	trafficV2Mu.Unlock()
}

var (
	trafficDirtyMu   sync.Mutex
	trafficDirty     bool
	trafficSaveTimer *time.Timer
)

func markTrafficDirty() {
	trafficDirtyMu.Lock()
	trafficDirty = true
	if trafficSaveTimer == nil {
		trafficSaveTimer = time.AfterFunc(trafficSaveInterval, flushTrafficStats)
	}
	trafficDirtyMu.Unlock()
}

func flushTrafficStats() {
	trafficDirtyMu.Lock()
	if !trafficDirty {
		trafficDirty = false
		trafficSaveTimer = nil
		trafficDirtyMu.Unlock()
		return
	}
	trafficDirty = false
	trafficSaveTimer = nil
	trafficDirtyMu.Unlock()
	saveTrafficStats()
}

func init() {
	loadTrafficDetail()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

type trafficCtxKeyType struct{}

var trafficCtxKey trafficCtxKeyType

type trafficMeta struct {
	direction string
	fileName  string
}

func setTrafficMeta(r *http.Request, direction, fileName string) {
	m, ok := r.Context().Value(trafficCtxKey).(*trafficMeta)
	if !ok || m == nil {
		return
	}
	m.direction = direction
	m.fileName = fileName
}

func isUploadEndpointPath(p string) bool {
	return p == "/upload" || p == "/upload-chunk" || p == "/up"
}

func ServeTraffic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		meta := &trafficMeta{}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), trafficCtxKey, meta)))
		if rec.bytes <= 0 && rec.status >= 400 {
			return
		}
		fileName := meta.fileName
		if fileName == "" {
			fileName = trafficFileKey(r.URL.Path)
		}
		bytes := rec.bytes
		if isUploadEndpointPath(r.URL.Path) {
			bytes = 0
		}
		recordRequestBytes(GetClientIP(r), r.URL.Path, fileName, meta.direction, bytes, time.Now())
	})
}
