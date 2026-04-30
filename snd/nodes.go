package snd

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── Types ───────────────────────────────────────────────────────────────────

type StorageNode struct {
	ID          string    `yaml:"id"          json:"id"`
	Name        string    `yaml:"name"         json:"name"`
	IP          string    `yaml:"ip"           json:"ip"`
	Port        string    `yaml:"port"         json:"port"`
	IsDefault   bool      `yaml:"is_default"   json:"is_default"`
	IsPrimary   bool      `yaml:"is_primary"   json:"is_primary"`
	BackupMode  bool      `yaml:"backup_mode"  json:"backup_mode"`
	SyncSources []string  `yaml:"sync_sources" json:"sync_sources"`
	CreatedAt   time.Time `yaml:"created_at"   json:"created_at"`
	Notes       string    `yaml:"notes"        json:"notes"`
}

// ─── State ───────────────────────────────────────────────────────────────────

var (
	StorageNodes   []*StorageNode
	StorageNodesMu sync.RWMutex
	NodesFile      = "nodes.yml"
)

// ─── Persistence ─────────────────────────────────────────────────────────────

func LoadNodes() {
	StorageNodesMu.Lock()
	defer StorageNodesMu.Unlock()

	data, err := os.ReadFile(NodesFile)
	if err == nil {
		yaml.Unmarshal(data, &StorageNodes)
	}

	// Ensure default node always exists
	ensureDefaultNode()
}

func SaveNodes() {
	StorageNodesMu.RLock()
	defer StorageNodesMu.RUnlock()
	data, _ := yaml.Marshal(StorageNodes)
	os.WriteFile(NodesFile, data, 0644)
}

func ensureDefaultNode() {
	for _, n := range StorageNodes {
		if n.IsDefault {
			return
		}
	}
	// Add default node (this server)
	defaultNode := &StorageNode{
		ID:        "default",
		Name:      "Local Server (Default)",
		IP:        Cfg.IP,
		Port:      Cfg.Port,
		IsDefault: true,
		IsPrimary: false,
		CreatedAt: time.Now(),
		Notes:     "Auto-created default node (this server). IP/Port cannot be changed.",
	}
	StorageNodes = append([]*StorageNode{defaultNode}, StorageNodes...)
}

// GetPrimaryNode returns the primary storage node, or nil if none is set.
func GetPrimaryNode() *StorageNode {
	StorageNodesMu.RLock()
	defer StorageNodesMu.RUnlock()
	for _, n := range StorageNodes {
		if n.IsPrimary {
			return n
		}
	}
	return nil
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

func HandleListNodes(w http.ResponseWriter, r *http.Request) {
	StorageNodesMu.RLock()
	defer StorageNodesMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StorageNodes)
}

func HandleCreateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		IP         string   `json:"ip"`
		Port       string   `json:"port"`
		Notes      string   `json:"notes"`
		BackupMode bool     `json:"backup_mode"`
		SyncSources []string `json:"sync_sources"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Name == "" || req.IP == "" {
		http.Error(w, `{"error":"name and ip required"}`, http.StatusBadRequest)
		return
	}

	node := &StorageNode{
		ID:          GenerateRandomToken(8),
		Name:        req.Name,
		IP:          req.IP,
		Port:        req.Port,
		Notes:       req.Notes,
		BackupMode:  req.BackupMode,
		SyncSources: req.SyncSources,
		CreatedAt:   time.Now(),
	}

	StorageNodesMu.Lock()
	StorageNodes = append(StorageNodes, node)
	StorageNodesMu.Unlock()
	go SaveNodes()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(node)
}

func HandleUpdateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		IP          string   `json:"ip"`
		Port        string   `json:"port"`
		Notes       string   `json:"notes"`
		BackupMode  bool     `json:"backup_mode"`
		SyncSources []string `json:"sync_sources"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	StorageNodesMu.Lock()
	defer StorageNodesMu.Unlock()

	for _, n := range StorageNodes {
		if n.ID != req.ID {
			continue
		}
		n.Name = req.Name
		n.Notes = req.Notes
		n.BackupMode = req.BackupMode
		n.SyncSources = req.SyncSources
		// IP/Port only changeable for non-default nodes
		if !n.IsDefault {
			n.IP = req.IP
			n.Port = req.Port
		}
		go SaveNodes()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(n)
		return
	}
	http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
}

func HandleDeleteNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	StorageNodesMu.Lock()
	defer StorageNodesMu.Unlock()

	for i, n := range StorageNodes {
		if n.ID != req.ID {
			continue
		}
		if n.IsDefault {
			http.Error(w, `{"error":"cannot delete default node"}`, http.StatusBadRequest)
			return
		}
		StorageNodes = append(StorageNodes[:i], StorageNodes[i+1:]...)
		go SaveNodes()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
}

func HandleSetPrimaryNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	StorageNodesMu.Lock()
	defer StorageNodesMu.Unlock()

	// Clear all primary flags, then set the requested one
	found := req.ID == ""
	for _, n := range StorageNodes {
		n.IsPrimary = false
		if req.ID != "" && n.ID == req.ID {
			n.IsPrimary = true
			found = true
		}
	}

	if !found {
		http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
		return
	}

	go SaveNodes()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ─── Node Connect (called by child node) ─────────────────────────────────────

// NodeConnectRequest is sent by a child node to register itself.
type NodeConnectRequest struct {
	PrivateKey string `json:"key"`
	NodeURL    string `json:"node"`
	Name       string `json:"name"`
}

// HandleNodeConnect receives a POST /api/v9/connect from a child node.
// It validates the private key, registers the node, and replies with a public key.
func HandleNodeConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req NodeConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PrivateKey == "" || req.NodeURL == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	// H2 FIX: Use constant-time comparison to prevent timing attacks on NodePrivateKey.
	if Cfg.NodePrivateKey == "" || subtle.ConstantTimeCompare([]byte(req.PrivateKey), []byte(Cfg.NodePrivateKey)) != 1 {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Register the node if not already present
	StorageNodesMu.Lock()
	found := false
	for _, n := range StorageNodes {
		if n.IP == req.NodeURL {
			found = true
			break
		}
	}
	if !found {
		newNode := &StorageNode{
			ID:        GenerateRandomToken(8),
			Name:      req.Name,
			IP:        req.NodeURL,
			CreatedAt: time.Now(),
			Notes:     "Auto-registered via quick-setup",
		}
		StorageNodes = append(StorageNodes, newNode)
	}
	StorageNodesMu.Unlock()
	go SaveNodes()

	// Reply with the public key so the child node can store it
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_key": Cfg.NodePublicKey,
		"status":     "connected",
	})
}

// ─── Node Info (proxy — fetch stats from a remote node) ──────────────────────

func HandleNodeInfo(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("id")

	// Special case: "local" or empty → return this server's own stats
	if nodeID == "" || nodeID == "default" || nodeID == "local" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(collectLocalNodeInfo())
		return
	}

	StorageNodesMu.RLock()
	var target *StorageNode
	for _, n := range StorageNodes {
		if n.ID == nodeID {
			target = n
			break
		}
	}
	StorageNodesMu.RUnlock()

	if target == nil {
		http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
		return
	}

	// For non-default nodes, return what we know + placeholder stats
	// (full remote stats would require an agent running on the remote node)
	info := collectLocalNodeInfo()
	info["node_name"] = target.Name
	info["node_ip"]   = target.IP
	info["node_url"]  = target.IP
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func collectLocalNodeInfo() map[string]interface{} {
	info := map[string]interface{}{
		"node_name": Cfg.SiteName,
		"node_ip":   Cfg.IP,
		"node_url":  Cfg.IP,
	}

	// CPU count
	cpuCount := 0
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "processor") {
				cpuCount++
			}
		}
	}
	info["cpu_cores"] = cpuCount

	// CPU usage (1-second sample via /proc/stat)
	info["cpu_percent"] = readCPUPercent()

	// RAM
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available int64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				total = val * 1024
			case "MemAvailable:":
				available = val * 1024
			}
		}
		info["ram_total"] = total
		info["ram_used"]  = total - available
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			secs, _ := strconv.ParseFloat(fields[0], 64)
			info["uptime_seconds"] = int64(secs)
		}
	}

	// Public IP (best-effort)
	info["public_ip"] = Cfg.IP

	// Disk info
	disks := collectDiskInfo()
	info["disks"] = disks

	return info
}

func readCPUPercent() float64 {
	readStat := func() (idle, total int64) {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)
			for i, f := range fields[1:] {
				v, _ := strconv.ParseInt(f, 10, 64)
				total += v
				if i == 3 {
					idle = v
				}
			}
			break
		}
		return
	}
	idle1, total1 := readStat()
	time.Sleep(500 * time.Millisecond)
	idle2, total2 := readStat()
	dTotal := total2 - total1
	dIdle  := idle2 - idle1
	if dTotal == 0 {
		return 0
	}
	return float64(dTotal-dIdle) / float64(dTotal) * 100
}

type DiskStat struct {
	Device string `json:"device"`
	Path   string `json:"path"`
	Total  int64  `json:"total"`
	Used   int64  `json:"used"`
	Free   int64  `json:"free"`
}

func collectDiskInfo() []DiskStat {
	var disks []DiskStat
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return disks
	}

	// Build a set of physical block device base names from /sys/block.
	// Entries like sda, nvme0n1, vda, hda are real disks; loop/ram/dm-/zram/sr are not.
	physDevs := map[string]bool{}
	if entries, err := os.ReadDir("/sys/block"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
				strings.HasPrefix(name, "zram") || strings.HasPrefix(name, "dm-") ||
				strings.HasPrefix(name, "md") || strings.HasPrefix(name, "sr") {
				continue
			}
			physDevs[name] = true
		}
	}

	// isPhysicalDev returns true when dev belongs to a known physical block device.
	isPhysicalDev := func(dev string) bool {
		if !strings.HasPrefix(dev, "/dev/") {
			return false
		}
		devName := strings.TrimPrefix(dev, "/dev/")
		if physDevs[devName] {
			return true
		}
		// Partition: strip trailing digits (sda1→sda, vda2→vda)
		stripped := strings.TrimRight(devName, "0123456789")
		if physDevs[stripped] {
			return true
		}
		// NVMe partition style: nvme0n1p2 → nvme0n1
		if idx := strings.LastIndex(stripped, "p"); idx > 0 {
			if physDevs[stripped[:idx]] {
				return true
			}
		}
		return false
	}

	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		dev        := fields[0]
		mountPoint := fields[1]
		if !isPhysicalDev(dev) {
			continue
		}
		if seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true
		var stat syscallStatfs
		if err := syscallStatfsCall(mountPoint, &stat); err == nil {
			total := int64(stat.Blocks) * int64(stat.Bsize)
			free  := int64(stat.Bfree)  * int64(stat.Bsize)
			if total > 0 {
				disks = append(disks, DiskStat{
					Device: dev,
					Path:   mountPoint,
					Total:  total,
					Used:   total - free,
					Free:   free,
				})
			}
		}
	}
	return disks
}
