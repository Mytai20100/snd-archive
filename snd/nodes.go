package snd

import (
	"encoding/json"
	"net/http"
	"os"
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
