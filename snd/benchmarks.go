package snd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

func HandleBenchmarkPing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "pong",
		"time":   time.Now().Format(time.RFC3339Nano),
	})
}

func HandleBenchmarkDownload(w http.ResponseWriter, r *http.Request) {
	size := 10 * 1024 * 1024
	if sizeParam := r.URL.Query().Get("size"); sizeParam != "" {
		if s, err := strconv.Atoi(sizeParam); err == nil {
			size = s * 1024 * 1024
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	buffer := make([]byte, 32768)
	for i := 0; i < size; i += len(buffer) {
		remaining := size - i
		if remaining < len(buffer) {
			w.Write(buffer[:remaining])
		} else {
			w.Write(buffer)
		}
	}
}

func HandleBenchmarkUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	startTime := time.Now()
	written, err := io.Copy(io.Discard, r.Body)
	duration := time.Since(startTime).Seconds()
	if err != nil {
		http.Error(w, "Upload error", http.StatusInternalServerError)
		return
	}
	speed := float64(written) / duration / 1024 / 1024
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"bytes":    written,
		"duration": duration,
		"speed":    speed,
	})
}

func HandleBenchmarkDisk(w http.ResponseWriter, r *http.Request) {
	testFile := filepath.Join(PublicDir, ".benchmark_test")
	defer os.Remove(testFile)

	data := make([]byte, 10*1024*1024)
	writeStart := time.Now()
	writeErr := os.WriteFile(testFile, data, 0644)
	writeDuration := time.Since(writeStart).Seconds()
	writeSpeed := float64(len(data)) / writeDuration / 1024 / 1024

	readStart := time.Now()
	_, readErr := os.ReadFile(testFile)
	readDuration := time.Since(readStart).Seconds()
	readSpeed := float64(len(data)) / readDuration / 1024 / 1024

	if writeErr != nil || readErr != nil {
		http.Error(w, "Disk test error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"write_speed": writeSpeed,
		"read_speed":  readSpeed,
		"write_time":  writeDuration,
		"read_time":   readDuration,
	})
}

func HandleBenchmarkCPU(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	result := 0
	for i := 0; i < 10000000; i++ {
		result += i
	}
	elapsed := time.Since(start)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"test":         "cpu",
		"duration_ms":  elapsed.Milliseconds(),
		"iterations":   10000000,
		"result":       result,
	})
}

func HandleBenchmarkMemory(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"test":            "memory",
		"alloc_mb":        m.Alloc / 1024 / 1024,
		"total_alloc_mb":  m.TotalAlloc / 1024 / 1024,
		"sys_mb":          m.Sys / 1024 / 1024,
		"num_gc":          m.NumGC,
		"goroutines":      runtime.NumGoroutine(),
	})
}

func HandleBenchmarkNetwork(w http.ResponseWriter, r *http.Request) {
	data := make([]byte, 1024*1024)
	start := time.Now()
	w.Write(data)
	elapsed := time.Since(start)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"test":        "network",
		"duration_ms": elapsed.Milliseconds(),
		"bytes_sent":  len(data),
		"speed_mbps":  float64(len(data)*8) / float64(elapsed.Milliseconds()) / 1000,
	})
}
