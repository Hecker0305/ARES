package cloudscanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxCloudBody = 1 << 20

type ScanStore struct {
	mu    sync.RWMutex
	scans map[string]*ScanRecord
}

type ScanRecord struct {
	ID        string         `json:"id"`
	Path      string         `json:"path"`
	Status    string         `json:"status"`
	Findings  []CloudFinding `json:"findings,omitempty"`
	Error     string         `json:"error,omitempty"`
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time,omitempty"`
}

var globalScanStore = &ScanStore{
	scans: make(map[string]*ScanRecord),
}

func (s *ScanStore) Set(id string, record *ScanRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[id] = record
}

func (s *ScanStore) Get(id string) *ScanRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scans[id]
}

func writeCloudJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func readCloudJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxCloudBody)
	return json.NewDecoder(r.Body).Decode(v)
}

func cloudAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := os.Getenv("ARES_WEB_AUTH_TOKEN")
		if token == "" {
			token = os.Getenv("ARES_AUTH_TOKEN")
		}
		if token != "" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func HandleCloudScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := readCloudJSON(w, r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	if strings.Contains(req.Path, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	cleanPath := filepath.Clean(req.Path)
	if !filepath.IsAbs(cleanPath) {
		http.Error(w, "path must be absolute", http.StatusBadRequest)
		return
	}
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		http.Error(w, "path not accessible", http.StatusBadRequest)
		return
	}

	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	id := "cs-" + hex.EncodeToString(idBytes)

	record := &ScanRecord{
		ID:        id,
		Path:      resolved,
		Status:    "running",
		StartTime: time.Now(),
	}
	globalScanStore.Set(id, record)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		done := make(chan []CloudFinding, 1)
		var scanErr error
		go func() {
			f, err := ScanDirectory(resolved)
			if err != nil {
				scanErr = err
			} else {
				done <- f
			}
		}()
		var findings []CloudFinding
		select {
		case findings = <-done:
		case <-ctx.Done():
			scanErr = fmt.Errorf("scan timed out")
		}
		record := globalScanStore.Get(id)
		if record == nil {
			return
		}
		if scanErr != nil {
			record.Error = "scan failed"
			record.Status = "error"
		} else {
			record.Findings = DedupFindings(findings)
			record.Status = "complete"
		}
		record.EndTime = time.Now()
		globalScanStore.Set(id, record)
	}()

	writeCloudJSON(w, map[string]string{
		"scan_id": id,
		"status":  "running",
		"path":    resolved,
	})
}

func HandleCloudGetResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/cloud/scan/")
	id := strings.SplitN(path, "?", 2)[0]
	if id == "" || id == r.URL.Path {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}

	record := globalScanStore.Get(id)
	if record == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	writeCloudJSON(w, record)
}

func HandleCloudValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Line string `json:"line"`
	}
	if err := readCloudJSON(w, r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Line == "" {
		http.Error(w, "line is required", http.StatusBadRequest)
		return
	}

	findings, err := ValidateConfigLine(req.Line)
	if err != nil {
		http.Error(w, "validation error", http.StatusInternalServerError)
		return
	}

	writeCloudJSON(w, map[string]interface{}{
		"input":    req.Line,
		"findings": findings,
		"safe":     len(findings) == 0,
	})
}

func RegisterCloudScannerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/cloud/scan", cloudAuthMiddleware(HandleCloudScan))
	mux.HandleFunc("/api/cloud/scan/", cloudAuthMiddleware(HandleCloudGetResult))
	mux.HandleFunc("/api/cloud/validate", cloudAuthMiddleware(HandleCloudValidate))
}
