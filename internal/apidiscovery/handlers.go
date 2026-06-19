package apidiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/uuid"
)

type scanJob struct {
	ID        string
	Target    string
	Status    string
	Result    *APIDiscoveryResult
	CreatedAt time.Time
	DoneAt    time.Time
	Error     string
}

type Handler struct {
	mu        sync.RWMutex
	jobs      map[string]*scanJob
	scanner   *Scanner
	basePath  string
	nextID    int
	authToken string
}

func NewHandler(scanner *Scanner, basePath string, authToken string) *Handler {
	return &Handler{
		jobs:      make(map[string]*scanJob),
		scanner:   scanner,
		basePath:  strings.TrimRight(basePath, "/"),
		nextID:    1,
		authToken: authToken,
	}
}

func (h *Handler) generateID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := fmt.Sprintf("disc-%s-%d", uuid.New(), h.nextID)
	h.nextID++
	return id
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	prefix := h.basePath
	mux.HandleFunc("POST "+prefix+"/api/discover", h.authMiddleware(h.handleDiscover))
	mux.HandleFunc("GET "+prefix+"/api/discover/", h.authMiddleware(h.handleGetResults))
}

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.authToken == "" {
			http.Error(w, `{"error":"authentication not configured"}`, http.StatusForbidden)
			return
		}
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}
		if token != h.authToken {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (h *Handler) handleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		http.Error(w, `{"error":"target is required"}`, http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(req.Target, "http://") && !strings.HasPrefix(req.Target, "https://") {
		req.Target = "https://" + req.Target
	}

	if err := security.ValidateURL(req.Target); err != nil {
		http.Error(w, `{"error":"invalid target URL"}`, http.StatusBadRequest)
		return
	}
	u, parseErr := url.Parse(req.Target)
	if parseErr == nil {
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
				http.Error(w, `{"error":"private/internal IP not allowed"}`, http.StatusBadRequest)
				return
			}
		} else {
			ips, err := net.LookupIP(host)
			if err != nil {
				http.Error(w, `{"error":"DNS resolution failed"}`, http.StatusBadRequest)
				return
			}
			for _, ip := range ips {
				if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
					http.Error(w, `{"error":"target resolves to private/internal IP"}`, http.StatusBadRequest)
					return
				}
			}
		}
	}

	jobID := h.generateID()

	job := &scanJob{
		ID:        jobID,
		Target:    req.Target,
		Status:    "running",
		CreatedAt: time.Now(),
	}

	h.mu.Lock()
	h.jobs[jobID] = job
	h.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()

		result := h.scanner.ScanTarget(ctx, req.Target)

		h.mu.Lock()
		job.Status = "completed"
		job.DoneAt = time.Now()
		job.Result = result
		if result.Error != "" {
			job.Error = result.Error
		}
		h.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"scan_id":    jobID,
		"target":     req.Target,
		"status":     "running",
		"check_url":  h.basePath + "/api/discover/" + jobID + "/results",
		"created_at": job.CreatedAt.Format(time.RFC3339),
	})
}

func (h *Handler) handleGetResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, h.basePath+"/api/discover/")
	path = strings.TrimSuffix(path, "/results")
	path = strings.TrimSuffix(path, "/")

	scanID := path
	if scanID == "" {
		http.Error(w, `{"error":"scan_id is required"}`, http.StatusBadRequest)
		return
	}

	h.mu.RLock()
	job, exists := h.jobs[scanID]
	h.mu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"scan not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if job.Status == "running" {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{
			"scan_id":    job.ID,
			"target":     job.Target,
			"status":     "running",
			"created_at": job.CreatedAt.Format(time.RFC3339),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"scan_id":    job.ID,
		"target":     job.Target,
		"status":     job.Status,
		"result":     job.Result,
		"error":      job.Error,
		"created_at": job.CreatedAt.Format(time.RFC3339),
		"done_at":    job.DoneAt.Format(time.RFC3339),
	})
}
