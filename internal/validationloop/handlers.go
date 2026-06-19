package validationloop

import (
	"encoding/json"
	"net/http"
	"strings"
)

type ValidationHandler struct {
	loop *ValidationLoop
}

func NewValidationHandler(loop *ValidationLoop) *ValidationHandler {
	return &ValidationHandler{loop: loop}
}

func (h *ValidationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/validation-loops/")

	switch {
	case r.Method == http.MethodGet && (path == "" || path == "tasks"):
		h.handleList(w, r)
	case r.Method == http.MethodPost && path == "tasks":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "tasks/"):
		id := strings.TrimPrefix(path, "tasks/")
		task := h.loop.GetTask(id)
		if task == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(task)
	case r.Method == http.MethodGet && path == "stats":
		json.NewEncoder(w).Encode(h.loop.GetStats())
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *ValidationHandler) handleList(w http.ResponseWriter, r *http.Request) {
	tasks := h.loop.ListTasks()
	if tasks == nil {
		tasks = []ValidationTask{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
		"total": len(tasks),
	})
}

func (h *ValidationHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FindingID         string `json:"finding_id"`
		Target            string `json:"target"`
		VulnerabilityType string `json:"vulnerability_type"`
		Evidence          string `json:"evidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}

	id := h.loop.AddTask(req.FindingID, req.Target, req.VulnerabilityType, req.Evidence)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func RegisterValidationHandlers(mux *http.ServeMux, loop *ValidationLoop) {
	handler := NewValidationHandler(loop)
	mux.HandleFunc("/api/validation-loops", handler.ServeHTTP)
	mux.HandleFunc("/api/validation-loops/", handler.ServeHTTP)
}
