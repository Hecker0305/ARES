package ticketing

import (
	"encoding/json"
	"net/http"
	"strings"
)

type ProviderHandler struct {
	manager *TicketManager
}

func NewProviderHandler(manager *TicketManager) *ProviderHandler {
	return &ProviderHandler{manager: manager}
}

func (h *ProviderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/ticketing/providers")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.listProviders(w, r)
	case path == "" && r.Method == http.MethodPost:
		h.addProvider(w, r)
	case path == "test" && r.Method == http.MethodPost:
		h.testProvider(w, r)
	case strings.Count(path, "/") == 1 && strings.HasSuffix(path, "/test") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(path, "/test")
		h.testSpecificProvider(w, r, id)
	case strings.Count(path, "/") == 0 && path != "" && r.Method == http.MethodDelete:
		h.removeProvider(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *ProviderHandler) listProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.manager.ListProviders()
	writeJSON(w, providers)
}

func (h *ProviderHandler) addProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string   `json:"id"`
		Provider  Provider `json:"provider"`
		URL       string   `json:"url"`
		Token     string   `json:"token"`
		Email     string   `json:"email"`
		Project   string   `json:"project"`
		Enabled   bool     `json:"enabled"`
		Assignees []string `json:"assignees,omitempty"`
		Owner     string   `json:"owner,omitempty"`
		Repo      string   `json:"repo,omitempty"`
		Labels    []string `json:"labels,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Provider == "" {
		writeError(w, "id and provider are required", http.StatusBadRequest)
		return
	}

	if req.Provider != ProviderJira && req.Provider != ProviderGitHub && req.Provider != ProviderServiceNow && req.Provider != ProviderLinear {
		writeError(w, "provider must be 'jira', 'github', 'servicenow', or 'linear'", http.StatusBadRequest)
		return
	}

	if h.manager.GetProvider(req.ID) != nil {
		writeError(w, "provider id already exists", http.StatusConflict)
		return
	}

	cfg := &TicketConfig{
		Provider:  req.Provider,
		URL:       req.URL,
		Token:     req.Token,
		Email:     req.Email,
		Project:   req.Project,
		Enabled:   req.Enabled,
		Assignees: req.Assignees,
		Owner:     req.Owner,
		Repo:      req.Repo,
		Labels:    req.Labels,
	}

	h.manager.AddProvider(req.ID, cfg)
	writeJSON(w, map[string]string{"status": "provider added", "id": req.ID})
}

func (h *ProviderHandler) removeProvider(w http.ResponseWriter, r *http.Request, id string) {
	if h.manager.GetProvider(id) == nil {
		writeError(w, "provider not found", http.StatusNotFound)
		return
	}
	h.manager.RemoveProvider(id)
	writeJSON(w, map[string]string{"status": "provider removed", "id": id})
}

func (h *ProviderHandler) testProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "bad request", http.StatusBadRequest)
		return
	}
	h.testAndRespond(w, req.ID)
}

func (h *ProviderHandler) testSpecificProvider(w http.ResponseWriter, r *http.Request, id string) {
	h.testAndRespond(w, id)
}

func (h *ProviderHandler) testAndRespond(w http.ResponseWriter, id string) {
	if h.manager.GetProvider(id) == nil {
		writeError(w, "provider not found", http.StatusNotFound)
		return
	}

	if err := h.manager.TestConnection(id); err != nil {
		writeError(w, "connection failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]string{"status": "ok", "message": "connection successful"})
}
