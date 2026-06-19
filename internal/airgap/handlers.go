package airgap

import (
	"encoding/json"
	"net/http"
)

type AirGapHandlers struct {
	manager *AirGapManager
}

func NewAirGapHandlers(manager *AirGapManager) *AirGapHandlers {
	return &AirGapHandlers{manager: manager}
}

func (h *AirGapHandlers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/airgap/status" && r.Method == http.MethodGet:
		h.handleStatus(w, r)
	case r.URL.Path == "/api/airgap/policy" && r.Method == http.MethodGet:
		h.handlePolicy(w, r)
	case r.URL.Path == "/api/airgap/validate" && r.Method == http.MethodPost:
		h.handleValidate(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *AirGapHandlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"airgapped": h.manager.IsAirGapped(),
		"enabled":   h.manager.IsAirGapped(),
	})
}

func (h *AirGapHandlers) handlePolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"config":          h.manager.GetConfig(),
		"allowed_domains": h.manager.GetAllowedDomains(),
		"blocked_ips":     h.manager.GetBlockedIPs(),
	})
}

func (h *AirGapHandlers) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	valid := h.manager.ValidateExternalRequest(req.URL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":   req.URL,
		"valid": valid,
	})
}
