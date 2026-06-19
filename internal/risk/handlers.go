package risk

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type RiskHandler struct {
	engine *RiskEngine
}

func NewRiskHandler(engine *RiskEngine) *RiskHandler {
	return &RiskHandler{engine: engine}
}

func (h *RiskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/risk/")

	switch {
	case r.Method == http.MethodGet && (path == "" || path == "profile"):
		h.handleProfile(w, r)
	case r.Method == http.MethodGet && path == "assets":
		h.handleListAssets(w, r)
	case r.Method == http.MethodPost && path == "assets":
		h.handleRegisterAsset(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "assets/"):
		id := strings.TrimPrefix(path, "assets/")
		h.handleGetAsset(w, r, id)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "impact/"):
		id := strings.TrimPrefix(path, "impact/")
		h.handleGetImpact(w, r, id)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "impact/"):
		id := strings.TrimPrefix(path, "impact/")
		h.handleCalculateImpact(w, r, id)
	case r.Method == http.MethodGet && path == "trends":
		h.handleTrends(w, r)
	case r.Method == http.MethodGet && path == "sla":
		h.handleSLA(w, r)
	case r.Method == http.MethodGet && path == "sla/compliance":
		h.handleSLACompliance(w, r)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *RiskHandler) handleProfile(w http.ResponseWriter, r *http.Request) {
	profile := h.engine.CurrentRiskProfile()
	json.NewEncoder(w).Encode(profile)
}

func (h *RiskHandler) handleListAssets(w http.ResponseWriter, r *http.Request) {
	assets := h.engine.ListAssets()
	if assets == nil {
		assets = []Asset{}
	}
	json.NewEncoder(w).Encode(assets)
}

func (h *RiskHandler) handleRegisterAsset(w http.ResponseWriter, r *http.Request) {
	var asset Asset
	if err := json.NewDecoder(r.Body).Decode(&asset); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	h.engine.RegisterAsset(asset)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(asset)
}

func (h *RiskHandler) handleGetAsset(w http.ResponseWriter, r *http.Request, id string) {
	asset, ok := h.engine.GetAsset(id)
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(asset)
}

func (h *RiskHandler) handleGetImpact(w http.ResponseWriter, r *http.Request, id string) {
	impact, ok := h.engine.GetImpact(id)
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(impact)
}

func (h *RiskHandler) handleCalculateImpact(w http.ResponseWriter, r *http.Request, id string) {
	var params struct {
		VulnerabilityScore float64 `json:"vulnerability_score"`
		Exploitability     float64 `json:"exploitability"`
	}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	impact := h.engine.CalculateBusinessImpact(id, params.VulnerabilityScore, params.Exploitability)
	json.NewEncoder(w).Encode(impact)
}

func (h *RiskHandler) handleTrends(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")
	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}
	trends := h.engine.GetTrends(days)
	if trends == nil {
		trends = []RiskTrend{}
	}
	json.NewEncoder(w).Encode(trends)
}

func (h *RiskHandler) handleSLA(w http.ResponseWriter, r *http.Request) {
	entries := h.engine.sla.GetSLAEntries(true)
	if entries == nil {
		entries = []SLAEntry{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"overdue": entries,
		"total":   len(entries),
	})
}

func (h *RiskHandler) handleSLACompliance(w http.ResponseWriter, r *http.Request) {
	rate := h.engine.sla.SLAComplianceRate()
	json.NewEncoder(w).Encode(map[string]float64{"compliance_rate": rate})
}

func RegisterRiskHandlers(mux *http.ServeMux, engine *RiskEngine) {
	handler := NewRiskHandler(engine)
	mux.HandleFunc("/api/risk", handler.ServeHTTP)
	mux.HandleFunc("/api/risk/", handler.ServeHTTP)
}
