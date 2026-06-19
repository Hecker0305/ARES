package exposure

import (
	"encoding/json"
	"net/http"
	"strings"
)

type ExposureHandler struct {
	monitor *ExposureMonitor
}

func NewExposureHandler(monitor *ExposureMonitor) *ExposureHandler {
	return &ExposureHandler{monitor: monitor}
}

func (h *ExposureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/exposure/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.handleList(w, r)
	case r.Method == http.MethodGet && path != "":
		h.handleListByType(w, r, path)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (h *ExposureHandler) handleList(w http.ResponseWriter, r *http.Request) {
	findings := h.monitor.GetFindings()
	if findings == nil {
		findings = []ExposureFinding{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"total":    len(findings),
	})
}

func (h *ExposureHandler) handleListByType(w http.ResponseWriter, r *http.Request, exposureType string) {
	findings := h.monitor.GetFindingsByType(ExposureType(exposureType))
	if findings == nil {
		findings = []ExposureFinding{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"total":    len(findings),
	})
}

func RegisterExposureHandlers(mux *http.ServeMux, monitor *ExposureMonitor) {
	handler := NewExposureHandler(monitor)
	mux.HandleFunc("/api/exposure", handler.ServeHTTP)
	mux.HandleFunc("/api/exposure/", handler.ServeHTTP)
}
