package compliancebuilder

import (
	"encoding/json"
	"net/http"
	"strings"
)

type BuilderHandler struct {
	builder *ComplianceBuilder
}

func NewBuilderHandler(builder *ComplianceBuilder) *BuilderHandler {
	return &BuilderHandler{builder: builder}
}

func (h *BuilderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/compliance-frameworks/")

	switch {
	case r.Method == http.MethodGet && (path == "" || path == "frameworks"):
		fws := h.builder.ListFrameworks()
		if fws == nil {
			fws = []*Framework{}
		}
		json.NewEncoder(w).Encode(fws)
	case r.Method == http.MethodPost && (path == "" || path == "frameworks"):
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "frameworks/"):
		id := strings.TrimPrefix(path, "frameworks/")
		fw := h.builder.GetFramework(id)
		if fw == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(fw)
	case r.Method == http.MethodPut && strings.HasPrefix(path, "frameworks/"):
		id := strings.TrimPrefix(path, "frameworks/")
		var updates Framework
		json.NewDecoder(r.Body).Decode(&updates)
		if h.builder.UpdateFramework(id, updates) {
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
		} else {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "frameworks/"):
		id := strings.TrimPrefix(path, "frameworks/")
		if h.builder.DeleteFramework(id) {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	case r.Method == http.MethodPost && strings.Contains(path, "controls"):
		parts := strings.Split(path, "/")
		if len(parts) >= 3 && parts[0] == "frameworks" {
			fwID := parts[1]
			var control Control
			if err := json.NewDecoder(r.Body).Decode(&control); err != nil {
				http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
				return
			}
			id, err := h.builder.AddControl(fwID, control)
			if err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": id})
		}
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *BuilderHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var fw Framework
	if err := json.NewDecoder(r.Body).Decode(&fw); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}

	id, err := h.builder.CreateFramework(fw)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func RegisterComplianceBuilderHandlers(mux *http.ServeMux, builder *ComplianceBuilder) {
	handler := NewBuilderHandler(builder)
	mux.HandleFunc("/api/compliance-frameworks", handler.ServeHTTP)
	mux.HandleFunc("/api/compliance-frameworks/", handler.ServeHTTP)
}
