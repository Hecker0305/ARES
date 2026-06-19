package approvals

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ApprovalHandler struct {
	engine *WorkflowEngine
}

func NewApprovalHandler(engine *WorkflowEngine) *ApprovalHandler {
	return &ApprovalHandler{engine: engine}
}

func (h *ApprovalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/approvals/")
	parts := strings.SplitN(path, "/", 2)

	switch {
	case r.Method == http.MethodGet && path == "":
		h.handleList(w, r)
	case r.Method == http.MethodPost && path == "":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] != "":
		h.handleGet(w, r, parts[0])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "approve":
		h.handleApprove(w, r, parts[0])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "deny":
		h.handleDeny(w, r, parts[0])
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *ApprovalHandler) handleList(w http.ResponseWriter, r *http.Request) {
	reqs := h.engine.ListRequests()
	if reqs == nil {
		reqs = []ApprovalRequest{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"approvals": reqs,
		"total":     len(reqs),
	})
}

func (h *ApprovalHandler) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	req := h.engine.GetRequest(id)
	if req == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(req)
}

func (h *ApprovalHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req ApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	id, err := h.engine.CreateRequest(req)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *ApprovalHandler) handleApprove(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Approver string `json:"approver"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Approver == "" {
		body.Approver = "admin"
	}

	if err := h.engine.Approve(id, body.Approver); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
}

func (h *ApprovalHandler) handleDeny(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Denier string `json:"denier"`
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Denier == "" {
		body.Denier = "admin"
	}

	if err := h.engine.Deny(id, body.Denier, body.Reason); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "denied"})
}

type EmergencyStop struct {
	mu          sync.RWMutex
	active      bool
	triggered   bool
	reason      string
	triggeredAt time.Time
}

var globalEmergencyStop = &EmergencyStop{}

func (e *EmergencyStop) IsActive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active
}

func (e *EmergencyStop) GetReason() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.reason
}

func (e *EmergencyStop) Activate(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = true
	e.triggered = true
	e.reason = reason
	e.triggeredAt = time.Now()
}

func (e *EmergencyStop) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = false
	e.reason = ""
}

func (e *EmergencyStop) Status() (bool, string, time.Time) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active, e.reason, e.triggeredAt
}

func IsEStopActive() bool {
	return globalEmergencyStop.IsActive()
}

func GetEStopReason() string {
	return globalEmergencyStop.GetReason()
}

func (h *ApprovalHandler) handleEStop(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		globalEmergencyStop.Activate(body.Reason)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "emergency_stop_activated"})
	case http.MethodDelete:
		globalEmergencyStop.Clear()
		json.NewEncoder(w).Encode(map[string]string{"status": "emergency_stop_cleared"})
	case http.MethodGet:
		active, reason, triggeredAt := globalEmergencyStop.Status()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active":       active,
			"reason":       reason,
			"triggered_at": triggeredAt,
		})
	}
}

func RegisterApprovalHandlers(mux *http.ServeMux, engine *WorkflowEngine) {
	handler := NewApprovalHandler(engine)
	mux.HandleFunc("/api/approvals", handler.ServeHTTP)
	mux.HandleFunc("/api/approvals/", handler.ServeHTTP)
	mux.HandleFunc("/api/emergency-stop", handler.handleEStop)
}
