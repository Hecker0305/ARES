package agentdeploy

import (
	"encoding/json"
	"net/http"
	"strings"
)

type AgentHandler struct {
	manager *AgentManager
}

func NewAgentHandler(manager *AgentManager) *AgentHandler {
	return &AgentHandler{manager: manager}
}

func (h *AgentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/agents/")

	switch {
	case r.Method == http.MethodGet && (path == "" || path == "agents"):
		h.handleList(w, r)
	case r.Method == http.MethodGet && path == "stats":
		json.NewEncoder(w).Encode(h.manager.GetStats())
	case r.Method == http.MethodPost && (path == "" || path == "register"):
		h.handleRegister(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "agents/"):
		id := strings.TrimPrefix(path, "agents/")
		agent := h.manager.GetAgent(id)
		if agent == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(agent)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "heartbeat/"):
		id := strings.TrimPrefix(path, "heartbeat/")
		if h.manager.Heartbeat(id) {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		} else {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	case r.Method == http.MethodPost && strings.HasPrefix(path, "scan/"):
		id := strings.TrimPrefix(path, "scan/")
		var req struct {
			Target   string `json:"target"`
			ScanType string `json:"scan_type"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.ScanType == "" {
			req.ScanType = "quick"
		}
		taskID, err := h.manager.AssignScan(id, req.Target, req.ScanType)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"task_id": taskID})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "tasks"):
		agentID := r.URL.Query().Get("agent_id")
		tasks := h.manager.GetTasks(agentID)
		if tasks == nil {
			tasks = []ScanTask{}
		}
		json.NewEncoder(w).Encode(tasks)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "agents/"):
		id := strings.TrimPrefix(path, "agents/")
		if h.manager.RemoveAgent(id) {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *AgentHandler) handleList(w http.ResponseWriter, r *http.Request) {
	segment := r.URL.Query().Get("segment")
	var agents []*DeployedAgent
	if segment != "" {
		agents = h.manager.ListAgentsBySegment(segment)
	} else {
		agents = h.manager.ListAgents()
	}
	if agents == nil {
		agents = []*DeployedAgent{}
	}
	json.NewEncoder(w).Encode(agents)
}

func (h *AgentHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var agent DeployedAgent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}
	id := h.manager.Register(agent)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func RegisterAgentHandlers(mux *http.ServeMux, manager *AgentManager) {
	handler := NewAgentHandler(manager)
	mux.HandleFunc("/api/agents", handler.ServeHTTP)
	mux.HandleFunc("/api/agents/", handler.ServeHTTP)
}
