package purpleteam

import (
	"encoding/json"
	"net/http"
	"strings"
)

type PurpleTeamHandler struct {
	engine *PurpleTeamEngine
}

func NewPurpleTeamHandler(engine *PurpleTeamEngine) *PurpleTeamHandler {
	return &PurpleTeamHandler{engine: engine}
}

func (h *PurpleTeamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/purple-team/")

	switch {
	case r.Method == http.MethodGet && (path == "" || path == "simulations"):
		sims := h.engine.ListSimulations()
		if sims == nil {
			sims = []PurpleTeamSimulation{}
		}
		json.NewEncoder(w).Encode(sims)
	case r.Method == http.MethodPost && path == "simulations":
		h.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "simulations/"):
		id := strings.TrimPrefix(path, "simulations/")
		sim := h.engine.GetSimulation(id)
		if sim == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(sim)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "simulations/"):
		id := strings.TrimPrefix(path, "simulations/")
		id = strings.TrimSuffix(id, "/start")
		if strings.HasSuffix(path, "/start") {
			if err := h.engine.StartSimulation(id); err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "started"})
		} else {
			http.NotFound(w, r)
		}
	case r.Method == http.MethodGet && path == "coverage":
		json.NewEncoder(w).Encode(h.engine.CoverageReport())
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *PurpleTeamHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var sim PurpleTeamSimulation
	if err := json.NewDecoder(r.Body).Decode(&sim); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}

	id := h.engine.CreateSimulation(sim)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func RegisterPurpleTeamHandlers(mux *http.ServeMux, engine *PurpleTeamEngine) {
	handler := NewPurpleTeamHandler(engine)
	mux.HandleFunc("/api/purple-team", handler.ServeHTTP)
	mux.HandleFunc("/api/purple-team/", handler.ServeHTTP)
}
