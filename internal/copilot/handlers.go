package copilot

import (
	"encoding/json"
	"net/http"
)

func RegisterCopilotHandlers(mux *http.ServeMux, copilot *CopilotEngine) {
	mux.HandleFunc("/api/copilot/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}

		resp := copilot.ProcessQuery(req)
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/copilot/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			history := copilot.GetHistory()
			if history == nil {
				history = []ConversationEntry{}
			}
			json.NewEncoder(w).Encode(history)
		case http.MethodDelete:
			copilot.ClearHistory()
			json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/copilot/suggestions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string][]string{
			"suggestions": copilot.generateSuggestions(""),
		})
	})
}
