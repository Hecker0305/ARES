package webhook

import (
	"encoding/json"
	"net/http"

	"github.com/ares/engine/internal/security"
)

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func ListWebhooksHandler(manager *WebhookManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, manager.List())
	}
}

func CreateWebhookHandler(manager *WebhookManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var cfg WebhookConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if cfg.ID == "" || cfg.URL == "" || cfg.Type == "" {
			http.Error(w, "id, url, and type are required", http.StatusBadRequest)
			return
		}
		if err := security.ValidateURL(cfg.URL); err != nil {
			http.Error(w, "invalid webhook URL: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(cfg.Events) == 0 {
			cfg.Events = []string{"*"}
		}
		manager.AddOrUpdate(cfg)
		writeJSON(w, map[string]string{"status": "created", "id": cfg.ID})
	}
}

func DeleteWebhookHandler(manager *WebhookManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing webhook id", http.StatusBadRequest)
			return
		}
		manager.Delete(id)
		writeJSON(w, map[string]string{"status": "deleted"})
	}
}

func TestWebhookHandler(manager *WebhookManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var cfg WebhookConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if cfg.URL == "" || cfg.Type == "" {
			http.Error(w, "url and type are required", http.StatusBadRequest)
			return
		}
		if err := security.ValidateURL(cfg.URL); err != nil {
			http.Error(w, "invalid webhook URL", http.StatusBadRequest)
			return
		}
		if err := manager.SendTest(cfg); err != nil {
			http.Error(w, "test failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "test sent"})
	}
}
