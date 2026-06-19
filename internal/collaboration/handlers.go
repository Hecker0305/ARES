package collaboration

import (
	"encoding/json"
	"net/http"
	"strings"
)

type CollaborationHandler struct {
	engine *CollaborationEngine
}

func NewCollaborationHandler(engine *CollaborationEngine) *CollaborationHandler {
	return &CollaborationHandler{engine: engine}
}

func (h *CollaborationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/collaboration/")

	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(path, "comments"):
		h.handleAddComment(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "comments/"):
		targetID := strings.TrimPrefix(path, "comments/")
		comments := h.engine.GetComments(targetID)
		if comments == nil {
			comments = []Comment{}
		}
		json.NewEncoder(w).Encode(comments)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "assignments"):
		h.handleAssign(w, r)
	case r.Method == http.MethodGet && path == "assignments":
		assignee := r.URL.Query().Get("assignee")
		assignments := h.engine.GetAssignments(assignee)
		if assignments == nil {
			assignments = []Assignment{}
		}
		json.NewEncoder(w).Encode(assignments)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "assignments/"):
		id := strings.TrimPrefix(path, "assignments/")
		if strings.HasSuffix(path, "/complete") {
			id = strings.TrimSuffix(id, "/complete")
			if h.engine.CompleteAssignment(id) {
				json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
			} else {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			}
		}
	case r.Method == http.MethodPost && strings.HasPrefix(path, "reviews"):
		h.handleCreateReview(w, r)
	case r.Method == http.MethodGet && path == "reviews":
		status := r.URL.Query().Get("status")
		reviews := h.engine.GetReviews(status)
		if reviews == nil {
			reviews = []EvidenceReview{}
		}
		json.NewEncoder(w).Encode(reviews)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "reviews/"):
		id := strings.TrimPrefix(path, "reviews/")
		var body struct {
			Notes string `json:"notes"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if strings.HasSuffix(path, "/approve") {
			h.engine.ApproveReview(id, body.Notes)
			json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		} else if strings.HasSuffix(path, "/reject") {
			h.engine.RejectReview(id, body.Notes)
			json.NewEncoder(w).Encode(map[string]string{"status": "rejected"})
		} else {
			http.NotFound(w, r)
		}
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *CollaborationHandler) handleAddComment(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TargetID   string `json:"target_id"`
		TargetType string `json:"target_type"`
		Author     string `json:"author"`
		Content    string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}

	id := h.engine.AddComment(body.TargetID, body.TargetType, body.Author, body.Content)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *CollaborationHandler) handleAssign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TargetID   string `json:"target_id"`
		TargetType string `json:"target_type"`
		Assignee   string `json:"assignee"`
		AssignedBy string `json:"assigned_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}

	id := h.engine.Assign(body.TargetID, body.TargetType, body.Assignee, body.AssignedBy)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *CollaborationHandler) handleCreateReview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FindingID string `json:"finding_id"`
		Reviewer  string `json:"reviewer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}

	id := h.engine.CreateReview(body.FindingID, body.Reviewer)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func RegisterCollaborationHandlers(mux *http.ServeMux, engine *CollaborationEngine) {
	handler := NewCollaborationHandler(engine)
	mux.HandleFunc("/api/collaboration", handler.ServeHTTP)
	mux.HandleFunc("/api/collaboration/", handler.ServeHTTP)
}
