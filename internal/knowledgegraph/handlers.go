package knowledgegraph

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type GraphHandler struct {
	graph *KnowledgeGraph
}

func NewGraphHandler(graph *KnowledgeGraph) *GraphHandler {
	return &GraphHandler{graph: graph}
}

func (h *GraphHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/knowledge-graph/")

	switch {
	case r.Method == http.MethodGet && (path == "" || path == "stats"):
		json.NewEncoder(w).Encode(h.graph.GetStats())
	case r.Method == http.MethodGet && path == "entities":
		json.NewEncoder(w).Encode(h.graph.AllEntities())
	case r.Method == http.MethodPost && path == "entities":
		h.handleAddEntity(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "entities/"):
		id := strings.TrimPrefix(path, "entities/")
		entity := h.graph.GetEntity(id)
		if entity == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(entity)
	case r.Method == http.MethodGet && path == "relationships":
		id := r.URL.Query().Get("entity_id")
		if id == "" {
			http.Error(w, `{"error":"entity_id required"}`, http.StatusBadRequest)
			return
		}
		rels := h.graph.GetRelationships(id)
		if rels == nil {
			rels = []*Relationship{}
		}
		json.NewEncoder(w).Encode(rels)
	case r.Method == http.MethodPost && path == "relationships":
		h.handleAddRelationship(w, r)
	case r.Method == http.MethodGet && path == "paths":
		h.handleFindPaths(w, r)
	case r.Method == http.MethodGet && path == "exposure":
		assetID := r.URL.Query().Get("asset_id")
		if assetID == "" {
			http.Error(w, `{"error":"asset_id required"}`, http.StatusBadRequest)
			return
		}
		paths := h.graph.GetExposurePath(assetID)
		if paths == nil {
			paths = []AttackPath{}
		}
		json.NewEncoder(w).Encode(paths)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "type/"):
		entityType := EntityType(strings.TrimPrefix(path, "type/"))
		entities := h.graph.GetEntitiesByType(entityType)
		if entities == nil {
			entities = []*Entity{}
		}
		json.NewEncoder(w).Encode(entities)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *GraphHandler) handleAddEntity(w http.ResponseWriter, r *http.Request) {
	var entity Entity
	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		http.Error(w, `{"error":"invalid entity"}`, http.StatusBadRequest)
		return
	}

	id := h.graph.AddEntity(entity)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *GraphHandler) handleAddRelationship(w http.ResponseWriter, r *http.Request) {
	var rel Relationship
	if err := json.NewDecoder(r.Body).Decode(&rel); err != nil {
		http.Error(w, `{"error":"invalid relationship"}`, http.StatusBadRequest)
		return
	}

	id := h.graph.AddRelationship(rel)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *GraphHandler) handleFindPaths(w http.ResponseWriter, r *http.Request) {
	startID := r.URL.Query().Get("start")
	endID := r.URL.Query().Get("end")
	maxDepthStr := r.URL.Query().Get("max_depth")

	maxDepth := 5
	if maxDepthStr != "" {
		if d, err := strconv.Atoi(maxDepthStr); err == nil && d > 0 {
			maxDepth = d
		}
	}

	if startID == "" || endID == "" {
		http.Error(w, `{"error":"start and end required"}`, http.StatusBadRequest)
		return
	}

	paths := h.graph.FindPaths(startID, endID, maxDepth)
	if paths == nil {
		paths = []AttackPath{}
	}
	json.NewEncoder(w).Encode(paths)
}

func RegisterGraphHandlers(mux *http.ServeMux, graph *KnowledgeGraph) {
	handler := NewGraphHandler(graph)
	mux.HandleFunc("/api/knowledge-graph", handler.ServeHTTP)
	mux.HandleFunc("/api/knowledge-graph/", handler.ServeHTTP)
}
