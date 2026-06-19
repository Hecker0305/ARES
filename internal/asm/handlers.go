package asm

import (
	"encoding/json"
	"net/http"
	"strings"
)

type ASMHandler struct {
	engine *ASMEngine
}

func NewASMHandler(engine *ASMEngine) *ASMHandler {
	return &ASMHandler{engine: engine}
}

func (h *ASMHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/asm/")

	switch {
	case r.Method == http.MethodGet && (path == "" || path == "stats"):
		json.NewEncoder(w).Encode(h.engine.GetStats())
	case r.Method == http.MethodGet && path == "assets":
		assets := h.engine.ListAssets()
		if assets == nil {
			assets = []*ASMAsset{}
		}
		json.NewEncoder(w).Encode(assets)
	case r.Method == http.MethodPost && path == "assets":
		h.handleAddAsset(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "assets/"):
		id := strings.TrimPrefix(path, "assets/")
		asset := h.engine.GetAsset(id)
		if asset == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(asset)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "type/"):
		assetType := AssetType(strings.TrimPrefix(path, "type/"))
		assets := h.engine.GetAssetsByType(assetType)
		if assets == nil {
			assets = []*ASMAsset{}
		}
		json.NewEncoder(w).Encode(assets)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *ASMHandler) handleAddAsset(w http.ResponseWriter, r *http.Request) {
	var asset ASMAsset
	if err := json.NewDecoder(r.Body).Decode(&asset); err != nil {
		http.Error(w, `{"error":"invalid"}`, http.StatusBadRequest)
		return
	}

	id := h.engine.AddAsset(asset)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func RegisterASMHandlers(mux *http.ServeMux, engine *ASMEngine) {
	handler := NewASMHandler(engine)
	mux.HandleFunc("/api/asm", handler.ServeHTTP)
	mux.HandleFunc("/api/asm/", handler.ServeHTTP)
}
