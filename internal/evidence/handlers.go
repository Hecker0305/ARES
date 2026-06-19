package evidence

import (
	"encoding/json"
	"net/http"
	"strings"
)

type EvidenceHandler struct {
	signer *EvidenceSigner
}

func NewEvidenceHandler(signer *EvidenceSigner) *EvidenceHandler {
	return &EvidenceHandler{signer: signer}
}

func (h *EvidenceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/evidence/")

	switch {
	case r.Method == http.MethodPost && (path == "sign" || path == ""):
		h.handleSign(w, r)
	case r.Method == http.MethodPost && path == "verify":
		h.handleVerify(w, r)
	case r.Method == http.MethodGet && path == "chain":
		h.handleChain(w, r)
	case r.Method == http.MethodGet && path == "log":
		h.handleLog(w, r)
	case r.Method == http.MethodGet && path == "tamper":
		h.handleTamperCheck(w, r)
	case r.Method == http.MethodGet && path == "verify-chain":
		json.NewEncoder(w).Encode(map[string]bool{"valid": h.signer.VerifyChain()})
	case r.Method == http.MethodGet && path == "public-key":
		json.NewEncoder(w).Encode(map[string]string{
			"key_id":     h.signer.KeyID(),
			"public_key": string(h.signer.PublicKey()),
		})
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

type signRequest struct {
	FindingID string          `json:"finding_id"`
	Content   json.RawMessage `json:"content"`
	CreatedBy string          `json:"created_by"`
}

func (h *EvidenceHandler) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	record, err := h.signer.SignEvidence(req.FindingID, req.Content, req.CreatedBy)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(record)
}

func (h *EvidenceHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var record EvidenceRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	valid := h.signer.VerifyEvidence(record)
	json.NewEncoder(w).Encode(map[string]bool{"valid": valid})
}

func (h *EvidenceHandler) handleChain(w http.ResponseWriter, r *http.Request) {
	chain := h.signer.GetChain()
	if chain == nil {
		chain = []ChainOfCustodyEntry{}
	}
	json.NewEncoder(w).Encode(chain)
}

func (h *EvidenceHandler) handleLog(w http.ResponseWriter, r *http.Request) {
	log := h.signer.GetImmutableLog()
	if log == nil {
		log = []ImmutableLogEntry{}
	}
	json.NewEncoder(w).Encode(log)
}

func (h *EvidenceHandler) handleTamperCheck(w http.ResponseWriter, r *http.Request) {
	issues := h.signer.DetectTampering()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tampered": len(issues) > 0,
		"issues":   issues,
	})
}

func RegisterEvidenceHandlers(mux *http.ServeMux, signer *EvidenceSigner) {
	handler := NewEvidenceHandler(signer)
	mux.HandleFunc("/api/evidence", handler.ServeHTTP)
	mux.HandleFunc("/api/evidence/", handler.ServeHTTP)
}
