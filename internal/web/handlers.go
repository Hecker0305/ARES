package web

import (
	"net/http"
)

func (s *Server) handleScanHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scans := s.scanStore.ListCompleted()
	if scans == nil {
		scans = []*ScanSession{}
	}
	writeJSON(w, scans)
}
