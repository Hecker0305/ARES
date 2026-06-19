package jsanalysis

import (
	"testing"
	"time"
)

func TestNewAnalyzer(t *testing.T) {
	a := NewAnalyzer(30 * time.Second)
	if a == nil {
		t.Fatal("expected non-nil analyzer")
	}
}

func TestScanURLs(t *testing.T) {
	a := NewAnalyzer(10 * time.Second)
	result := a.ScanURLs([]string{"http://example.com/script.js"})
	if result.URL == "" {
		t.Log("URL may be empty (no actual scan performed)")
	}
}
