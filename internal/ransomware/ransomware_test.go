package ransomware

import (
	"testing"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestListFamilies(t *testing.T) {
	e := New()
	if len(e.ListFamilies()) == 0 {
		t.Fatal("expected at least one ransomware family")
	}
}

func TestGetFamily(t *testing.T) {
	e := New()
	f := e.GetFamily("WannaCry")
	if f == nil {
		t.Fatal("expected WannaCry family")
	}
	if f.Name != "WannaCry" {
		t.Fatalf("expected name WannaCry, got %s", f.Name)
	}
}

func TestGetFamilyNotFound(t *testing.T) {
	e := New()
	if e.GetFamily("Nonexistent") != nil {
		t.Fatal("expected nil for nonexistent family")
	}
}

func TestAnalyzeSample(t *testing.T) {
	e := New()
	r := e.AnalyzeSample("abc123", []string{".wcry", ".wncry"}, "your files have been encrypted 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", []string{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"})
	if r == nil {
		t.Fatal("expected report")
	}
	if r.Family == "" {
		t.Fatal("expected non-empty family")
	}
}

func TestAnalyzeSampleLowConfidence(t *testing.T) {
	e := New()
	r := e.AnalyzeSample("xyz789", nil, "hello world", nil)
	if r == nil || r.Family == "" {
		t.Fatal("expected report with at least unknown family")
	}
}

func TestListReportsEmpty(t *testing.T) {
	e := New()
	if len(e.ListReports()) != 0 {
		t.Fatal("expected empty reports on fresh engine")
	}
}

func TestGetReportNotFound(t *testing.T) {
	e := New()
	if e.GetReport("nonexistent") != nil {
		t.Fatal("expected nil for nonexistent report")
	}
}

func TestSearchDecryptor(t *testing.T) {
	e := New()
	d := e.SearchDecryptor("WannaCry")
	if d == nil {
		t.Fatal("expected decryptor result for WannaCry")
	}
}

func TestSearchDecryptorNotFound(t *testing.T) {
	e := New()
	d := e.SearchDecryptor("Nonexistent")
	if d == nil {
		t.Fatal("expected non-nil result even for nonexistent")
	}
	if d.Status != "unknown" {
		t.Fatalf("expected status unknown, got %s", d.Status)
	}
}
