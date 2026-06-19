package memory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewJSONMemoryStore(t *testing.T) {
	path := filepath.Join(os.TempDir(), "ares_test_memory.json")
	defer os.Remove(path)
	s := NewJSONMemoryStore(path)
	if s == nil {
		t.Fatal("NewJSONMemoryStore returned nil")
	}
}

func TestRecordAndGetProbability(t *testing.T) {
	path := filepath.Join(os.TempDir(), "ares_test_prob.json")
	defer os.Remove(path)
	s := NewJSONMemoryStore(path)

	p := s.GetProbability("sqli", "xss")
	if p != 0.3 {
		t.Errorf("initial probability = %f, want 0.3", p)
	}

	s.RecordOutcome("sqli", "xss", "<script>alert(1)</script>", true)
	p = s.GetProbability("sqli", "xss")
	if p <= 0.3 {
		t.Errorf("after success probability = %f, want > 0.3", p)
	}
}

func TestGetTopPayloads(t *testing.T) {
	path := filepath.Join(os.TempDir(), "ares_test_payloads.json")
	defer os.Remove(path)
	s := NewJSONMemoryStore(path)

	payloads := s.GetTopPayloads("sqli", "xss", 5)
	if payloads != nil {
		t.Errorf("expected nil, got %v", payloads)
	}

	s.RecordOutcome("sqli", "xss", "<script>alert(1)</script>", true)
	payloads = s.GetTopPayloads("sqli", "xss", 5)
	if len(payloads) != 1 {
		t.Errorf("expected 1 payload, got %d", len(payloads))
	}
}

func TestPersistenceAcrossInstances(t *testing.T) {
	path := filepath.Join(os.TempDir(), "ares_test_persist.json")
	defer os.Remove(path)

	s1 := NewJSONMemoryStore(path)
	s1.RecordOutcome("rce", "php", "system(id)", true)

	s2 := NewJSONMemoryStore(path)
	p := s2.GetProbability("rce", "php")
	if p <= 0.3 {
		t.Errorf("persisted probability = %f, want > 0.3", p)
	}
}
