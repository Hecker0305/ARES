package webserver

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	s := New(0, "")
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.port != 0 {
		t.Errorf("port = %d, want 0", s.port)
	}
}

func TestPushEvent(t *testing.T) {
	s := New(9999, "")
	s.Push("scan-1", "FINDING_ADD", "SQL injection found")
	s.mu.RLock()
	if len(s.events) != 1 {
		t.Errorf("events count = %d, want 1", len(s.events))
	}
	s.mu.RUnlock()
}

func TestPushMultipleEvents(t *testing.T) {
	s := New(9998, "")
	for i := 0; i < 5; i++ {
		s.Push("scan-1", "TOOL_CALL", "nmap")
	}
	s.mu.RLock()
	if len(s.events) != 5 {
		t.Errorf("events count = %d, want 5", len(s.events))
	}
	s.mu.RUnlock()
}

func TestEventLimit(t *testing.T) {
	s := New(9997, "")
	for i := 0; i < 1500; i++ {
		s.Push("scan-1", "TEST", "event")
	}
	s.mu.RLock()
	if len(s.events) > 1100 {
		t.Errorf("events should be capped at ~1000, got %d", len(s.events))
	}
	s.mu.RUnlock()
}

func TestStartStop(t *testing.T) {
	s := New(9996, "")
	s.Start()
	s.Stop(1 * time.Second)
}

func TestServerConfigAuthToken(t *testing.T) {
	s := New(9995, "secret-token")
	expectedHash := sha256.Sum256([]byte("secret-token"))
	expectedHashStr := hex.EncodeToString(expectedHash[:])
	if s.authTokenHash != expectedHashStr {
		t.Errorf("authTokenHash = %q, want %q", s.authTokenHash, expectedHashStr)
	}
}
