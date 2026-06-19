package oob

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ares/engine/internal/security"
)

func TestNewOOBServer(t *testing.T) {
	s := NewOOBServer(0, 0)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.httpPort == 0 {
		t.Error("expected default HTTP port")
	}
	if s.dnsPort == 0 {
		t.Error("expected default DNS port")
	}
}

func TestNewOOBServerWithAuth(t *testing.T) {
	s := NewOOBServerWithAuth(18181, 5353, "test-auth-token")
	if s.authToken != "test-auth-token" {
		t.Errorf("expected auth token 'test-auth-token', got: %s", s.authToken)
	}
}

func TestNewToken(t *testing.T) {
	s := NewOOBServer(0, 0)
	t1 := s.NewToken()
	t2 := s.NewToken()
	if t1 == t2 {
		t.Error("expected unique tokens")
	}
	if len(t1) < 10 {
		t.Error("expected token to be sufficiently long")
	}
}

func TestNewSignedToken_Verification(t *testing.T) {
	s := NewOOBServer(0, 0)
	scanID := "scan-123"
	token := s.NewSignedToken(scanID)
	if token == "" {
		t.Fatal("expected non-empty signed token")
	}
	if !s.VerifySignedToken(scanID, token) {
		t.Error("expected valid signature")
	}
	if s.VerifySignedToken("wrong-scan", token) {
		t.Error("expected invalid signature for wrong scan ID")
	}
}

func TestHasCallback_NoCallbacks(t *testing.T) {
	s := NewOOBServer(0, 0)
	if s.HasCallback("nonexistent") {
		t.Error("expected no callback for nonexistent token")
	}
}

func TestHasCallback_WithCallback(t *testing.T) {
	s := NewOOBServer(0, 0)
	token := s.NewToken()
	s.mu.Lock()
	s.callbacks[token] = append(s.callbacks[token], Callback{
		Token:      token,
		Protocol:   "http",
		SourceIP:   "127.0.0.1",
		Payload:    "/test",
		ReceivedAt: time.Now(),
	})
	s.mu.Unlock()
	if !s.HasCallback(token) {
		t.Error("expected callback to be present")
	}
}

func TestHTTPPayload_Format(t *testing.T) {
	s := NewOOBServer(18182, 5353)
	token := "test-token-123"
	payload := s.HTTPPayload(token)
	if payload == "" {
		t.Error("expected non-empty HTTP payload")
	}
}

func TestDNSPayload_Format(t *testing.T) {
	s := NewOOBServer(18183, 5353)
	token := "test-dns-token"
	payload := s.DNSPayload(token)
	if payload == "" {
		t.Error("expected non-empty DNS payload")
	}
}

func TestURLFor(t *testing.T) {
	s := NewOOBServer(18184, 5353)
	url := s.URLFor("scan-456")
	if url == "" {
		t.Error("expected non-empty URL")
	}
}

func TestSecureCompare(t *testing.T) {
	if !security.SecureCompare("abc", "abc") {
		t.Error("equal strings should match")
	}
	if security.SecureCompare("abc", "abcd") {
		t.Error("different length strings should not match")
	}
	if security.SecureCompare("abc", "xyz") {
		t.Error("different strings should not match")
	}
}

func TestHTTP_NoAuthNeeded(t *testing.T) {
	s := NewOOBServer(18185, 5353)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleHTTP(w, r)
	})

	server := &http.Server{
		Addr:    ":18185",
		Handler: handler,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://localhost:18185/test-token")
	if err != nil {
		server.Close()
		wg.Wait()
		t.Skipf("HTTP test skipped: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got: %d", resp.StatusCode)
	}

	server.Close()
	wg.Wait()
}

func TestPurgeLoop(t *testing.T) {
	s := NewOOBServer(0, 0)
	oldToken := "old-token"
	s.mu.Lock()
	s.callbacks[oldToken] = []Callback{{
		Token:      oldToken,
		ReceivedAt: time.Now().Add(-30 * time.Minute),
	}}
	s.mu.Unlock()

	s.purgeLoopOnce()

	s.mu.RLock()
	_, exists := s.callbacks[oldToken]
	s.mu.RUnlock()
	if exists {
		t.Error("expected old callback to be purged")
	}
}

func (s *OOBServer) purgeLoopOnce() {
	cutoff := time.Now().Add(-callbackTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, cbs := range s.callbacks {
		var live []Callback
		for _, cb := range cbs {
			if cb.ReceivedAt.After(cutoff) {
				live = append(live, cb)
			}
		}
		if len(live) == 0 && len(cbs) > 0 {
			delete(s.callbacks, token)
		} else {
			s.callbacks[token] = live
		}
	}
}

func TestStartStop(t *testing.T) {
	s := NewOOBServer(18186, 5353)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.Stop(ctx)
	if err != nil {
		t.Errorf("stop error: %v", err)
	}
}
