package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHub(t *testing.T) {
	h := NewHub()
	if h == nil {
		t.Fatal("expected non-nil hub")
	}
}

func TestNewHubWithAuth(t *testing.T) {
	authFn := func(r *http.Request) bool { return true }
	h := NewHubWithAuth(authFn, []byte("secret"))
	if h == nil {
		t.Fatal("expected non-nil hub")
	}
}

func TestRun(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.Run(ctx)
}

func TestClientsCount(t *testing.T) {
	h := NewHub()
	count := h.ClientsCount()
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestStats(t *testing.T) {
	h := NewHub()
	stats := h.Stats()
	if stats == nil {
		t.Error("expected non-nil stats")
	}
}

func TestServeHTTP(t *testing.T) {
	h := NewHub()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Logf("HTTP error (expected for websocket endpoint): %v", err)
		return
	}
	defer resp.Body.Close()
}

func TestBroadcast(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	err := h.Broadcast("test_event", "data")
	if err != nil {
		t.Logf("broadcast error (expected with no clients): %v", err)
	}
}

func TestBroadcastToRole(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	err := h.BroadcastToRole("test_event", "data", "admin")
	if err != nil {
		t.Logf("broadcast to role error: %v", err)
	}
}
