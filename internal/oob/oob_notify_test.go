package oob

import (
	"context"
	"testing"
	"time"
)

func TestWaitForCallback_ChannelNotification(t *testing.T) {
	srv := NewOOBServer(0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token := srv.NewToken()

	// Simulate callback arriving after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		srv.mu.Lock()
		srv.callbacks[token] = append(srv.callbacks[token], Callback{
			Token:    token,
			Protocol: "http",
			Payload:  "test",
		})
		srv.mu.Unlock()
		srv.notifySubscribers(token)
	}()

	found, cbs := srv.WaitForCallback(ctx, token, 2*time.Second)
	if !found {
		t.Fatal("expected callback to be found")
	}
	if len(cbs) != 1 {
		t.Fatalf("expected 1 callback, got %d", len(cbs))
	}
}

func TestWaitForCallback_Timeout(t *testing.T) {
	srv := NewOOBServer(0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token := srv.NewToken()

	found, cbs := srv.WaitForCallback(ctx, token, 50*time.Millisecond)
	if found {
		t.Fatal("expected timeout without callback")
	}
	if cbs != nil {
		t.Fatal("expected nil callbacks on timeout")
	}
}

func TestWaitForCallback_ContextCancelled(t *testing.T) {
	srv := NewOOBServer(0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cancel()

	token := srv.NewToken()
	found, _ := srv.WaitForCallback(ctx, token, 2*time.Second)
	if found {
		t.Fatal("expected false when context is cancelled")
	}
}

func TestHasCallbackAfterAdd(t *testing.T) {
	srv := NewOOBServer(0, 0)
	token := srv.NewToken()
	srv.mu.Lock()
	srv.callbacks[token] = append(srv.callbacks[token], Callback{Token: token})
	srv.mu.Unlock()
	if !srv.HasCallback(token) {
		t.Fatal("expected true after adding callback")
	}
}
