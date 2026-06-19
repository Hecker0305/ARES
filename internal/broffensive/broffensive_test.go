package broffensive

import (
	"context"
	"testing"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestCaptureSession(t *testing.T) {
	e := New()
	session, err := e.CaptureSession(context.Background(), "http://localhost:9999")
	if err != nil {
		t.Logf("CaptureSession error (expected without server): %v", err)
	}
	_ = session
}

func TestAuthenticate(t *testing.T) {
	e := New()
	auth, err := e.Authenticate(context.Background(), "http://localhost:9999/login", "admin", "password")
	if err != nil {
		t.Logf("Auth error (expected without server): %v", err)
	}
	_ = auth
}

func TestReplaySession(t *testing.T) {
	e := New()
	session, err := e.ReplaySession(context.Background(), "test-session")
	if err != nil {
		t.Logf("Replay error (expected without server): %v", err)
	}
	_ = session
}

func TestDetectStoredXSS(t *testing.T) {
	e := New()
	results := e.DetectStoredXSS(context.Background(), "http://localhost:9999")
	if results != nil {
		t.Logf("found %d XSS issues", len(results))
	}
}

func TestAnalyzeCSRF(t *testing.T) {
	e := New()
	chains := e.AnalyzeCSRF(context.Background(), "http://localhost:9999")
	if chains != nil {
		t.Logf("found %d CSRF chains", len(chains))
	}
}

func TestLearnUIFlow(t *testing.T) {
	e := New()
	flow := e.LearnUIFlow(context.Background(), "http://localhost:9999")
	_ = flow
}

func TestAutoFillForms(t *testing.T) {
	e := New()
	events, err := e.AutoFillForms(context.Background(), "http://localhost:9999")
	if err != nil {
		t.Logf("AutoFill error: %v", err)
	}
	_ = events
}

func TestEnumerateEndpoints(t *testing.T) {
	e := New()
	endpoints := e.EnumerateEndpoints(context.Background(), "http://localhost:9999")
	if endpoints != nil {
		t.Logf("found %d endpoints", len(endpoints))
	}
}

func TestSessions(t *testing.T) {
	e := New()
	sessions := e.Sessions()
	_ = sessions
}

func TestAuth(t *testing.T) {
	e := New()
	auth := e.Auth()
	_ = auth
}
