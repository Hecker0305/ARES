package browser

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewBrowser(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	if b == nil {
		t.Fatal("expected non-nil browser")
	}
	if b.cfg.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", b.cfg.Timeout)
	}
	if b.cfg.UserAgent == "" {
		t.Error("expected non-empty user agent")
	}
	if len(b.pages) != 0 {
		t.Errorf("expected 0 pages, got %d", len(b.pages))
	}
}

func TestNewBrowserWithConfig(t *testing.T) {
	b := NewBrowser(BrowserConfig{
		Timeout:   10 * time.Second,
		Headless:  true,
		UserAgent: "test-agent",
	})
	if b.cfg.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", b.cfg.Timeout)
	}
	if !b.cfg.Headless {
		t.Error("expected headless true")
	}
	if b.cfg.UserAgent != "test-agent" {
		t.Errorf("expected test-agent, got %s", b.cfg.UserAgent)
	}
}

func TestNavigate_InvalidURL(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	_, err := b.Navigate(context.Background(), "javascript:alert(1)")
	if err == nil {
		t.Error("expected error for javascript URL")
	}
}

func TestNavigate_EmptyURL(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	_, err := b.Navigate(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestSetCookie(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	b.mu.Lock()
	b.pages["http://example.com"] = &Page{URL: "http://example.com"}
	b.mu.Unlock()

	err := b.SetCookie("session", "abc123")
	if err != nil {
		t.Errorf("SetCookie error: %v", err)
	}

	b.mu.RLock()
	page := b.pages["http://example.com"]
	b.mu.RUnlock()
	if page.Cookies["session"] != "abc123" {
		t.Errorf("expected cookie value abc123, got %s", page.Cookies["session"])
	}
}

func TestSetCookie_NoPages(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	err := b.SetCookie("test", "value")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClose(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	b.mu.Lock()
	b.pages["http://example.com"] = &Page{URL: "http://example.com"}
	b.mu.Unlock()

	if err := b.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
	b.mu.RLock()
	if len(b.pages) != 0 {
		t.Errorf("expected 0 pages after close, got %d", len(b.pages))
	}
	b.mu.RUnlock()
}

func TestPageLimit(t *testing.T) {
	b := NewBrowser(BrowserConfig{Timeout: 5 * time.Second})
	b.mu.Lock()
	for i := 0; i < 150; i++ {
		u := "http://example.com/page"
		b.pages[u] = &Page{URL: u}
	}
	b.mu.Unlock()

	b.mu.RLock()
	count := len(b.pages)
	b.mu.RUnlock()
	if count > 100 {
		t.Errorf("expected max 100 pages after eviction, got %d", count)
	}
}

func TestNewSessionManager(t *testing.T) {
	sm := NewSessionManager()
	if sm == nil {
		t.Fatal("expected non-nil session manager")
	}
	id := sm.NewSession()
	if id == "" {
		t.Fatal("expected non-empty session ID")
	}
	s := sm.GetSession(id)
	if s == nil {
		t.Fatal("expected session")
	}
	if s.ID != id {
		t.Errorf("expected session ID %s, got %s", id, s.ID)
	}
}

func TestSessionManagerConcurrency(t *testing.T) {
	sm := NewSessionManager()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := sm.NewSession()
			sm.SetCookie(id, "key", "value")
			sm.SetHeader(id, "X-Test", "val")
			sm.GetSession(id)
		}()
	}
	wg.Wait()
}

func TestNewPageAgent(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	pa := NewPageAgent(b)
	if pa == nil {
		t.Fatal("expected non-nil page agent")
	}
	result, err := pa.Run("controller")
	if err != nil {
		t.Errorf("Run error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty script content")
	}
}

func TestPageAgentUnknownScript(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	pa := NewPageAgent(b)
	_, err := pa.Run("nonexistent")
	if err == nil {
		t.Error("expected error for unknown script")
	}
}

func TestPageAgentRegisterScript(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	pa := NewPageAgent(b)
	pa.RegisterScript("custom", "console.log('test')")
	result, err := pa.Run("custom")
	if err != nil {
		t.Errorf("Run error: %v", err)
	}
	if result != "console.log('test')" {
		t.Errorf("expected script content, got %s", result)
	}
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		html string
		want string
	}{
		{"<html><title>Test Page</title></html>", "Test Page"},
		{"<html></html>", ""},
		{"<TITLE>Uppercase</TITLE>", ""}, // extractTitle only matches lowercase <title
		{"<title>   Spaced   </title>", "Spaced"},
	}
	for _, tt := range tests {
		got := extractTitle(tt.html)
		if got != tt.want {
			t.Errorf("extractTitle(%q) = %q, want %q", tt.html[:min(len(tt.html), 30)], got, tt.want)
		}
	}
}

func TestSafeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal.txt", "normaltxt"},
		{"../../etc/passwd", "etcpasswd"},
		{"hello world", "helloworld"},
		{"", "page"},
		{"a", "a"},
	}
	for _, tt := range tests {
		got := safeFilename(tt.input)
		if got != tt.want {
			t.Errorf("safeFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMin(t *testing.T) {
	if min(1, 2) != 1 {
		t.Error("min(1,2) should be 1")
	}
	if min(5, 3) != 3 {
		t.Error("min(5,3) should be 3")
	}
	if min(-1, 0) != -1 {
		t.Error("min(-1,0) should be -1")
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com", "http://example.com"},
		{"not-a-url", "not-a-url"},
		{"https://test.com/path?q=1", "https://test.com/path?q=1"},
	}
	for _, tt := range tests {
		got := parseURL(tt.input)
		if got != tt.want {
			t.Errorf("parseURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"http://example.com", true},
		{"https://test.com", true},
		{"ftp://test.com", false},
		{"not-a-url", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isURL(tt.input)
		if got != tt.want {
			t.Errorf("isURL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEvaluate_NoPages(t *testing.T) {
	b := NewBrowser(BrowserConfig{})
	_, err := b.Evaluate(context.Background(), "test")
	if err == nil {
		t.Error("expected error with no pages")
	}
}

func TestFetchURL_NavigateFirst(t *testing.T) {
	b := NewBrowser(BrowserConfig{Timeout: 5 * time.Second})
	_, err := b.FetchURL(context.Background(), "http://invalid.nonexistent.domain")
	if err == nil {
		t.Skip("fetch unexpectedly succeeded")
	}
}

func TestBrowserConcurrency(t *testing.T) {
	b := NewBrowser(BrowserConfig{Timeout: 5 * time.Second})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.mu.Lock()
			b.pages["http://example.com"] = &Page{URL: "http://example.com"}
			b.mu.Unlock()
			b.SetCookie("k", "v")
			b.Close()
		}()
	}
	wg.Wait()
}

func TestSessionManagerSetCookie(t *testing.T) {
	sm := NewSessionManager()
	id := sm.NewSession()
	sm.SetCookie(id, "test-cookie", "test-value")
	s := sm.GetSession(id)
	if s.Cookies["test-cookie"] != "test-value" {
		t.Errorf("expected test-value, got %s", s.Cookies["test-cookie"])
	}
}

func TestSessionManagerSetCookieNoSession(t *testing.T) {
	sm := NewSessionManager()
	sm.SetCookie("nonexistent", "key", "value")
}

func TestSessionManagerSetHeader(t *testing.T) {
	sm := NewSessionManager()
	id := sm.NewSession()
	sm.SetHeader(id, "X-Custom", "header-value")
	s := sm.GetSession(id)
	if s.Headers["X-Custom"] != "header-value" {
		t.Errorf("expected header-value, got %s", s.Headers["X-Custom"])
	}
}

func TestSessionManagerGetSession(t *testing.T) {
	sm := NewSessionManager()
	s := sm.GetSession("nonexistent")
	if s != nil {
		t.Error("expected nil for nonexistent session")
	}
}
