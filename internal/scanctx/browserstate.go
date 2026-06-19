package scanctx

import (
	"github.com/ares/engine/internal/uuid"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Session struct {
	ID           string
	Cookies      map[string]string
	Headers      map[string]string
	LocalStorage map[string]string
	CreatedAt    time.Time
}

type BrowserState struct {
	mu         sync.RWMutex
	sessions   map[string]*Session
	currentURL string
}

func NewBrowserState() *BrowserState {
	return &BrowserState{
		sessions: make(map[string]*Session),
	}
}

func (bs *BrowserState) NewSession() string {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	session := &Session{
		ID:           uuid.New(),
		Cookies:      make(map[string]string),
		Headers:      make(map[string]string),
		LocalStorage: make(map[string]string),
		CreatedAt:    time.Now(),
	}
	bs.sessions[session.ID] = session
	return session.ID
}

func (bs *BrowserState) GetSession(id string) *Session {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	s := bs.sessions[id]
	if s == nil {
		return nil
	}
	cp := *s
	cp.Cookies = make(map[string]string, len(s.Cookies))
	for k, v := range s.Cookies {
		cp.Cookies[k] = v
	}
	cp.Headers = make(map[string]string, len(s.Headers))
	for k, v := range s.Headers {
		cp.Headers[k] = v
	}
	cp.LocalStorage = make(map[string]string, len(s.LocalStorage))
	for k, v := range s.LocalStorage {
		cp.LocalStorage[k] = v
	}
	return &cp
}

func sanitizeValue(v string) string {
	// Escape HTML special characters to prevent XSS when rendered
	v = strings.ReplaceAll(v, "&", "&amp;")
	v = strings.ReplaceAll(v, "<", "&lt;")
	v = strings.ReplaceAll(v, ">", "&gt;")
	v = strings.ReplaceAll(v, "\"", "&quot;")
	v = strings.ReplaceAll(v, "'", "&#x27;")
	return v
}

func (bs *BrowserState) SetCookie(sessionID, name, value string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if s, ok := bs.sessions[sessionID]; ok {
		s.Cookies[name] = sanitizeValue(value)
	}
}

func (bs *BrowserState) SetHeader(sessionID, name, value string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if s, ok := bs.sessions[sessionID]; ok {
		s.Headers[name] = sanitizeValue(value)
	}
}

func (bs *BrowserState) SetLocalStorage(sessionID, key, value string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if s, ok := bs.sessions[sessionID]; ok {
		s.LocalStorage[key] = sanitizeValue(value)
	}
}

func (bs *BrowserState) GetLocalStorage(sessionID, key string) string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	if s, ok := bs.sessions[sessionID]; ok {
		return s.LocalStorage[key]
	}
	return ""
}

func (bs *BrowserState) Navigate(sessionID, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: %s", parsed.Scheme)
	}
	// Reject javascript: URLs and other dangerous schemes
	if strings.HasPrefix(strings.ToLower(parsed.Scheme), "javascript") {
		return fmt.Errorf("javascript URLs not allowed")
	}
	if strings.HasPrefix(strings.ToLower(parsed.Scheme), "data") {
		return fmt.Errorf("data URLs not allowed")
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.currentURL = rawURL
	return nil
}

func (bs *BrowserState) GetCurrentURL() string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.currentURL
}
