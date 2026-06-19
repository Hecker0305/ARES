package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	hash, err := hashPassword("testpassword123")
	if err != nil {
		t.Fatalf("hashPassword failed: %v", err)
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash should start with $argon2id$, got: %s", hash)
	}
	if !verifyPassword("testpassword123", hash) {
		t.Fatal("verifyPassword should return true for correct password")
	}
	if verifyPassword("wrongpassword", hash) {
		t.Fatal("verifyPassword should return false for wrong password")
	}
}

func TestTokenGeneration(t *testing.T) {
	secret := "test-secret-key-for-testing"
	token1, err := generateSessionToken("admin", secret)
	if err != nil {
		t.Fatalf("generateSessionToken failed: %v", err)
	}
	token2, err := generateSessionToken("admin", secret)
	if err != nil {
		t.Fatalf("generateSessionToken failed: %v", err)
	}
	if token1 == "" {
		t.Fatal("token should not be empty")
	}
	if token1 == token2 {
		t.Fatal("tokens should be unique across calls")
	}
}

func TestLoginHandler_LoginLogout(t *testing.T) {
	h := NewLoginHandler("test-secret")
	session, err := h.Login("nonexistent", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if session != nil {
		t.Fatal("expected nil session for nonexistent user")
	}
}

func TestLoginHandler_ValidateToken(t *testing.T) {
	h := NewLoginHandler("test-secret")
	session, err := h.ValidateToken("invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if session != nil {
		t.Fatal("expected nil session for invalid token")
	}
}

func TestLoginHandler_CSRF(t *testing.T) {
	h := NewLoginHandler("test-secret")
	req := httptest.NewRequest(http.MethodGet, "/api/auth/csrf", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["csrf_token"] == "" {
		t.Fatal("expected non-empty csrf_token")
	}
}

func TestLoginHandler_RateLimit(t *testing.T) {
	h := NewLoginHandler("test-secret")
	// Send more than rate limit requests quickly
	ip := "192.168.1.1:12345"
	// Fill rate bucket to exceed rateLimit (5)
	h.SetRateLimitForTest(ip, 5)
	if !h.IsRateLimited(ip) {
		t.Fatal("expected rate limit to trigger when count exceeds limit")
	}
	// Fresh IP should not be rate limited
	otherIP := "10.0.0.1:12345"
	if h.IsRateLimited(otherIP) {
		t.Fatal("expected fresh IP to not be rate limited")
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		cookies  map[string]string
		expected string
	}{
		{
			name:     "bearer token",
			headers:  map[string]string{"Authorization": "Bearer test-token-123"},
			expected: "test-token-123",
		},
		{
			name:     "x-session-token",
			headers:  map[string]string{"X-Session-Token": "session-token"},
			expected: "session-token",
		},
		{
			name:     "no token",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := extractToken(req)
			if got != tt.expected {
				t.Errorf("extractToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}
