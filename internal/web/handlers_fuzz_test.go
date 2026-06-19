package web_test

import (
	"testing"

	"github.com/ares/engine/internal/web"
)

func FuzzLoginHandler(f *testing.F) {
	seeds := []struct {
		username string
		password string
		csrf     string
	}{
		{"admin", "password123!", "valid-csrf-token"},
		{"nonexistent", "guess", ""},
		{"'; DROP TABLE users; --", "' OR '1'='1", "<script>"},
		{"<script>alert(1)</script>", "$(cat /etc/passwd)", "csrf123"},
		{"", "", ""},
		{"../etc/passwd", "'; DROP; --", ""},
		{"user@example.com", "../../../etc/shadow", "csrf\x00inject"},
		{string([]byte{0xff, 0xfe, 0x00}), string([]byte{0x00, 0x01, 0x02}), ""},
	}
	for _, s := range seeds {
		f.Add(s.username, s.password, s.csrf)
	}

	f.Fuzz(func(t *testing.T, username, password, csrf string) {
		h := web.NewLoginHandler("fuzz-secret-key-for-testing")
		if h == nil {
			t.Skip("login handler creation failed")
		}
		_, _ = h.Login(username, password)
	})
}

func FuzzValidateToken(f *testing.F) {
	seeds := []string{
		"valid-token-123",
		"",
		"'; DROP TABLE sessions; --",
		"<script>alert(1)</script>",
		"$(cat /etc/passwd)",
		"../../../etc/shadow",
		"\x00\x01\x02\xff\xfe",
		"Bearer invalid",
		"../",
		`{"alg":"none"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		h := web.NewLoginHandler("fuzz-secret-key-for-testing")
		if h == nil {
			t.Skip("login handler creation failed")
		}
		_, _ = h.ValidateToken(token)
	})
}
