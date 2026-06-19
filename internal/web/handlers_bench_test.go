package web_test

import (
	"testing"

	"github.com/ares/engine/internal/web"
)

func BenchmarkLogin(b *testing.B) {
	h := web.NewLoginHandler("bench-secret-key")
	if h == nil {
		b.Fatal("login handler is nil")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Login("nonexistent", "password123!")
	}
}

func BenchmarkValidateToken(b *testing.B) {
	h := web.NewLoginHandler("bench-secret-key")
	if h == nil {
		b.Fatal("login handler is nil")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.ValidateToken("bench-invalid-token-12345")
	}
}
