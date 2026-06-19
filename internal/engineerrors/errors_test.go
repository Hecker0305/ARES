package engineerrors

import (
	"errors"
	"net/http"
	"testing"
)

func TestEngineError(t *testing.T) {
	t.Run("basic error", func(t *testing.T) {
		err := New(CodeNotFound, "scan not found")
		if err.Error() != "[NOT_FOUND] scan not found" {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if err.HTTPStatus() != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", err.HTTPStatus())
		}
	})

	t.Run("wrap error", func(t *testing.T) {
		inner := errors.New("inner error")
		err := Wrap(CodeInternal, "wrapped", inner)
		if !errors.Is(err, inner) {
			t.Fatal("Unwrap should return inner error")
		}
	})

	t.Run("not found helper", func(t *testing.T) {
		err := NotFound("sample")
		if err.Code != CodeNotFound {
			t.Fatal("expected NOT_FOUND")
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		err := InvalidInput("bad data")
		if err.HTTPStatus() != http.StatusBadRequest {
			t.Fatal("expected 400")
		}
	})

	t.Run("resource exceeded", func(t *testing.T) {
		err := ResourceExceeded("packets", 10000)
		if err.Code != CodeResourceExceeded {
			t.Fatal("expected RESOURCE_EXCEEDED")
		}
	})

	t.Run("http status mapping", func(t *testing.T) {
		tests := []struct {
			code Code
			http int
		}{
			{CodeNotFound, http.StatusNotFound},
			{CodeInvalidInput, http.StatusBadRequest},
			{CodeAlreadyExists, http.StatusConflict},
			{CodeNotSupported, http.StatusNotImplemented},
			{CodeRateLimited, http.StatusTooManyRequests},
			{CodeUnauthorized, http.StatusUnauthorized},
			{CodeResourceExceeded, http.StatusTooManyRequests},
			{CodeTimeout, http.StatusGatewayTimeout},
			{CodeUnavailable, http.StatusServiceUnavailable},
			{CodeInternal, http.StatusInternalServerError},
		}
		for _, tt := range tests {
			err := New(tt.code, "test")
			if err.HTTPStatus() != tt.http {
				t.Errorf("code %s: expected HTTP %d, got %d", tt.code, tt.http, err.HTTPStatus())
			}
		}
	})
}

func TestGovernor(t *testing.T) {
	t.Run("allows within limits", func(t *testing.T) {
		g := &Governor{maxPackets: 100, maxBytes: 1024 * 1024}
		if err := g.Check(10, 1024); err != nil {
			t.Fatal("expected no error")
		}
	})

	t.Run("blocks packet overflow", func(t *testing.T) {
		g := &Governor{maxPackets: 10, maxBytes: 1024 * 1024}
		if err := g.Check(11, 1024); err == nil {
			t.Fatal("expected error for packet overflow")
		}
	})

	t.Run("blocks byte overflow", func(t *testing.T) {
		g := &Governor{maxPackets: 1000, maxBytes: 1024}
		if err := g.Check(1, 2048); err == nil {
			t.Fatal("expected error for byte overflow")
		}
	})

	t.Run("accumulates usage", func(t *testing.T) {
		g := &Governor{maxPackets: 10, maxBytes: 1024 * 1024}
		g.Check(3, 100)
		g.Check(3, 100)
		err := g.Check(5, 100)
		if err == nil {
			t.Fatal("expected error after accumulation")
		}
	})

	t.Run("reset clears usage", func(t *testing.T) {
		g := &Governor{maxPackets: 10, maxBytes: 1024 * 1024}
		g.Check(9, 100)
		g.Reset()
		if err := g.Check(5, 100); err != nil {
			t.Fatal("expected no error after reset")
		}
	})

	t.Run("usage string format", func(t *testing.T) {
		g := &Governor{maxPackets: 100, maxBytes: 1024 * 1024}
		g.Check(50, 2048)
		u := g.Usage()
		if u == "" {
			t.Fatal("expected non-empty usage string")
		}
	})
}
