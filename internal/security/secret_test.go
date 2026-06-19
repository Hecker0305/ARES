package security

import (
	"encoding/json"
	"testing"
)

func TestSecretString_Redaction(t *testing.T) {
	s := NewSecret("my-api-key-12345")
	if s.String() != "***REDACTED***" {
		t.Errorf("expected redacted string, got: %s", s.String())
	}
}

func TestSecretString_GoString(t *testing.T) {
	s := NewSecret("secret-value")
	if s.GoString() != "***REDACTED***" {
		t.Error("GoString should be redacted")
	}
}

func TestSecretString_MarshalJSON(t *testing.T) {
	s := NewSecret("super-secret-key")
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if string(data) != `"***REDACTED***"` {
		t.Errorf("expected redacted JSON, got: %s", string(data))
	}
}

func TestSecretString_MarshalText(t *testing.T) {
	s := NewSecret("hidden-value")
	data, err := s.MarshalText()
	if err != nil {
		t.Fatalf("marshal text error: %v", err)
	}
	if string(data) != "***REDACTED***" {
		t.Errorf("expected redacted text, got: %s", string(data))
	}
}

func TestSecretString_Raw(t *testing.T) {
	s := NewSecret("raw-value-123")
	if s.Raw() != "raw-value-123" {
		t.Errorf("Raw() should return original value, got: %s", s.Raw())
	}
}

func TestSecretString_IsZero(t *testing.T) {
	var empty SecretString
	if !empty.IsZero() {
		t.Error("empty secret should be zero")
	}
	nonEmpty := NewSecret("value")
	if nonEmpty.IsZero() {
		t.Error("non-empty secret should not be zero")
	}
}
