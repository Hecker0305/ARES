package secretmgr

import (
	"testing"
	"time"
)

func mustNewManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	return m
}

func TestNewManager(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Manager")
	}
	if m.secrets == nil {
		t.Error("secrets map should be initialized")
	}
	if m.client == nil {
		t.Error("HTTP client should be initialized")
	}
	if m.rotationPolicy == nil {
		t.Error("rotation policy should be initialized")
	}
}

func TestSetAndGet(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	m.Set("test-key", SecretAPIKey, "sk-12345678")

	s, err := m.Get("test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil secret")
	}
	if s.Name != "test-key" {
		t.Errorf("expected name test-key, got %s", s.Name)
	}
	if s.Type != SecretAPIKey {
		t.Errorf("expected type api_key, got %s", s.Type)
	}
	if s.Value.GoString() != "***REDACTED***" {
		t.Errorf("expected value to be encrypted and masked, got %s", s.Value)
	}
	if s.Provider != "manual" {
		t.Errorf("expected provider manual, got %s", s.Provider)
	}
	if s.LastRotated.IsZero() {
		t.Error("LastRotated should be set")
	}
	if s.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
	if s == nil {
		t.Fatal("expected non-nil secret")
	}
	if s.Name != "test-key" {
		t.Errorf("expected name test-key, got %s", s.Name)
	}
	if s.Type != SecretAPIKey {
		t.Errorf("expected type api_key, got %s", s.Type)
	}
	if s.Value.GoString() != "***REDACTED***" {
		t.Errorf("expected masked value, got %s", s.Value)
	}
	if s.Provider != "manual" {
		t.Errorf("expected provider manual, got %s", s.Provider)
	}
	if s.LastRotated.IsZero() {
		t.Error("LastRotated should be set")
	}
	if s.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
}

func TestGet_NotFound(t *testing.T) {
	m := mustNewManager(t)
	_, err := m.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
}

func TestGet_Expired(t *testing.T) {
	m := mustNewManager(t)
	m.Set("expired", SecretAuthToken, "value")

	m.mu.Lock()
	m.secrets["expired"].ExpiresAt = time.Now().Add(-1 * time.Hour)
	m.mu.Unlock()

	_, err := m.Get("expired")
	if err == nil {
		t.Fatal("expected error for expired secret")
	}
}

func TestSet_UpdatesExisting(t *testing.T) {
	m := mustNewManager(t)
	m.Set("key", SecretAPIKey, "old")
	m.Set("key", SecretDBPassword, "new")

	s, err := m.Get("key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Value.GoString() != "***REDACTED***" {
		t.Errorf("expected value to be masked, got %s", s.Value)
	}
	if s.Type != SecretDBPassword {
		t.Errorf("expected type db_password, got %s", s.Type)
	}
}

func TestSet_DifferentTypes(t *testing.T) {
	m := mustNewManager(t)
	m.Set("api", SecretAPIKey, "v1")
	m.Set("auth", SecretAuthToken, "v2")
	m.Set("db", SecretDBPassword, "v3")
	m.Set("tls", SecretTLSKey, "v4")
	m.Set("oauth", SecretOAuthToken, "v5")

	for _, name := range []string{"api", "auth", "db", "tls", "oauth"} {
		if _, err := m.Get(name); err != nil {
			t.Errorf("unexpected error for %s: %v", name, err)
		}
	}
}

func TestRotate_NotFound(t *testing.T) {
	m := mustNewManager(t)
	err := m.Rotate("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
}

func TestRotate_ManualProvider(t *testing.T) {
	m := mustNewManager(t)
	m.Set("test", SecretAPIKey, "original")

	if err := m.Rotate("test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s, _ := m.Get("test")
	if s.Value.GoString() != "***REDACTED***" {
		t.Error("value should be masked after rotation")
	}
}

func TestRotate_DifferentTypes(t *testing.T) {
	m := mustNewManager(t)

	types := []struct {
		name string
		st   SecretType
	}{
		{"api", SecretAPIKey},
		{"auth", SecretAuthToken},
		{"db", SecretDBPassword},
		{"tls", SecretTLSKey},
		{"oauth", SecretOAuthToken},
	}

	for _, tc := range types {
		m.Set(tc.name, tc.st, "original")
		if err := m.Rotate(tc.name); err != nil {
			t.Errorf("unexpected error rotating %s: %v", tc.name, err)
		}
		s, _ := m.Get(tc.name)
		if s.Value.GoString() != "***REDACTED***" {
			t.Errorf("%s value should be masked", tc.name)
		}
	}
}

func TestRotate_UpdatesExpiry(t *testing.T) {
	m := mustNewManager(t)
	m.Set("test", SecretAPIKey, "original")
	s, _ := m.Get("test")
	originalExpiry := s.ExpiresAt

	time.Sleep(time.Millisecond)
	m.Rotate("test")
	s, _ = m.Get("test")

	if !s.LastRotated.After(originalExpiry.Add(-100 * 365 * 24 * time.Hour)) {
		t.Error("LastRotated should be updated after rotation")
	}
	if s.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future after rotation")
	}
}

func TestRotateAll_Empty(t *testing.T) {
	m := mustNewManager(t)
	errs := m.RotateAll()
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for empty manager, got %d", len(errs))
	}
}

func TestRotateAll_Multiple(t *testing.T) {
	m := mustNewManager(t)
	m.Set("a", SecretAPIKey, "v1")
	m.Set("b", SecretAuthToken, "v2")
	m.Set("c", SecretDBPassword, "v3")

	errs := m.RotateAll()
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}

	for _, name := range []string{"a", "b", "c"} {
		s, err := m.Get(name)
		if err != nil {
			t.Errorf("unexpected error for %s: %v", name, err)
			continue
		}
		if s.Value.GoString() != "***REDACTED***" {
			t.Errorf("%s value should be masked", name)
		}
	}
}

func TestCheckExpiring_NoneExpiring(t *testing.T) {
	m := mustNewManager(t)
	m.Set("key", SecretAPIKey, "value")

	expiring := m.CheckExpiring(1 * time.Minute)
	if len(expiring) != 0 {
		t.Errorf("expected 0 expiring secrets, got %d", len(expiring))
	}
}

func TestCheckExpiring_AllExpiring(t *testing.T) {
	m := mustNewManager(t)
	m.Set("key", SecretAPIKey, "value")

	m.mu.Lock()
	m.secrets["key"].ExpiresAt = time.Now().Add(1 * time.Second)
	m.mu.Unlock()

	expiring := m.CheckExpiring(5 * time.Minute)
	if len(expiring) != 1 {
		t.Errorf("expected 1 expiring secret, got %d", len(expiring))
	}
}

func TestCheckExpiring_Multiple(t *testing.T) {
	m := mustNewManager(t)
	m.Set("far", SecretAPIKey, "v1")
	m.Set("soon", SecretAuthToken, "v2")

	m.mu.Lock()
	m.secrets["soon"].ExpiresAt = time.Now().Add(1 * time.Second)
	m.mu.Unlock()

	expiring := m.CheckExpiring(1 * time.Hour)
	if len(expiring) != 1 {
		t.Fatalf("expected 1 expiring secret, got %d", len(expiring))
	}
	if expiring[0].Name != "soon" {
		t.Errorf("expected 'soon' to be expiring, got %s", expiring[0].Name)
	}
}

func TestListSecrets_MasksValues(t *testing.T) {
	m := mustNewManager(t)
	m.Set("key1", SecretAPIKey, "super-secret-value")
	m.Set("key2", SecretDBPassword, "db-password-123")

	secrets := m.ListSecrets()
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	for _, s := range secrets {
		if s.Value.GoString() != "***REDACTED***" {
			t.Errorf("value should be masked, got %s", s.Value)
		}
	}
}

func TestListSecrets_Empty(t *testing.T) {
	m := mustNewManager(t)
	secrets := m.ListSecrets()
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets))
	}
}

func TestGenerateNewSecret_APIKey(t *testing.T) {
	s, err := generateNewSecret(SecretAPIKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("expected 32 chars, got %d", len(s))
	}
}

func TestGenerateNewSecret_DBPassword(t *testing.T) {
	s, err := generateNewSecret(SecretDBPassword)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 24 {
		t.Errorf("expected 24 chars, got %d", len(s))
	}
}

func TestGenerateNewSecret_TLSKey(t *testing.T) {
	s, err := generateNewSecret(SecretTLSKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 64 {
		t.Errorf("expected 64 chars, got %d", len(s))
	}
}

func TestGenerateNewSecret_Default(t *testing.T) {
	s, err := generateNewSecret(SecretType("unknown"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("expected 32 chars for unknown type, got %d", len(s))
	}
}

func TestGenerateRandomString_Length(t *testing.T) {
	for _, length := range []int{0, 1, 8, 16, 32, 64} {
		s, err := generateRandomString(length)
		if err != nil {
			t.Fatalf("unexpected error for length %d: %v", length, err)
		}
		if len(s) != length {
			t.Errorf("expected length %d, got %d: %s", length, len(s), s)
		}
	}
}

func TestGenerateRandomString_Uniqueness(t *testing.T) {
	m := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := generateRandomString(16)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m[s] {
			t.Fatal("collision detected in random string generation")
		}
		m[s] = true
	}
}

func TestGenerateRandomString_Empty(t *testing.T) {
	s, err := generateRandomString(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 0 {
		t.Errorf("expected empty string for length 0, got %d", len(s))
	}
}

func TestRotationPolicy_Populated(t *testing.T) {
	m := mustNewManager(t)
	expectedPolicies := map[SecretType]time.Duration{
		SecretAPIKey:     90 * 24 * time.Hour,
		SecretAuthToken:  30 * 24 * time.Hour,
		SecretDBPassword: 60 * 24 * time.Hour,
		SecretTLSKey:     365 * 24 * time.Hour,
		SecretOAuthToken: 1 * time.Hour,
	}

	for st, expected := range expectedPolicies {
		got, ok := m.rotationPolicy[st]
		if !ok {
			t.Errorf("missing rotation policy for %s", st)
			continue
		}
		if got != expected {
			t.Errorf("rotation policy for %s: expected %v, got %v", st, expected, got)
		}
	}
}

func TestSet_ExpiresAtByType(t *testing.T) {
	m := mustNewManager(t)
	m.Set("key", SecretOAuthToken, "value")
	s, _ := m.Get("key")

	expectedExpiry := time.Hour
	actualExpiry := s.ExpiresAt.Sub(s.LastRotated)
	if actualExpiry.Round(time.Second) != expectedExpiry {
		t.Errorf("expected expiry %v for OAuthToken, got %v", expectedExpiry, actualExpiry)
	}
}
