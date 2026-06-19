package airgap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewAirGapManager_Default(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: false})
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.IsAirGapped() {
		t.Error("expected airgap to be disabled")
	}
}

func TestNewAirGapManager_WithManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := struct {
		Tools []toolHash `json:"tools"`
	}{
		Tools: []toolHash{
			{Name: "custom-tool", SHA256: "abc123"},
		},
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(dir, "manifest.json")
	os.WriteFile(manifestPath, data, 0644)
	t.Setenv("ARES_AIRGAP_MANIFEST", manifestPath)

	m := NewAirGapManager(AirGapConfig{Enabled: true})
	if m == nil {
		t.Fatal("expected non-nil manager")
	}

	err := m.VerifyToolHashOnExec("custom-tool", "/nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tool path")
	}
}

func TestNewAirGapManager_WithBadManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "bad.json")
	os.WriteFile(manifestPath, []byte("not json"), 0644)
	t.Setenv("ARES_AIRGAP_MANIFEST", manifestPath)

	m := NewAirGapManager(AirGapConfig{Enabled: true})
	if m.toolHashes == nil {
		t.Error("should fall back to defaults on bad manifest")
	}
	if len(m.toolHashes) == 0 {
		t.Error("default tool hashes should be non-empty")
	}
}

func TestIsAirGapped(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: false})
	if m.IsAirGapped() {
		t.Error("expected airgap to be disabled when config.Enabled is false")
	}
}

func TestIsAirGapped_EnabledConfig(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: true})
	got := m.IsAirGapped()
	t.Logf("IsAirGapped() = %v (depends on actual network state)", got)
}

func TestValidateTool(t *testing.T) {
	tests := []struct {
		name     string
		config   AirGapConfig
		tool     string
		expected bool
	}{
		{
			name:     "airgap disabled",
			config:   AirGapConfig{Enabled: false},
			tool:     "anything",
			expected: true,
		},
		{
			name:     "no allowed tools list",
			config:   AirGapConfig{Enabled: true, AllowedTools: nil},
			tool:     "nmap",
			expected: true,
		},
		{
			name:     "empty allowed tools list",
			config:   AirGapConfig{Enabled: true, AllowedTools: []string{}},
			tool:     "nmap",
			expected: true,
		},
		{
			name:     "tool in allowed list",
			config:   AirGapConfig{Enabled: true, AllowedTools: []string{"nmap", "curl"}},
			tool:     "curl",
			expected: true,
		},
		{
			name:     "tool not in allowed list",
			config:   AirGapConfig{Enabled: true, AllowedTools: []string{"nmap", "curl"}},
			tool:     "gobuster",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewAirGapManager(tc.config)
			if got := m.ValidateTool(tc.tool); got != tc.expected {
				t.Errorf("ValidateTool(%q) = %v, want %v", tc.tool, got, tc.expected)
			}
		})
	}
}

func TestValidateExternalRequest(t *testing.T) {
	tests := []struct {
		name    string
		config  AirGapConfig
		rawURL  string
		allowed bool
	}{
		{
			name:    "airgap disabled",
			config:  AirGapConfig{Enabled: false},
			rawURL:  "https://evil.com",
			allowed: true,
		},
		{
			name:    "blocked IP",
			config:  AirGapConfig{Enabled: true, BlockListIPs: []string{"10.0.0.1"}},
			rawURL:  "http://10.0.0.1/",
			allowed: false,
		},
		{
			name:    "allowed domain",
			config:  AirGapConfig{Enabled: true, AllowedDomains: []string{"trusted.com"}},
			rawURL:  "https://trusted.com/api",
			allowed: true,
		},
		{
			name:    "subdomain of allowed domain",
			config:  AirGapConfig{Enabled: true, AllowedDomains: []string{"trusted.com"}},
			rawURL:  "https://sub.trusted.com/api",
			allowed: true,
		},
		{
			name:    "not in allowed domains",
			config:  AirGapConfig{Enabled: true, AllowedDomains: []string{"trusted.com"}},
			rawURL:  "https://evil.com",
			allowed: false,
		},
		{
			name:    "blocked IP even if domain allowed",
			config:  AirGapConfig{Enabled: true, AllowedDomains: []string{"trusted.com"}, BlockListIPs: []string{"10.0.0.1"}},
			rawURL:  "http://10.0.0.1/",
			allowed: false,
		},
		{
			name:    "empty allowed domains means all allowed",
			config:  AirGapConfig{Enabled: true, AllowedDomains: nil},
			rawURL:  "https://anything.com",
			allowed: true,
		},
		{
			name:    "malformed URL",
			config:  AirGapConfig{Enabled: true},
			rawURL:  "://invalid",
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewAirGapManager(tc.config)
			if got := m.ValidateExternalRequest(tc.rawURL); got != tc.allowed {
				t.Errorf("ValidateExternalRequest(%q) = %v, want %v", tc.rawURL, got, tc.allowed)
			}
		})
	}
}

func TestVerifyToolHashOnExec(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: false})
	if err := m.VerifyToolHashOnExec("nmap", ""); err != nil {
		t.Error("expected nil when airgap disabled, got:", err)
	}

	m2 := NewAirGapManager(AirGapConfig{Enabled: true})
	err := m2.VerifyToolHashOnExec("nonexistent-tool", "/dev/null")
	if err == nil {
		t.Error("expected error for unknown tool")
	}

	err = m2.VerifyToolHashOnExec("nmap", "/nonexistent/path")
	if err == nil {
		t.Error("expected error for hash mismatch or missing file")
	}
}

func TestGetConfig(t *testing.T) {
	cfg := AirGapConfig{
		Enabled:          true,
		AllowedDomains:   []string{"a.com", "b.com"},
		BlockListIPs:     []string{"1.1.1.1"},
		AllowedTools:     []string{"nmap"},
		NoExternalLLM:    true,
		LocalModelsOnly:  true,
		DisableTelemetry: true,
	}
	m := NewAirGapManager(cfg)

	got := m.GetConfig()
	if got.Enabled != true {
		t.Error("Enabled should be true")
	}
	if len(got.AllowedDomains) != 2 {
		t.Error("expected 2 allowed domains")
	}
	if !got.NoExternalLLM {
		t.Error("NoExternalLLM should be true")
	}
	if !got.DisableTelemetry {
		t.Error("DisableTelemetry should be true")
	}
}

func TestSetConfig(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: false})
	m.SetConfig(AirGapConfig{Enabled: true, AllowedDomains: []string{"example.com"}})

	cfg := m.GetConfig()
	if !cfg.Enabled {
		t.Error("expected config enabled after SetConfig")
	}
	domains := m.GetAllowedDomains()
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Errorf("unexpected domains: %v", domains)
	}
}

func TestGetAllowedDomains(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{AllowedDomains: []string{"a.com", "b.com"}})
	domains := m.GetAllowedDomains()
	if len(domains) != 2 {
		t.Fatal("expected 2 domains")
	}
	domains[0] = "modified"
	domains2 := m.GetAllowedDomains()
	if domains2[0] != "a.com" {
		t.Error("GetAllowedDomains should return a copy")
	}
}

func TestGetBlockedIPs(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{BlockListIPs: []string{"192.168.1.1"}})
	ips := m.GetBlockedIPs()
	if len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Errorf("unexpected blocked IPs: %v", ips)
	}
}

func TestRefreshToolHashes(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: true})
	err := m.RefreshToolHashes()
	if err == nil {
		t.Error("expected error when ARES_AIRGAP_MANIFEST is not set")
	}
}

func TestVerifyToolHash(t *testing.T) {
	if VerifyToolHash("/nonexistent", "abc") {
		t.Error("expected false for nonexistent file")
	}
}

func TestGenerateManifest(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "tool1")
	os.WriteFile(f1, []byte("binary content"), 0644)

	result, err := GenerateManifest(map[string]string{"mytool": f1})
	if err != nil {
		t.Fatal("GenerateManifest failed:", err)
	}

	var parsed struct {
		Tools []toolHash `json:"tools"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatal("unmarshal failed:", err)
	}
	if len(parsed.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(parsed.Tools))
	}
	if parsed.Tools[0].Name != "mytool" {
		t.Errorf("expected name mytool, got %s", parsed.Tools[0].Name)
	}
	if parsed.Tools[0].SHA256 == "" {
		t.Error("expected non-empty SHA256 hash")
	}
}

func TestGenerateManifest_ReadError(t *testing.T) {
	_, err := GenerateManifest(map[string]string{"missing": "/nonexistent/path"})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestDefaultToolHashes(t *testing.T) {
	hashes := defaultToolHashes()
	expectedTools := []string{"nmap", "ffuf", "gobuster", "curl", "wget", "dig", "nslookup", "openssl", "python3", "ping"}
	if len(hashes) != len(expectedTools) {
		t.Fatalf("expected %d tools, got %d", len(expectedTools), len(hashes))
	}
	for i, th := range hashes {
		if th.Name != expectedTools[i] {
			t.Errorf("hashes[%d].Name = %s, want %s", i, th.Name, expectedTools[i])
		}
		if len(th.SHA256) != 64 && len(th.SHA256) != 62 {
			t.Errorf("hash for %s should be 62-64 hex chars, got %d", th.Name, len(th.SHA256))
		}
	}
}

func TestLoadManifest_NotFound(t *testing.T) {
	_, err := loadManifest("/nonexistent/manifest.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadManifest_BadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	os.WriteFile(p, []byte("not json"), 0644)
	_, err := loadManifest(p)
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestNewAirGapHandlers(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: true})
	h := NewAirGapHandlers(m)
	if h == nil {
		t.Fatal("expected non-nil handlers")
	}
}

func TestHandler_ServeHTTP_Status(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: true})
	h := NewAirGapHandlers(m)

	req := httptest.NewRequest(http.MethodGet, "/api/airgap/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["airgapped"] == nil {
		t.Error("expected airgapped field in response")
	}
}

func TestHandler_ServeHTTP_Policy(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: false})
	h := NewAirGapHandlers(m)

	req := httptest.NewRequest(http.MethodGet, "/api/airgap/policy", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["config"] == nil {
		t.Error("expected config in response")
	}
}

func TestHandler_ServeHTTP_Validate(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{Enabled: true, AllowedDomains: []string{"trusted.com"}})
	h := NewAirGapHandlers(m)

	req := httptest.NewRequest(http.MethodPost, "/api/airgap/validate", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad body, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/airgap/validate", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad request, got %d", w.Code)
	}
}

func TestHandler_ServeHTTP_NotFound(t *testing.T) {
	m := NewAirGapManager(AirGapConfig{})
	h := NewAirGapHandlers(m)

	req := httptest.NewRequest(http.MethodGet, "/api/airgap/nonexistent", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestConfigFieldsToggleBehavior(t *testing.T) {
	cfg := AirGapConfig{
		Enabled:            true,
		NoExternalLLM:      true,
		LocalModelsOnly:    true,
		DisableTelemetry:   true,
		DisableUpdateCheck: true,
	}

	m := NewAirGapManager(cfg)
	c := m.GetConfig()
	if !c.NoExternalLLM {
		t.Error("NoExternalLLM should be true")
	}
	if !c.LocalModelsOnly {
		t.Error("LocalModelsOnly should be true")
	}
	if !c.DisableTelemetry {
		t.Error("DisableTelemetry should be true")
	}
	if !c.DisableUpdateCheck {
		t.Error("DisableUpdateCheck should be true")
	}
}
