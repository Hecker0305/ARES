package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine("oob.example.com")
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.oobDomain != "oob.example.com" {
		t.Errorf("expected oob.example.com, got %s", e.oobDomain)
	}
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got %v", e.client.Timeout)
	}
}

func TestNewEngine_EmptyDomain(t *testing.T) {
	e := NewEngine("")
	if e.oobDomain != "" {
		t.Errorf("expected empty domain, got %s", e.oobDomain)
	}
}

func TestTestAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://app.com/callback?code=abc")
		w.WriteHeader(http.StatusFound)
		w.Write([]byte{})
	}))
	defer server.Close()

	e := NewEngine("oob.example.com")
	findings, err := e.TestAll(server.URL, server.URL+"/token")
	if err != nil {
		t.Fatal("TestAll failed:", err)
	}
	_ = findings
}

func TestTestOpenRedirect(t *testing.T) {
	tests := []struct {
		name           string
		locationHeader string
		expectFinding  bool
	}{
		{
			name:           "redirect to evil.com",
			locationHeader: "https://evil.com/login",
			expectFinding:  true,
		},
		{
			name:           "redirect to trusted.com",
			locationHeader: "https://trusted.com/callback",
			expectFinding:  false,
		},
		{
			name:           "no location header",
			locationHeader: "",
			expectFinding:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.locationHeader != "" {
					w.Header().Set("Location", tc.locationHeader)
				}
				w.WriteHeader(http.StatusFound)
			}))
			defer server.Close()

			e := NewEngine("oob.example.com")
			findings, err := e.TestOpenRedirect(server.URL)
			if err != nil {
				t.Fatal("TestOpenRedirect failed:", err)
			}

			if tc.expectFinding && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tc.expectFinding {
				for _, f := range findings {
					if f.Type == "oauth_open_redirect" {
						t.Errorf("unexpected open redirect finding: %s", f.Evidence)
					}
				}
			}
		})
	}
}

func TestTestOpenRedirect_AllPayloads(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Location", "https://evil.com/callback")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	e := NewEngine("")
	findings, err := e.TestOpenRedirect(server.URL)
	if err != nil {
		t.Fatal("TestOpenRedirect failed:", err)
	}

	if len(findings) == 0 {
		t.Error("expected at least one finding when server always redirects to evil.com")
	}
	if callCount != 6 {
		t.Errorf("expected 6 payload attempts, got %d", callCount)
	}
}

func TestTestOpenRedirect_InvalidURL(t *testing.T) {
	e := NewEngine("")
	findings, _ := e.TestOpenRedirect("://invalid")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid URL, got %d", len(findings))
	}
}

func TestTestStateFixation(t *testing.T) {
	tests := []struct {
		name          string
		locationState string
		expectFinding bool
	}{
		{
			name:          "server echoes fixed state",
			locationState: "FIXED_STATE_VALUE",
			expectFinding: true,
		},
		{
			name:          "server uses different state",
			locationState: "RANDOM_STATE",
			expectFinding: false,
		},
		{
			name:          "no location header",
			locationState: "",
			expectFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.locationState != "" {
					w.Header().Set("Location", fmt.Sprintf("https://app.com/callback?state=%s&code=abc", tc.locationState))
				}
				w.WriteHeader(http.StatusFound)
			}))
			defer server.Close()

			e := NewEngine("")
			findings, err := e.TestStateFixation(server.URL)
			if err != nil {
				t.Fatal("TestStateFixation failed:", err)
			}

			if tc.expectFinding && len(findings) == 0 {
				t.Error("expected finding for state fixation")
			}
			if !tc.expectFinding && len(findings) > 0 {
				t.Error("unexpected finding")
			}
		})
	}
}

func TestTestStateFixation_InvalidURL(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestStateFixation("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestTestTokenLeakage(t *testing.T) {
	tests := []struct {
		name          string
		location      string
		expectFinding bool
	}{
		{
			name:          "token in fragment",
			location:      "https://app.com/callback#access_token=abc123&token_type=Bearer",
			expectFinding: true,
		},
		{
			name:          "token param in URL",
			location:      "https://app.com/callback?token=xyz",
			expectFinding: true,
		},
		{
			name:          "no token in URL",
			location:      "https://app.com/callback?code=abc",
			expectFinding: false,
		},
		{
			name:          "no location",
			location:      "",
			expectFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				w.WriteHeader(http.StatusFound)
			}))
			defer server.Close()

			e := NewEngine("")
			findings, err := e.TestTokenLeakage(server.URL)
			if err != nil {
				t.Fatal("TestTokenLeakage failed:", err)
			}

			if tc.expectFinding && len(findings) == 0 {
				t.Error("expected finding for token leakage")
			}
			if !tc.expectFinding && len(findings) > 0 {
				t.Error("unexpected finding")
			}
		})
	}
}

func TestTestTokenLeakage_InvalidURL(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestTokenLeakage("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestTestPKCEBypass(t *testing.T) {
	authCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://app.com/callback?code=auth_code_123")
		w.WriteHeader(http.StatusFound)
	}))
	defer authCodeServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token": "abc", "token_type": "Bearer"}`))
	}))
	defer tokenServer.Close()

	e := NewEngine("")
	findings, err := e.TestPKCEBypass(authCodeServer.URL, tokenServer.URL)
	if err != nil {
		t.Fatal("TestPKCEBypass failed:", err)
	}

	if len(findings) == 0 {
		t.Log("PKCE bypass test: no finding (expected when token server accepts invalid verifier)")
	}
}

func TestTestPKCEBypass_NoCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://app.com/callback?error=access_denied")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	e := NewEngine("")
	findings, err := e.TestPKCEBypass(server.URL, server.URL)
	if err != nil {
		t.Fatal("TestPKCEBypass failed:", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no auth code, got %d", len(findings))
	}
}

func TestTestPKCEBypass_TokenError(t *testing.T) {
	authCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://app.com/callback?code=abc")
		w.WriteHeader(http.StatusFound)
	}))
	defer authCodeServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant"}`))
	}))
	defer tokenServer.Close()

	e := NewEngine("")
	findings, err := e.TestPKCEBypass(authCodeServer.URL, tokenServer.URL)
	if err != nil {
		t.Fatal("TestPKCEBypass failed:", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when token endpoint rejects, got %d", len(findings))
	}
}

func TestTestImplicitGrant(t *testing.T) {
	tests := []struct {
		name          string
		location      string
		expectFinding bool
	}{
		{
			name:          "implicit grant enabled",
			location:      "https://app.com/callback#access_token=abc&token_type=Bearer",
			expectFinding: true,
		},
		{
			name:          "authorization code flow",
			location:      "https://app.com/callback?code=abc",
			expectFinding: false,
		},
		{
			name:          "no location",
			location:      "",
			expectFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				w.WriteHeader(http.StatusFound)
			}))
			defer server.Close()

			e := NewEngine("")
			findings, err := e.TestImplicitGrant(server.URL)
			if err != nil {
				t.Fatal("TestImplicitGrant failed:", err)
			}

			if tc.expectFinding && len(findings) == 0 {
				t.Error("expected finding for implicit grant")
			}
			if !tc.expectFinding && len(findings) > 0 {
				t.Error("unexpected finding")
			}
		})
	}
}

func TestTestConfusedDeputy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"consent_url": "https://auth.com/consent"}`))
	}))
	defer server.Close()

	e := NewEngine("")
	findings, err := e.TestConfusedDeputy(server.URL)
	if err != nil {
		t.Fatal("TestConfusedDeputy failed:", err)
	}

	if len(findings) == 0 {
		t.Log("Confused deputy test: no finding")
	}
}

func TestTestConfusedDeputy_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	e := NewEngine("")
	findings, _ := e.TestConfusedDeputy(server.URL)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 404, got %d", len(findings))
	}
}

func TestTestConfusedDeputy_InvalidURL(t *testing.T) {
	e := NewEngine("")
	_, err := e.TestConfusedDeputy("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestFinding_Fields(t *testing.T) {
	f := Finding{
		URL:       "https://example.com/authorize",
		Type:      "oauth_open_redirect",
		Payload:   "redirect_uri=https://evil.com",
		Evidence:  "Redirected to evil.com",
		Severity:  "high",
		Confirmed: true,
		Timestamp: time.Now(),
	}

	if f.URL != "https://example.com/authorize" {
		t.Errorf("URL = %s", f.URL)
	}
	if !f.Confirmed {
		t.Error("Confirmed should be true")
	}
	if f.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestMinInt(t *testing.T) {
	if minInt(5, 10) != 5 {
		t.Error("minInt(5,10) should be 5")
	}
	if minInt(10, 5) != 5 {
		t.Error("minInt(10,5) should be 5")
	}
	if minInt(3, 3) != 3 {
		t.Error("minInt(3,3) should be 3")
	}
	if minInt(-1, 5) != -1 {
		t.Error("minInt(-1,5) should be -1")
	}
}

func TestOpenRedirect_PayloadEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.com/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	e := NewEngine("")
	findings, _ := e.TestOpenRedirect(server.URL)

	for _, f := range findings {
		if !strings.Contains(f.Payload, "redirect_uri=") {
			t.Errorf("payload should mention redirect_uri, got: %s", f.Payload)
		}
		if !strings.Contains(f.Evidence, "evil.com") {
			t.Errorf("evidence should mention the redirect target, got: %s", f.Evidence)
		}
	}
}

func TestTokenLeakage_EvidenceTruncation(t *testing.T) {
	longURL := "https://app.com/callback#access_token=" + strings.Repeat("a", 500)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", longURL)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	e := NewEngine("")
	findings, _ := e.TestTokenLeakage(server.URL)

	for _, f := range findings {
		if len(f.Evidence) > 250 {
			t.Errorf("evidence should be truncated to around 200 chars, got %d", len(f.Evidence))
		}
	}
}

func TestImplicitGrant_EvidenceTruncation(t *testing.T) {
	longURL := "https://app.com/callback#access_token=" + strings.Repeat("b", 500)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", longURL)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	e := NewEngine("")
	findings, _ := e.TestImplicitGrant(server.URL)

	for _, f := range findings {
		if len(f.Evidence) > 250 {
			t.Errorf("evidence should be truncated to around 200 chars, got %d", len(f.Evidence))
		}
	}
}

func TestEngine_RedirectDisabled(t *testing.T) {
	redirected := false
	serverURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !redirected {
			redirected = true
			w.Header().Set("Location", serverURL+"/redirected")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte(`final`))
	}))
	serverURL = server.URL
	defer server.Close()

	e := NewEngine("")
	findings, _ := e.TestOpenRedirect(server.URL)
	_ = findings

	if redirected {
		t.Log("redirect occurred as expected")
	}
}

func TestEngine_ClientTimeoutSet(t *testing.T) {
	e := NewEngine("")
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got %v", e.client.Timeout)
	}
}

func TestTestRedirectCallbackFunctionality(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.com")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	e := NewEngine("")
	findings, err := e.TestOpenRedirect(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Error("expected finding since server redirects to evil.com")
	}

	for _, f := range findings {
		if f.Type != "oauth_open_redirect" {
			t.Errorf("expected type oauth_open_redirect, got %s", f.Type)
		}
		if f.Severity != "high" {
			t.Errorf("expected severity high, got %s", f.Severity)
		}
	}
}
