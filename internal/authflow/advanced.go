package authflow

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

// AuthFinding represents an authentication/authorization finding.
type AuthFinding struct {
	ID          string
	Type        string
	Severity    string
	Title       string
	Description string
	Endpoint    string
	PoC         string
	Impact      string
	Remediation string
	CVSS        float64
	MITRE       string
	Timestamp   time.Time
}

// AuthConfig configures authentication testing.
type AuthConfig struct {
	Target      string
	BaseURL     string
	AuthMethods []string                     // oauth, saml, mfa, totp, browser, password
	Roles       map[string]map[string]string // role -> {username, password, token}
	MFASecrets  map[string]string
	TOTPSecrets map[string]string
	Timeout     time.Duration
}

// Engine performs advanced authentication and authorization testing.
type Engine struct {
	mu       sync.Mutex
	findings []AuthFinding
	config   AuthConfig
	client   *http.Client
}

// New creates a new auth testing engine.
func New(cfg AuthConfig) *Engine {
	return &Engine{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		findings: make([]AuthFinding, 0),
	}
}

// Run executes all authentication tests.
func (e *Engine) Run(ctx context.Context) []AuthFinding {
	e.mu.Lock()
	e.findings = make([]AuthFinding, 0)
	e.mu.Unlock()

	tests := []func(context.Context){
		e.testOAuthFlows,
		e.testSAMLInjection,
		e.testMFABypass,
		e.testTOTPBruteForce,
		e.testBrowserAuthBypass,
		e.testMultiRoleAccess,
		e.testSessionFixation,
		e.testTokenReplay,
		e.testJWTManipulation,
		e.testPasswordPolicy,
	}

	for _, test := range tests {
		select {
		case <-ctx.Done():
			return e.findings
		default:
			test(ctx)
		}
	}

	return e.findings
}

// testOAuthFlows tests OAuth 2.0 / OIDC implementation flaws.
func (e *Engine) testOAuthFlows(ctx context.Context) {
	// Test authorization code flow manipulation
	oauthEndpoints := []string{
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/callback",
		"/.well-known/openid-configuration",
	}

	for _, ep := range oauthEndpoints {
		req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+ep, nil)
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}

		// Test open redirect in OAuth callback
		if strings.Contains(ep, "callback") || strings.Contains(ep, "authorize") {
			redirectURL := e.config.BaseURL + ep + "?redirect_uri=https://evil.com"
			req2, _ := http.NewRequestWithContext(ctx, "GET", redirectURL, nil)
			resp2, err := e.client.Do(req2)
			if err == nil {
				location := resp2.Header.Get("Location")
				if strings.Contains(location, "evil.com") {
					e.addFinding(AuthFinding{
						Type:        "OAuth",
						Severity:    "high",
						Title:       "OAuth open redirect vulnerability",
						Description: "OAuth callback accepts arbitrary redirect_uri values",
						Endpoint:    e.config.BaseURL + ep,
						PoC:         fmt.Sprintf("redirect_uri=https://evil.com -> %s", location),
						Impact:      "Authorization code interception, account takeover",
						Remediation: "Validate redirect_uri against allowlist of registered URIs",
						CVSS:        7.5,
						MITRE:       "T1190",
						Timestamp:   time.Now(),
					})
				}
				resp2.Body.Close()
			}
		}

		// Test PKCE bypass
		if strings.Contains(ep, "token") {
			// Request without PKCE code_verifier
			data := url.Values{}
			data.Set("grant_type", "authorization_code")
			data.Set("code", "test_code")
			data.Set("redirect_uri", "http://localhost/callback")
			req3, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+ep, strings.NewReader(data.Encode()))
			req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp3, err := e.client.Do(req3)
			if err == nil && resp3.StatusCode == 200 {
				e.addFinding(AuthFinding{
					Type:        "OAuth",
					Severity:    "medium",
					Title:       "OAuth PKCE not enforced",
					Description: "Token endpoint accepts authorization codes without PKCE code_verifier",
					Endpoint:    e.config.BaseURL + ep,
					Impact:      "Authorization code interception attack",
					Remediation: "Enforce PKCE for all public clients",
					CVSS:        6.5,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
			if resp3 != nil {
				resp3.Body.Close()
			}
		}
		resp.Body.Close()
	}
}

// testSAMLInjection tests SAML authentication vulnerabilities.
func (e *Engine) testSAMLInjection(ctx context.Context) {
	samlEndpoints := []string{"/saml/acs", "/saml/login", "/sso/saml"}
	for _, ep := range samlEndpoints {
		samlPayload := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>test_user@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`

		data := url.Values{}
		data.Set("SAMLResponse", samlPayload)
		req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+ep, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			e.addFinding(AuthFinding{
				Type:        "SAML",
				Severity:    "high",
				Title:       "SAML endpoint accepts test assertion",
				Description: "SAML endpoint responded to unsigned test assertion — requires manual verification",
				Endpoint:    e.config.BaseURL + ep,
				PoC:         "Unsigned SAML assertion with test NameID received response",
				Impact:      "Potential authentication bypass if signature not validated",
				Remediation: "Enforce SAML signature validation and certificate pinning",
				CVSS:        7.0,
				MITRE:       "T1190",
				Timestamp:   time.Now(),
			})
		}
		resp.Body.Close()
	}
}

// testMFABypass tests multi-factor authentication bypass.
func (e *Engine) testMFABypass(ctx context.Context) {
	// Test MFA code bypass via parameter manipulation
	mfaEndpoints := []string{"/api/mfa/verify", "/api/2fa/validate", "/mfa/check"}
	for _, ep := range mfaEndpoints {
		// Test empty MFA code
		for _, bypass := range []string{"", "000000", "123456", "null", "false"} {
			data := url.Values{}
			data.Set("code", bypass)
			data.Set("user_id", "test_user")
			req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+ep, strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				e.addFinding(AuthFinding{
					Type:        "MFA Bypass",
					Severity:    "critical",
					Title:       fmt.Sprintf("MFA bypass with code '%s'", bypass),
					Description: fmt.Sprintf("MFA verification accepts bypass payload '%s'", bypass),
					Endpoint:    e.config.BaseURL + ep,
					PoC:         fmt.Sprintf("POST %s with code=%s", ep, bypass),
					Impact:      "Complete MFA bypass, account takeover",
					Remediation: "Validate MFA codes against TOTP/HOTP algorithm, reject known bypass patterns",
					CVSS:        9.0,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
			resp.Body.Close()
		}
	}
}

// testTOTPBruteForce tests TOTP brute force vulnerability.
func (e *Engine) testTOTPBruteForce(ctx context.Context) {
	totpEndpoints := []string{"/api/totp/verify", "/api/otp/check"}
	for _, ep := range totpEndpoints {
		// Rapid-fire TOTP codes (000000-000010)
		successCount := 0
		for code := 0; code <= 10; code++ {
			data := url.Values{}
			data.Set("code", fmt.Sprintf("%06d", code))
			data.Set("user_id", "test_user")
			req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+ep, strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 {
				successCount++
			}
			resp.Body.Close()
		}

		// If no rate limiting detected
		if successCount == 0 {
			// All requests were processed (not rate limited)
			e.addFinding(AuthFinding{
				Type:        "TOTP Brute Force",
				Severity:    "high",
				Title:       "TOTP endpoint lacks rate limiting",
				Description: "TOTP verification allows rapid brute force attempts without throttling",
				Endpoint:    e.config.BaseURL + ep,
				Impact:      "TOTP code brute force within valid time window",
				Remediation: "Implement rate limiting and account lockout after 5 failed TOTP attempts",
				CVSS:        7.5,
				MITRE:       "T1110",
				Timestamp:   time.Now(),
			})
		}
	}
}

// testBrowserAuthBypass tests browser-based authentication bypass.
func (e *Engine) testBrowserAuthBypass(ctx context.Context) {
	// Test cookie manipulation
	authCookies := []string{"session", "auth_token", "access_token", "jwt", "sid"}
	for _, cookieName := range authCookies {
		req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+"/api/profile", nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: "manipulated_value"})
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			e.addFinding(AuthFinding{
				Type:        "Browser Auth",
				Severity:    "high",
				Title:       fmt.Sprintf("Cookie-based auth bypass via '%s'", cookieName),
				Description: fmt.Sprintf("Manipulated '%s' cookie value accepted by server", cookieName),
				Endpoint:    e.config.BaseURL + "/api/profile",
				Impact:      "Authentication bypass via cookie manipulation",
				Remediation: "Validate cookie signatures server-side, use HttpOnly + Secure flags",
				CVSS:        7.5,
				MITRE:       "T1190",
				Timestamp:   time.Now(),
			})
		}
		resp.Body.Close()
	}
}

// testMultiRoleAccess tests multi-role access control.
func (e *Engine) testMultiRoleAccess(ctx context.Context) {
	roleEndpoints := map[string][]string{
		"admin":    {"/api/admin", "/api/users", "/api/settings"},
		"user":     {"/api/profile", "/api/orders"},
		"readonly": {"/api/reports", "/api/dashboard"},
	}

	for roleA, _ := range roleEndpoints {
		for roleB, endpointsB := range roleEndpoints {
			if roleA == roleB {
				continue
			}

			// Test if roleA can access roleB's endpoints
			for _, ep := range endpointsB {
				tokens := e.config.Roles[roleA]
				if tokens == nil {
					continue
				}
				token := tokens["token"]
				if token == "" {
					continue
				}

				req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+ep, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := e.client.Do(req)
				if err != nil {
					continue
				}

				if resp.StatusCode == 200 {
					e.addFinding(AuthFinding{
						Type:        "Multi-Role Access",
						Severity:    "high",
						Title:       fmt.Sprintf("Role '%s' can access '%s' endpoints", roleA, roleB),
						Description: fmt.Sprintf("User with role '%s' accessed endpoint %s intended for '%s'", roleA, ep, roleB),
						Endpoint:    e.config.BaseURL + ep,
						Impact:      "Privilege escalation via role confusion",
						Remediation: "Enforce strict role-based access control on all endpoints",
						CVSS:        7.0,
						MITRE:       "T1078",
						Timestamp:   time.Now(),
					})
				}
				resp.Body.Close()
			}
		}
	}
}

// testSessionFixation tests session fixation vulnerability.
func (e *Engine) testSessionFixation(ctx context.Context) {
	// Test if session ID is accepted before and after authentication
	req1, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+"/api/profile", nil)
	req1.AddCookie(&http.Cookie{Name: "session", Value: "fixated_session_id"})
	resp1, err := e.client.Do(req1)
	if err != nil {
		return
	}
	resp1.Body.Close()

	// Login with same session
	loginData := url.Values{}
	loginData.Set("username", "test")
	loginData.Set("password", "test")
	req2, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+"/api/login", strings.NewReader(loginData.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "session", Value: "fixated_session_id"})
	resp2, err := e.client.Do(req2)
	if err != nil {
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 200 {
		// Check if same session ID is still valid post-login
		req3, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+"/api/profile", nil)
		req3.AddCookie(&http.Cookie{Name: "session", Value: "fixated_session_id"})
		resp3, err := e.client.Do(req3)
		if err == nil && resp3.StatusCode == 200 {
			e.addFinding(AuthFinding{
				Type:        "Session Fixation",
				Severity:    "high",
				Title:       "Session fixation vulnerability",
				Description: "Server accepts pre-authentication session ID post-login",
				Endpoint:    e.config.BaseURL + "/api/login",
				Impact:      "Account takeover via session fixation",
				Remediation: "Regenerate session ID after successful authentication",
				CVSS:        7.5,
				MITRE:       "T1190",
				Timestamp:   time.Now(),
			})
		}
		if resp3 != nil {
			resp3.Body.Close()
		}
	}
}

// testTokenReplay tests token replay attacks.
func (e *Engine) testTokenReplay(ctx context.Context) {
	// Test if expired tokens are still accepted
	expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired"
	req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+"/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		e.addFinding(AuthFinding{
			Type:        "Token Replay",
			Severity:    "critical",
			Title:       "Expired token accepted",
			Description: "Server accepts expired authentication tokens",
			Endpoint:    e.config.BaseURL + "/api/profile",
			Impact:      "Persistent unauthorized access via token replay",
			Remediation: "Validate token expiration on every request, implement token revocation",
			CVSS:        8.5,
			MITRE:       "T1190",
			Timestamp:   time.Now(),
		})
	}
}

// testJWTManipulation tests JWT manipulation attacks.
func (e *Engine) testJWTManipulation(ctx context.Context) {
	jwtAttacks := []struct {
		name  string
		token string
	}{
		{"none_algorithm", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJyb2xlIjoidGVzdGVyIn0."},
		{"empty_secret", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3VzZXIifQ.INVALID"},
	}

	for _, attack := range jwtAttacks {
		req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+"/api/profile", nil)
		req.Header.Set("Authorization", "Bearer "+attack.token)
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			e.addFinding(AuthFinding{
				Type:        "JWT Manipulation",
				Severity:    "high",
				Title:       fmt.Sprintf("JWT vulnerability: %s", attack.name),
				Description: fmt.Sprintf("Server accepted test JWT with %s attack pattern", attack.name),
				Endpoint:    e.config.BaseURL + "/api/profile",
				Impact:      "Potential authentication bypass via JWT manipulation",
				Remediation: "Enforce strict algorithm validation, use allowlist of accepted algorithms",
				CVSS:        7.5,
				MITRE:       "T1190",
				Timestamp:   time.Now(),
			})
		}
		resp.Body.Close()
	}
}

// testPasswordPolicy tests password policy enforcement.
func (e *Engine) testPasswordPolicy(ctx context.Context) {
	weakPasswords := []string{"password", "123456", "admin", "password123", "qwerty"}
	for _, pwd := range weakPasswords {
		data := url.Values{}
		data.Set("username", "test_user")
		data.Set("password", pwd)
		req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+"/api/register", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			e.addFinding(AuthFinding{
				Type:        "Password Policy",
				Severity:    "medium",
				Title:       fmt.Sprintf("Weak password accepted: '%s'", pwd),
				Description: "Registration endpoint accepts commonly used weak passwords",
				Endpoint:    e.config.BaseURL + "/api/register",
				Impact:      "Account compromise via brute force or credential stuffing",
				Remediation: "Enforce password complexity requirements and check against breach databases",
				CVSS:        5.5,
				MITRE:       "T1110",
				Timestamp:   time.Now(),
			})
		}
		resp.Body.Close()
	}
}

func (e *Engine) addFinding(f AuthFinding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f.ID = fmt.Sprintf("auth-%d", len(e.findings)+1)
	e.findings = append(e.findings, f)
	logger.Info(fmt.Sprintf("[AuthFlow] Finding: %s - %s (%s)", f.Severity, f.Title, f.Type))
}

// Findings returns all findings.
func (e *Engine) Findings() []AuthFinding {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]AuthFinding, len(e.findings))
	copy(cp, e.findings)
	return cp
}
