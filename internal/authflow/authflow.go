// Package authflow provides custom authentication flow detection,
// session tracking, token analysis, and auth logic vulnerability mapping.
package authflow

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/security"
)

type AuthFlow struct {
	TargetURL     string      `json:"target_url"`
	LoginEndpoint string      `json:"login_endpoint"`
	LoginMethod   string      `json:"login_method"`
	AuthType      string      `json:"auth_type"`
	SessionCookie string      `json:"session_cookie"`
	TokenHeaders  []string    `json:"token_headers"`
	CSRFToken     *CSRFToken  `json:"csrf_token,omitempty"`
	OAuthFlows    []OAuthFlow `json:"oauth_flows,omitempty"`
	JWTConfig     *JWTConfig  `json:"jwt_config,omitempty"`
	Steps         []AuthStep  `json:"steps"`
	Vulns         []AuthVuln  `json:"vulnerabilities"`
}

type CSRFToken struct {
	ParameterName string `json:"parameter_name"`
	HeaderName    string `json:"header_name"`
	Endpoint      string `json:"endpoint"`
	CookieName    string `json:"cookie_name"`
}

type OAuthFlow struct {
	Type     string   `json:"type"`
	AuthURL  string   `json:"auth_url"`
	TokenURL string   `json:"token_url"`
	ClientID string   `json:"client_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	State    string   `json:"state,omitempty"`
}

type OAuthStateStore struct {
	mu     sync.RWMutex
	states map[string]time.Time
	ttl    time.Duration
	stopCh chan struct{}
}

func NewOAuthStateStore(ttl time.Duration) *OAuthStateStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s := &OAuthStateStore{
		states: make(map[string]time.Time),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go s.periodicCleanup()
	return s
}

func (s *OAuthStateStore) GenerateState() (string, error) {
	state, err := GenerateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate OAuth state: %w", err)
	}
	s.mu.Lock()
	s.states[state] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return state, nil
}

func (s *OAuthStateStore) ValidateState(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.states[state]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.states, state)
		return false
	}
	delete(s.states, state)
	return true
}

func (s *OAuthStateStore) periodicCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for state, expiry := range s.states {
				if now.After(expiry) {
					delete(s.states, state)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *OAuthStateStore) Stop() {
	close(s.stopCh)
}

type JWTConfig struct {
	Algorithm  string   `json:"algorithm"`
	Secret     string   `json:"secret,omitempty"`
	Claims     []string `json:"claims"`
	TokenParam string   `json:"token_param"`
}

type AuthStep struct {
	Order            int    `json:"order"`
	URL              string `json:"url"`
	Method           string `json:"method"`
	Purpose          string `json:"purpose"`
	HasCSRF          bool   `json:"has_csrf_protection"`
	SuccessIndicator string `json:"success_indicator"`
	FailureIndicator string `json:"failure_indicator"`
}

type AuthVuln struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Evidence    string `json:"evidence"`
	URL         string `json:"url"`
}

func DetectAuthFlow(targetURL string) (*AuthFlow, error) {
	flow := &AuthFlow{
		TargetURL: targetURL,
		Steps:     []AuthStep{},
		Vulns:     []AuthVuln{},
	}

	pages := []string{
		targetURL + "/login",
		targetURL + "/signin",
		targetURL + "/auth/login",
		targetURL + "/auth/signin",
		targetURL + "/admin/login",
		targetURL + "/wp-login.php",
		targetURL + "/api/auth/login",
		targetURL,
	}

	for _, page := range pages {
		loginFound, step := detectLoginPage(page)
		if loginFound {
			flow.LoginEndpoint = page
			if step.Method != "" {
				flow.LoginMethod = step.Method
			}
			flow.Steps = append(flow.Steps, step)
			break
		}
	}

	flow.AuthType = classifyAuthType(targetURL)

	flow.CSRFToken = detectCSRFProtection(flow.LoginEndpoint)

	flow.JWTConfig = detectJWT(flow.LoginEndpoint)

	flow.SessionCookie = detectSessionCookie(targetURL, flow.LoginEndpoint)

	flow.OAuthFlows = detectOAuth(targetURL)

	flow.Vulns = detectAuthVulns(flow)

	return flow, nil
}

// GenerateSecureToken generates a cryptographically secure token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func detectLoginPage(pageURL string) (bool, AuthStep) {
	if err := security.ValidateURL(pageURL); err != nil {
		return false, AuthStep{}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(pageURL)
	if err != nil {
		return false, AuthStep{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, AuthStep{}
	}

	step := AuthStep{
		URL:     pageURL,
		Method:  "GET",
		Purpose: "load_login_page",
	}

	cookieNames := []string{}
	for _, c := range resp.Cookies() {
		if strings.Contains(strings.ToLower(c.Name), "session") ||
			strings.Contains(strings.ToLower(c.Name), "csrf") ||
			strings.Contains(strings.ToLower(c.Name), "token") {
			cookieNames = append(cookieNames, c.Name)
		}
	}
	if len(cookieNames) > 0 {
		step.HasCSRF = true
	}

	return true, step
}

func classifyAuthType(targetURL string) string {
	if strings.Contains(targetURL, "wp-login") {
		return "wordpress_session"
	}
	if strings.Contains(targetURL, "/api/auth") || strings.Contains(targetURL, "/auth/") {
		return "jwt_or_session"
	}
	if strings.Contains(targetURL, "oauth") || strings.Contains(targetURL, "/login/oauth") {
		return "oauth2"
	}
	return "session_based"
}

func detectCSRFProtection(loginURL string) *CSRFToken {
	if err := security.ValidateURL(loginURL); err != nil {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(loginURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	csrf := &CSRFToken{}

	csrfParamPatterns := []string{"csrf", "xsrf", "_token", "authenticity_token", "requesttoken"}
	for _, name := range csrfParamPatterns {
		if csrf.ParameterName == "" && strings.Contains(resp.Request.URL.String(), name) {
			csrf.ParameterName = name
		}
	}

	for _, c := range resp.Cookies() {
		if strings.Contains(strings.ToLower(c.Name), "csrf") || strings.Contains(strings.ToLower(c.Name), "xsrf") {
			csrf.CookieName = c.Name
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	csrfRe := regexp.MustCompile(`<input[^>]+name=["']([^"']+)["'][^>]+(?:csrf|xsrf|token)`)
	matches := csrfRe.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		csrf.ParameterName = matches[1]
	}

	headerPatterns := []string{"X-CSRF-Token", "X-XSRF-Token", "X-CSRFToken", "X-Requested-With"}
	csrf.HeaderName = headerPatterns[0]

	return csrf
}

func detectJWT(loginURL string) *JWTConfig {
	if err := security.ValidateURL(loginURL); err != nil {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(loginURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	content := string(body)
	scripts := regexp.MustCompile(`<script[^>]*>([\s\S]*?)</script>`).FindAllStringSubmatch(content, -1)

	jwtConfig := &JWTConfig{
		TokenParam: "Authorization",
	}

	for _, match := range scripts {
		if len(match) > 1 {
			script := match[1]
			if strings.Contains(script, "jwt") || strings.Contains(script, "Bearer") || strings.Contains(script, "access_token") {
				if strings.Contains(script, "RS256") || strings.Contains(script, "HS256") {
					parts := strings.Split(script, "algorithm")
					if len(parts) > 1 {
						alg := strings.TrimSpace(parts[1])
						if len(alg) > 10 {
							alg = alg[:10]
						}
						alg = strings.Trim(alg, "'\"")
						jwtConfig.Algorithm = alg
					}
				}
				return jwtConfig
			}
		}
	}

	return nil
}

func detectSessionCookie(targetURL, loginURL string) string {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}

	if err := security.ValidateURL(targetURL); err != nil {
		return ""
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if strings.Contains(strings.ToLower(c.Name), "session") ||
			strings.Contains(strings.ToLower(c.Name), "auth") ||
			strings.Contains(strings.ToLower(c.Name), "sess") {
			return c.Name
		}
	}

	return ""
}

func detectOAuth(targetURL string) []OAuthFlow {
	var flows []OAuthFlow
	if err := security.ValidateURL(targetURL); err != nil {
		return flows
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return flows
	}
	defer resp.Body.Close()

	oauthURLs := []string{"oauth", "authorize", "oauth2", "oauth/authorize", ".auth0.com"}
	for _, ou := range oauthURLs {
		if strings.Contains(resp.Request.URL.String(), ou) {
			flows = append(flows, OAuthFlow{
				Type:    "oauth2",
				AuthURL: resp.Request.URL.String(),
			})
		}
	}

	return flows
}

func detectAuthVulns(flow *AuthFlow) []AuthVuln {
	var vulns []AuthVuln

	if flow.LoginEndpoint == "" {
		return vulns
	}

	if flow.CSRFToken == nil || flow.CSRFToken.ParameterName == "" {
		vulns = append(vulns, AuthVuln{
			Type:        "missing_csrf_protection",
			Description: "Login endpoint lacks CSRF token validation",
			Severity:    "High",
			Evidence:    "No CSRF token parameter or header detected",
			URL:         flow.LoginEndpoint,
		})
	}

	if flow.SessionCookie == "" && flow.JWTConfig == nil {
		vulns = append(vulns, AuthVuln{
			Type:        "weak_session_management",
			Description: "No session cookie or JWT configuration detected",
			Severity:    "Medium",
			Evidence:    "Could not identify session management mechanism",
			URL:         flow.LoginEndpoint,
		})
	}

	return vulns
}

func TestAuthBypass(targetURL, loginURL, username, password string) (bool, string) {
	return false, "active auth bypass testing disabled: requires explicit authorization"
}

func TestJWTAlgNone(url, token string) (bool, string) {
	return false, "active JWT alg=none testing disabled: requires explicit authorization"
}

func TestJWTKid(url, token string) (bool, string) {
	return false, "active JWT kid injection testing disabled: requires explicit authorization"
}

func extractJWTField(token, field string) string {
	if field == "kid" {
		parts := strings.Split(token, ".")
		if len(parts) < 2 {
			return ""
		}
		headerJSON := decodeBase64URL(parts[0])
		var m map[string]interface{}
		json.Unmarshal([]byte(headerJSON), &m)
		if v, ok := m["kid"]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func decodeBase64URL(s string) string {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return s
}

func TestOAuthMisconfiguration(authURL string, stateStore *OAuthStateStore) []AuthVuln {
	var vulns []AuthVuln

	if err := security.ValidateURL(authURL); err != nil {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	if stateStore != nil {
		state, err := stateStore.GenerateState()
		if err == nil {
			stateURL := authURL + "?response_type=code&state=" + url.QueryEscape(state) + "&redirect_uri=" + url.QueryEscape("https://localhost/callback")
			resp, err := client.Get(stateURL)
			if err == nil {
				defer resp.Body.Close()
				location := resp.Header.Get("Location")
				if location != "" {
					parsed, parseErr := url.Parse(location)
					if parseErr == nil {
						returnedState := parsed.Query().Get("state")
						if returnedState == "" || returnedState != state {
							vulns = append(vulns, AuthVuln{
								Type:        "oauth_state_parameter_mismatch",
								Description: "OAuth state parameter not properly echoed back — susceptible to CSRF",
								Severity:    "High",
								Evidence:    fmt.Sprintf("Sent state=%s, got state=%s", state, returnedState),
								URL:         stateURL,
							})
						}
					}
				}
			}
		}
	}

	testURL := authURL + "?response_type=code&redirect_uri=" + url.QueryEscape("https://evil.com")
	resp, err := client.Get(testURL)
	if err == nil {
		defer resp.Body.Close()
		location := resp.Header.Get("Location")
		if location != "" {
			parsed, parseErr := url.Parse(location)
			if parseErr == nil {
				if parsed.Query().Get("state") == "" {
					vulns = append(vulns, AuthVuln{
						Type:        "oauth_state_parameter_missing",
						Description: "OAuth state parameter missing in authorization response — susceptible to CSRF",
						Severity:    "High",
						Evidence:    "No state parameter in authorization redirect",
						URL:         testURL,
					})
				}
			}
		}
	}

	return vulns
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (f *AuthFlow) Summary() string {
	return fmt.Sprintf("AuthFlow: type=%s login=%s csrf=%v jwt=%v steps=%d vulns=%d",
		f.AuthType, f.LoginEndpoint, f.CSRFToken != nil, f.JWTConfig != nil, len(f.Steps), len(f.Vulns))
}

func TestWeakSession(url string) (bool, string) {
	if err := security.ValidateURL(url); err != nil {
		return false, err.Error()
	}
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if !c.Secure && strings.Contains(strings.ToLower(c.Name), "session") {
			return true, fmt.Sprintf("Session cookie %s is not Secure flag", c.Name)
		}
		if !c.HttpOnly && strings.Contains(strings.ToLower(c.Name), "session") {
			return true, fmt.Sprintf("Session cookie %s lacks HttpOnly flag", c.Name)
		}
		if c.SameSite != http.SameSiteStrictMode && c.SameSite != 0 {
			return true, fmt.Sprintf("Session cookie %s has weak SameSite policy", c.Name)
		}
	}

	return false, "No weak session issues detected"
}

type SessionTracker struct {
	jar     *cookiejar.Jar
	baseURL string
}

func NewSessionTracker(baseURL string) *SessionTracker {
	jar, _ := cookiejar.New(nil)
	return &SessionTracker{jar: jar, baseURL: baseURL}
}

func (st *SessionTracker) Login(username, password string, loginURL string) error {
	if err := security.ValidateURL(loginURL); err != nil {
		return fmt.Errorf("login URL validation failed: %w", err)
	}
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("login request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Jar: st.jar, Timeout: 15 * time.Second}
	_, err = client.Do(req)
	return err
}

func (st *SessionTracker) Request(method, path string) (*http.Response, error) {
	url := st.baseURL + path
	if err := security.ValidateURL(url); err != nil {
		return nil, fmt.Errorf("request URL validation failed: %w", err)
	}
	req, _ := http.NewRequest(method, url, nil)

	client := &http.Client{Jar: st.jar, Timeout: 15 * time.Second}
	return client.Do(req)
}

func (st *SessionTracker) GetSessionTokens() []string {
	var tokens []string
	parsedURL, _ := url.Parse(st.baseURL)
	if parsedURL == nil {
		return nil
	}
	for _, c := range st.jar.Cookies(parsedURL) {
		tokens = append(tokens, c.Name+"="+c.Value)
	}
	return tokens
}
