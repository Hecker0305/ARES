package broffensive

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DOMEvent struct {
	Type      string    `json:"type"`
	Selector  string    `json:"selector"`
	Value     string    `json:"value"`
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`
}

type SessionSnapshot struct {
	URL      string            `json:"url"`
	Title    string            `json:"title"`
	DOM      string            `json:"dom"`
	Cookies  map[string]string `json:"cookies"`
	Storage  map[string]string `json:"local_storage"`
	Forms    []FormInfo        `json:"forms"`
	Scripts  []string          `json:"scripts"`
	Mutation DOMEvent          `json:"mutation,omitempty"`
	CSPValid bool              `json:"csp_valid"`
}

type FormInfo struct {
	Action   string            `json:"action"`
	Method   string            `json:"method"`
	Fields   map[string]string `json:"fields"`
	AutoFill bool              `json:"autofill"`
}

type AuthState struct {
	LoginURL     string            `json:"login_url"`
	SessionToken string            `json:"session_token"`
	Cookies      map[string]string `json:"cookies"`
	LoggedIn     bool              `json:"logged_in"`
}

type UIFlow struct {
	Steps     []DOMEvent `json:"steps"`
	Pattern   string     `json:"pattern"`
	Completed bool       `json:"completed"`
}

type StoredXSSCheck struct {
	URL       string `json:"url"`
	Payload   string `json:"payload"`
	Reflected bool   `json:"reflected"`
	Persisted bool   `json:"persisted"`
	Evidence  string `json:"evidence"`
}

type CSRFChain struct {
	SourceURL      string            `json:"source_url"`
	TargetURL      string            `json:"target_url"`
	Method         string            `json:"method"`
	Params         map[string]string `json:"params"`
	RequiresAuth   bool              `json:"requires_auth"`
	HasToken       bool              `json:"has_csrf_token"`
	BypassPossible bool              `json:"bypass_possible"`
}

const maxSessions = 50
const maxDOMSize = 1 << 20
const maxScriptSize = 64 << 10

var dangerousJSAPIs = regexp.MustCompile(`(?i)(document\.cookie|window\.open|XMLHttpRequest|fetch\(|navigator\.sendBeacon|Image\(\)\.src|localStorage|sessionStorage|indexedDB|webkit\.messageHandlers|window\.postMessage)`)

var allowedCSPDirectives = map[string]bool{
	"default-src": true,
	"script-src":  true,
	"style-src":   true,
	"img-src":     true,
	"font-src":    true,
	"connect-src": true,
	"frame-src":   true,
	"object-src":  true,
	"base-uri":    true,
	"form-action": true,
}

type Engine struct {
	mu        sync.Mutex
	client    *http.Client
	sessions  map[string]*SessionSnapshot
	auth      *AuthState
	flows     []UIFlow
	cspPolicy string
}

func New() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
		sessions:  make(map[string]*SessionSnapshot),
		flows:     make([]UIFlow, 0),
		cspPolicy: "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'self'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'",
	}
}

func (e *Engine) SetCSP(policy string) error {
	if !validateCSP(policy) {
		return fmt.Errorf("invalid CSP policy: contains dangerous directives")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cspPolicy = policy
	return nil
}

func validateCSP(policy string) bool {
	directives := strings.Split(policy, ";")
	for _, d := range directives {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		parts := strings.SplitN(d, " ", 2)
		if len(parts) == 0 {
			return false
		}
		dir := strings.TrimSuffix(parts[0], ":")
		if !allowedCSPDirectives[dir] {
			return false
		}
		if len(parts) > 1 {
			val := parts[1]
			if strings.Contains(val, "'unsafe-inline'") && strings.Contains(val, "'unsafe-eval'") {
				return false
			}
		}
	}
	return true
}

func (e *Engine) CaptureSession(ctx context.Context, targetURL string) (*SessionSnapshot, error) {
	e.mu.Lock()
	if len(e.sessions) >= maxSessions {
		oldest := ""
		for url := range e.sessions {
			oldest = url
			break
		}
		if oldest != "" {
			delete(e.sessions, oldest)
		}
	}
	e.mu.Unlock()

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ARES-Browser-AI/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Content-Security-Policy", e.cspPolicy)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDOMSize))
	bodyStr := string(body)

	cspHeader := resp.Header.Get("Content-Security-Policy")
	cspValid := cspHeader != "" && !strings.Contains(cspHeader, "'unsafe-eval'") && !strings.Contains(cspHeader, "'unsafe-inline'")

	snap := &SessionSnapshot{
		URL:      targetURL,
		Title:    extractTitle(bodyStr),
		DOM:      sanitizeDOM(bodyStr),
		Cookies:  parseCookies(resp.Header),
		Storage:  make(map[string]string),
		Forms:    extractFormsAdvanced(bodyStr),
		Scripts:  extractAllScriptsSafe(bodyStr),
		CSPValid: cspValid,
	}

	e.mu.Lock()
	e.sessions[targetURL] = snap
	e.mu.Unlock()

	return snap, nil
}

func sanitizeDOM(html string) string {
	html = dangerousJSAPIs.ReplaceAllString(html, "[BLOCKED_API]")
	return html
}

func (e *Engine) Authenticate(ctx context.Context, loginURL, username, password string) (*AuthState, error) {
	forms := e.detectLoginForms(ctx, loginURL)
	if len(forms) == 0 {
		state, err := e.tryBasicAuth(ctx, loginURL, username, password)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.auth = state
		e.mu.Unlock()
		return state, nil
	}

	form := forms[0]
	data := url.Values{}
	for field := range form.Fields {
		if strings.Contains(strings.ToLower(field), "user") || strings.Contains(strings.ToLower(field), "email") {
			data.Set(field, username)
		} else if strings.Contains(strings.ToLower(field), "pass") {
			data.Set(field, password)
		} else {
			data.Set(field, "test")
		}
	}

	method := strings.ToUpper(form.Method)
	if method != "GET" && method != "POST" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, form.Action, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Security-Policy", e.cspPolicy)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	state := &AuthState{
		LoginURL:     loginURL,
		SessionToken: extractSessionToken(resp.Cookies()),
		Cookies:      parseCookies(resp.Header),
		LoggedIn:     resp.StatusCode < 400 && len(resp.Cookies()) > 0,
	}

	e.mu.Lock()
	e.auth = state
	e.mu.Unlock()
	return state, nil
}

func (e *Engine) ReplaySession(ctx context.Context, sessionID string) (*SessionSnapshot, error) {
	e.mu.Lock()
	snap, ok := e.sessions[sessionID]
	e.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", snap.URL, nil)
	if err != nil {
		return nil, err
	}
	if e.auth != nil && len(e.auth.Cookies) > 0 {
		for name, value := range e.auth.Cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
	}
	req.Header.Set("Content-Security-Policy", e.cspPolicy)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDOMSize))
	bodyStr := string(body)

	newSnap := &SessionSnapshot{
		URL:      snap.URL,
		Title:    extractTitle(bodyStr),
		DOM:      sanitizeDOM(bodyStr),
		Cookies:  parseCookies(resp.Header),
		Storage:  make(map[string]string),
		Forms:    extractFormsAdvanced(bodyStr),
		Scripts:  extractAllScriptsSafe(bodyStr),
		CSPValid: snap.CSPValid,
	}

	newSnap.Mutation = e.detectDOMMutation(snap, newSnap)

	e.mu.Lock()
	e.sessions[snap.URL] = newSnap
	e.mu.Unlock()

	return newSnap, nil
}

func (e *Engine) DetectStoredXSS(ctx context.Context, baseURL string) []StoredXSSCheck {
	payloads := []string{
		"<script>alert('ARES_XSS_1')</script>",
		"<img src=x onerror=alert('ARES_XSS_2')>",
		"<svg onload=alert('ARES_XSS_3')>",
		"ARES_XSS_TEST_PAYLOAD",
	}

	var results []StoredXSSCheck

	snap, err := e.CaptureSession(ctx, baseURL)
	if err != nil {
		return results
	}

	for _, payload := range payloads {
		check := StoredXSSCheck{
			URL:     baseURL,
			Payload: payload,
		}

		if strings.Contains(snap.DOM, payload) {
			check.Reflected = true
			check.Evidence = "Payload found in immediate response"
		}

		e.injectAndCheck(ctx, baseURL, payload, &check)

		if check.Reflected || check.Persisted {
			results = append(results, check)
		}
	}

	return results
}

func (e *Engine) AnalyzeCSRF(ctx context.Context, baseURL string) []CSRFChain {
	var chains []CSRFChain

	snap, err := e.CaptureSession(ctx, baseURL)
	if err != nil {
		return chains
	}

	for _, form := range snap.Forms {
		chain := CSRFChain{
			SourceURL: baseURL,
			TargetURL: form.Action,
			Method:    form.Method,
			Params:    form.Fields,
		}

		for field := range form.Fields {
			lower := strings.ToLower(field)
			if strings.Contains(lower, "csrf") || strings.Contains(lower, "token") ||
				strings.Contains(lower, "nonce") || strings.Contains(lower, "_csrf") {
				chain.HasToken = true
				break
			}
		}

		if !chain.HasToken {
			chain.BypassPossible = true
		}

		chains = append(chains, chain)
	}

	return chains
}

func (e *Engine) LearnUIFlow(ctx context.Context, baseURL string) UIFlow {
	flow := UIFlow{
		Steps: make([]DOMEvent, 0),
	}

	initialSnap, _ := e.CaptureSession(ctx, baseURL)
	if initialSnap == nil {
		return flow
	}

	for _, form := range initialSnap.Forms {
		flow.Steps = append(flow.Steps, DOMEvent{
			Type:     "form_submit",
			Selector: form.Action,
			Value:    fmt.Sprintf("METHOD:%s,FIELDS:%d", form.Method, len(form.Fields)),
			URL:      baseURL,
		})
	}

	flow.Pattern = e.detectUIPattern(flow.Steps)
	flow.Completed = len(flow.Steps) > 0
	return flow
}

func (e *Engine) AutoFillForms(ctx context.Context, baseURL string) ([]DOMEvent, error) {
	snap, err := e.CaptureSession(ctx, baseURL)
	if err != nil {
		return nil, err
	}

	var events []DOMEvent
	for _, form := range snap.Forms {
		if !form.AutoFill {
			continue
		}
		ev := DOMEvent{
			Type:     "autofill",
			Selector: form.Action,
			Value:    fmt.Sprintf("auto-filled %d fields", len(form.Fields)),
			URL:      baseURL,
		}
		events = append(events, ev)
	}
	return events, nil
}

func (e *Engine) EnumerateEndpoints(ctx context.Context, baseURL string) []string {
	snap, err := e.CaptureSession(ctx, baseURL)
	if err != nil {
		return nil
	}
	return snap.Scripts
}

func (e *Engine) injectAndCheck(ctx context.Context, targetURL, payload string, check *StoredXSSCheck) {
	data := url.Values{}
	data.Set("q", payload)
	data.Set("search", payload)
	data.Set("message", payload)

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(data.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Security-Policy", e.cspPolicy)
	if e.auth != nil {
		for name, val := range e.auth.Cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: val})
		}
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	secondReq, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if e.auth != nil {
		for name, val := range e.auth.Cookies {
			secondReq.AddCookie(&http.Cookie{Name: name, Value: val})
		}
	}
	secondReq.Header.Set("Content-Security-Policy", e.cspPolicy)
	secondResp, err := e.client.Do(secondReq)
	if err != nil {
		return
	}
	defer secondResp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(secondResp.Body, maxDOMSize))
	if strings.Contains(string(body), payload) {
		check.Persisted = true
		if check.Evidence == "" {
			check.Evidence = "Payload persisted in server response"
		} else {
			check.Evidence += "; also persisted in server response"
		}
	}
}

func (e *Engine) detectLoginForms(ctx context.Context, targetURL string) []FormInfo {
	snap, err := e.CaptureSession(ctx, targetURL)
	if err != nil {
		return nil
	}

	var loginForms []FormInfo
	for _, form := range snap.Forms {
		hasPassword := false
		hasUsername := false
		for field := range form.Fields {
			lower := strings.ToLower(field)
			if strings.Contains(lower, "pass") {
				hasPassword = true
			}
			if strings.Contains(lower, "user") || strings.Contains(lower, "email") || strings.Contains(lower, "login") {
				hasUsername = true
			}
		}
		bareAction := strings.ToLower(form.Action)
		if (hasPassword && hasUsername) || strings.Contains(bareAction, "login") || strings.Contains(bareAction, "auth") {
			loginForms = append(loginForms, form)
		}
	}
	return loginForms
}

func (e *Engine) tryBasicAuth(ctx context.Context, targetURL, username, password string) (*AuthState, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Security-Policy", e.cspPolicy)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &AuthState{
		LoginURL:     targetURL,
		SessionToken: resp.Header.Get("X-Session-Token"),
		Cookies:      parseCookies(resp.Header),
		LoggedIn:     resp.StatusCode == 200,
	}, nil
}

func (e *Engine) detectDOMMutation(original, current *SessionSnapshot) DOMEvent {
	if original.Title != current.Title {
		return DOMEvent{Type: "title_change", Value: fmt.Sprintf("%s -> %s", original.Title, current.Title)}
	}
	if len(current.Forms) != len(original.Forms) {
		return DOMEvent{Type: "form_change", Value: fmt.Sprintf("forms: %d -> %d", len(original.Forms), len(current.Forms))}
	}
	if len(current.Scripts) != len(original.Scripts) {
		return DOMEvent{Type: "script_change", Value: fmt.Sprintf("scripts: %d -> %d", len(original.Scripts), len(current.Scripts))}
	}
	return DOMEvent{}
}

func (e *Engine) detectUIPattern(steps []DOMEvent) string {
	if len(steps) == 0 {
		return "static"
	}
	hasForm := false
	hasClick := false
	hasNav := false
	for _, s := range steps {
		switch s.Type {
		case "form_submit":
			hasForm = true
		case "click":
			hasClick = true
		case "navigate":
			hasNav = true
		}
	}
	switch {
	case hasForm && hasClick:
		return "form_interaction"
	case hasForm:
		return "form_submission"
	case hasNav:
		return "navigation"
	default:
		return "static"
	}
}

func (e *Engine) Sessions() []*SessionSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	var result []*SessionSnapshot
	for _, s := range e.sessions {
		redacted := *s
		redacted.Cookies = redactSensitiveCookies(redacted.Cookies)
		result = append(result, &redacted)
	}
	return result
}

func (e *Engine) Auth() *AuthState {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.auth == nil {
		return nil
	}
	redacted := *e.auth
	redacted.SessionToken = maskToken(redacted.SessionToken)
	redacted.Cookies = redactSensitiveCookies(redacted.Cookies)
	return &redacted
}

func redactSensitiveCookies(cookies map[string]string) map[string]string {
	redacted := make(map[string]string)
	for k, v := range cookies {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "session") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "auth") || strings.Contains(lower, "jwt") ||
			strings.Contains(lower, "secret") || strings.Contains(lower, "password") {
			redacted[k] = "[REDACTED]"
		} else {
			redacted[k] = v
		}
	}
	return redacted
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return "[REDACTED]"
	}
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x...", h[:4])
}

func extractTitle(html string) string {
	idx := strings.Index(strings.ToLower(html), "<title")
	if idx == -1 {
		return ""
	}
	start := idx + 6
	start = strings.IndexByte(html[start:], '>')
	if start == -1 {
		return ""
	}
	start += idx + 7
	end := strings.Index(html[start:], "</title>")
	if end == -1 {
		return html[start:]
	}
	return strings.TrimSpace(html[start : start+end])
}

func parseCookies(headers http.Header) map[string]string {
	cookies := make(map[string]string)
	for _, c := range headers["Set-Cookie"] {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) == 2 {
			cookies[parts[0]] = strings.SplitN(parts[1], ";", 2)[0]
		}
	}
	return cookies
}

func extractFormsAdvanced(html string) []FormInfo {
	var forms []FormInfo
	for _, block := range strings.Split(html, "<form") {
		if len(block) < 5 {
			continue
		}
		f := FormInfo{
			Action: extractAttr(block, "action"),
			Method: strings.ToUpper(extractAttr(block, "method")),
			Fields: make(map[string]string),
		}
		if f.Method == "" {
			f.Method = "GET"
		}
		for _, input := range strings.Split(block, "<input") {
			if name := extractAttr(input, "name"); name != "" {
				f.Fields[name] = extractAttr(input, "type")
				if f.Fields[name] == "" {
					f.Fields[name] = "text"
				}
				if extractAttr(input, "autofocus") != "" || extractAttr(input, "autocomplete") != "" {
					f.AutoFill = true
				}
			}
		}
		if len(f.Fields) > 0 {
			forms = append(forms, f)
		}
	}
	return forms
}

func extractAllScriptsSafe(html string) []string {
	var scripts []string
	for _, s := range strings.Split(html, "<script") {
		body := extractAttr(s, "src")
		if body != "" {
			if !strings.Contains(body, "javascript:") && !strings.Contains(body, "data:") {
				scripts = append(scripts, body)
			}
		}
	}
	for _, s := range strings.Split(html, "src=\"") {
		if i := strings.Index(s, "\""); i >= 0 {
			src := s[:i]
			if strings.HasPrefix(src, "http") || strings.HasPrefix(src, "//") || strings.HasPrefix(src, "/") {
				if !strings.Contains(src, "javascript:") && !strings.Contains(src, "data:") {
					scripts = append(scripts, src)
				}
			}
		}
	}
	return unique(scripts)
}

func extractAttr(block, attr string) string {
	marker := fmt.Sprintf(`%s="`, attr)
	idx := strings.Index(block, marker)
	if idx == -1 {
		marker = fmt.Sprintf(`%s='`, attr)
		idx = strings.Index(block, marker)
	}
	if idx == -1 {
		return ""
	}
	start := idx + len(marker)
	end := strings.IndexAny(block[start:], `"'`)
	if end == -1 {
		return block[start:]
	}
	return block[start : start+end]
}

func extractSessionToken(cookies []*http.Cookie) string {
	for _, c := range cookies {
		lower := strings.ToLower(c.Name)
		if strings.Contains(lower, "session") || strings.Contains(lower, "token") || strings.Contains(lower, "auth") || strings.Contains(lower, "jwt") {
			return c.Value
		}
	}
	return ""
}

func unique(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
