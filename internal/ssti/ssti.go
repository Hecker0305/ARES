package ssti

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Finding struct {
	URL       string    `json:"url"`
	Engine    string    `json:"engine"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	Severity  string    `json:"severity"`
	Confirmed bool      `json:"confirmed"`
	Timestamp time.Time `json:"timestamp"`
}

type TemplateEngine string

const (
	EngineJinja2     TemplateEngine = "jinja2"
	EngineTwig       TemplateEngine = "twig"
	EngineFreemarker TemplateEngine = "freemarker"
	EnginePebble     TemplateEngine = "pebble"
	EngineERB        TemplateEngine = "erb"
)

var allowedEngines = map[TemplateEngine]bool{
	EngineJinja2:     true,
	EngineTwig:       true,
	EngineFreemarker: true,
	EnginePebble:     true,
	EngineERB:        true,
}

var dangerousDirectives = []*regexp.Regexp{
	regexp.MustCompile(`(?i)__import__`),
	regexp.MustCompile(`(?i)\.popen\(`),
	regexp.MustCompile(`(?i)\.system\(`),
	regexp.MustCompile(`(?i)\.exec\(`),
	regexp.MustCompile(`(?i)\.eval\(`),
	regexp.MustCompile(`(?i)os\.path`),
	regexp.MustCompile(`(?i)subprocess`),
	regexp.MustCompile(`(?i)registerUndefinedFilterCallback`),
	regexp.MustCompile(`(?i)freemarker\.template\.utility\.Execute`),
}

type Engine struct {
	client      *http.Client
	oobDomain   string
	allowed     map[TemplateEngine]bool
	sandboxMode bool
	rateLimiter chan struct{}
}

func NewEngine(oobDomain string) *Engine {
	return &Engine{
		client:      &http.Client{Timeout: 15 * time.Second},
		oobDomain:   oobDomain,
		allowed:     make(map[TemplateEngine]bool),
		sandboxMode: true,
		rateLimiter: make(chan struct{}, 10),
	}
}

func (e *Engine) SetAllowedEngines(engines []TemplateEngine) {
	e.allowed = make(map[TemplateEngine]bool)
	for _, eng := range engines {
		if allowedEngines[eng] {
			e.allowed[eng] = true
		}
	}
}

func (e *Engine) SetSandboxMode(enabled bool) {
	e.sandboxMode = enabled
}

func (e *Engine) isEngineAllowed(engine TemplateEngine) bool {
	if len(e.allowed) == 0 {
		return true
	}
	return e.allowed[engine]
}

func (e *Engine) sanitizePayload(payload string) string {
	if e.sandboxMode {
		for _, pattern := range dangerousDirectives {
			if pattern.MatchString(payload) {
				return "[SANDBOX: dangerous directive blocked]"
			}
		}
	}
	return payload
}

func (e *Engine) getSafePayloads(engine TemplateEngine) []sstiPayload {
	if !e.isEngineAllowed(engine) {
		return nil
	}

	switch engine {
	case EngineJinja2:
		return []sstiPayload{
			{engine: "jinja2", payload: "{{7*7}}", expected: "49"},
			{engine: "jinja2", payload: "{{config}}", expected: "config"},
			{engine: "jinja2", payload: "{{self}}", expected: "TemplateReference"},
		}
	case EngineTwig:
		return []sstiPayload{
			{engine: "twig", payload: "{{7*7}}", expected: "49"},
			{engine: "twig", payload: "{{app.request.query.all}}", expected: "query"},
		}
	case EngineFreemarker:
		return []sstiPayload{
			{engine: "freemarker", payload: "${7*7}", expected: "49"},
			{engine: "freemarker", payload: "${.version}", expected: "version"},
		}
	case EnginePebble:
		return []sstiPayload{
			{engine: "pebble", payload: "{{7*7}}", expected: "49"},
			{engine: "pebble", payload: "{{pebble}}", expected: "pebble"},
			{engine: "pebble", payload: "{{user}}", expected: "user"},
		}
	case EngineERB:
		return []sstiPayload{
			{engine: "erb", payload: "<%= 7*7 %>", expected: "49"},
		}
	default:
		return nil
	}
}

type sstiPayload struct {
	engine   string
	payload  string
	expected string
}

func (e *Engine) TestAll(target string) ([]Finding, error) {
	var findings []Finding

	engines := []TemplateEngine{EngineJinja2, EngineTwig, EngineFreemarker, EnginePebble, EngineERB}

	for _, engine := range engines {
		payloadSet := e.getSafePayloads(engine)
		for _, p := range payloadSet {
			safePayload := e.sanitizePayload(p.payload)
			if strings.HasPrefix(safePayload, "[SANDBOX:") {
				continue
			}
			f, err := e.testPayload(target, p)
			if err == nil && f != nil {
				findings = append(findings, *f)
				break
			}
		}
	}

	return findings, nil
}

func (e *Engine) TestGET(target, paramName string) ([]Finding, error) {
	var findings []Finding

	engines := []TemplateEngine{EngineJinja2, EngineTwig, EngineFreemarker, EnginePebble, EngineERB}

	for _, engine := range engines {
		payloadSet := e.getSafePayloads(engine)
		for _, p := range payloadSet {
			safePayload := e.sanitizePayload(p.payload)
			if strings.HasPrefix(safePayload, "[SANDBOX:") {
				continue
			}

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(paramName, p.payload)
			u.RawQuery = q.Encode()

			f, err := e.testURL(u.String(), p)
			if err == nil && f != nil {
				findings = append(findings, *f)
				break
			}
		}
	}

	return findings, nil
}

func (e *Engine) TestPOST(target string, paramName string) ([]Finding, error) {
	var findings []Finding

	engines := []TemplateEngine{EngineJinja2, EngineTwig, EngineFreemarker, EnginePebble, EngineERB}

	for _, engine := range engines {
		payloadSet := e.getSafePayloads(engine)
		for _, p := range payloadSet {
			safePayload := e.sanitizePayload(p.payload)
			if strings.HasPrefix(safePayload, "[SANDBOX:") {
				continue
			}

			data := url.Values{}
			data.Set(paramName, p.payload)

			req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			f, err := e.testRequest(req, p)
			if err == nil && f != nil {
				findings = append(findings, *f)
				break
			}
		}
	}

	return findings, nil
}

func (e *Engine) TestJSON(target string, paramName string) ([]Finding, error) {
	var findings []Finding

	engines := []TemplateEngine{EngineJinja2, EngineTwig, EngineFreemarker, EnginePebble, EngineERB}

	for _, engine := range engines {
		payloadSet := e.getSafePayloads(engine)
		for _, p := range payloadSet {
			safePayload := e.sanitizePayload(p.payload)
			if strings.HasPrefix(safePayload, "[SANDBOX:") {
				continue
			}

			body := fmt.Sprintf(`{"%s":"%s"}`, paramName, p.payload)
			req, err := http.NewRequest("POST", target, strings.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			f, err := e.testRequest(req, p)
			if err == nil && f != nil {
				findings = append(findings, *f)
				break
			}
		}
	}

	return findings, nil
}

func (e *Engine) TestOOB(target string) (*Finding, error) {
	if e.oobDomain == "" {
		return nil, fmt.Errorf("OOB domain not configured")
	}

	payload := fmt.Sprintf("{{request.session.__class__.__mro__[1].__subclasses__()[40]('%s').read()}}", e.oobDomain)

	safePayload := e.sanitizePayload(payload)
	if strings.HasPrefix(safePayload, "[SANDBOX:") {
		return &Finding{
			URL:       target,
			Engine:    "jinja2-oob",
			Payload:   "[SANDBOX: OOB payload blocked]",
			Evidence:  fmt.Sprintf("OOB callback expected at %s (payload blocked by sandbox)", e.oobDomain),
			Severity:  "critical",
			Confirmed: false,
			Timestamp: time.Now(),
		}, nil
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &Finding{
		URL:       target,
		Engine:    "jinja2-oob",
		Payload:   "[REDACTED: OOB payload]",
		Evidence:  fmt.Sprintf("OOB callback expected at %s", e.oobDomain),
		Severity:  "critical",
		Confirmed: false,
		Timestamp: time.Now(),
	}, nil
}

func (e *Engine) testPayload(target string, p sstiPayload) (*Finding, error) {
	safePayload := e.sanitizePayload(p.payload)
	if strings.HasPrefix(safePayload, "[SANDBOX:") {
		return nil, fmt.Errorf("payload blocked by sandbox mode")
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(p.payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	return e.testRequest(req, p)
}

func (e *Engine) testURL(target string, p sstiPayload) (*Finding, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}

	return e.testRequest(req, p)
}

func (e *Engine) testRequest(req *http.Request, p sstiPayload) (*Finding, error) {
	select {
	case e.rateLimiter <- struct{}{}:
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("rate limit exceeded")
	}
	defer func() { <-e.rateLimiter }()

	req.Header.Set("User-Agent", "ARES-SSTI/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if e.detectSSTI(string(body), p) {
		return &Finding{
			URL:       req.URL.String(),
			Engine:    p.engine,
			Payload:   "[sanitized]",
			Evidence:  string(body)[:minInt(len(body), 500)],
			Severity:  "high",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no SSTI detected")
}

func (e *Engine) detectSSTI(responseBody string, p sstiPayload) bool {
	body := strings.ToLower(responseBody)

	if p.expected != "" && strings.Contains(body, p.expected) {
		return true
	}

	if strings.Contains(body, "template") && strings.Contains(body, "error") {
		return true
	}

	if strings.Contains(body, "jinja") || strings.Contains(body, "twig") ||
		strings.Contains(body, "freemarker") || strings.Contains(body, "pebble") {
		return true
	}

	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
