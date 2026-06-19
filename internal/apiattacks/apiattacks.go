package apiattacks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/security"
)

type Endpoint struct {
	Path       string            `json:"path"`
	Method     string            `json:"method"`
	Params     map[string]string `json:"params"`
	AuthType   string            `json:"auth_type"`
	BodySchema string            `json:"body_schema"`
}

type APISchema struct {
	BaseURL   string     `json:"base_url"`
	Endpoints []Endpoint `json:"endpoints"`
	AuthType  string     `json:"auth_type"`
}

type TestResult struct {
	Endpoint   string `json:"endpoint"`
	Test       string `json:"test"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
	Severity   string `json:"severity"`
}

type Engine struct {
	mu           sync.Mutex
	client       *http.Client
	schema       *APISchema
	results      []TestResult
	allowedHosts []string
}

func New() *Engine {
	return &Engine{
		client:  &http.Client{Timeout: 30 * time.Second},
		results: make([]TestResult, 0),
	}
}

func (e *Engine) SetAllowedHosts(hosts []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowedHosts = hosts
}

func (e *Engine) isInScope(targetURL string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.allowedHosts) == 0 {
		return true
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	for _, allowed := range e.allowedHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

func (e *Engine) IngestOpenAPI(ctx context.Context, specURL string) (*APISchema, error) {
	if !e.isInScope(specURL) {
		return nil, fmt.Errorf("spec URL %s is out of scope", specURL)
	}
	if verdict := security.GetK().ValidateAction(ctx, security.ActionRequest{
		Type:   security.ActionHTTPRequest,
		URL:    specURL,
		Source: "apiattacks.IngestOpenAPI",
	}); verdict.Decision != security.DecisionAllow {
		return nil, fmt.Errorf("kernel denied spec URL: %s", verdict.Reason)
	}
	resp, err := e.client.Get(specURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch spec: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}

	var spec struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name     string `json:"name"`
				In       string `json:"in"`
				Required bool   `json:"required"`
			} `json:"parameters"`
			RequestBody struct {
				Content map[string]struct {
					Schema json.RawMessage `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}

	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	baseURL := ""
	if len(spec.Servers) > 0 {
		baseURL = spec.Servers[0].URL
	}

	schema := &APISchema{BaseURL: baseURL}

	for path, methods := range spec.Paths {
		for method, details := range methods {
			ep := Endpoint{
				Path:   path,
				Method: strings.ToUpper(method),
				Params: make(map[string]string),
			}
			for _, p := range details.Parameters {
				ep.Params[p.Name] = p.In
			}
			if details.RequestBody.Content != nil {
				ep.BodySchema = "json"
			}
			schema.Endpoints = append(schema.Endpoints, ep)
		}
	}

	sort.Slice(schema.Endpoints, func(i, j int) bool {
		if schema.Endpoints[i].Path != schema.Endpoints[j].Path {
			return schema.Endpoints[i].Path < schema.Endpoints[j].Path
		}
		return schema.Endpoints[i].Method < schema.Endpoints[j].Method
	})

	e.mu.Lock()
	e.schema = schema
	e.mu.Unlock()
	return schema, nil
}

func (e *Engine) IntrospectGraphQL(ctx context.Context, endpoint string) (*APISchema, error) {
	if !e.isInScope(endpoint) {
		return nil, fmt.Errorf("endpoint %s is out of scope", endpoint)
	}
	if err := security.ValidateURL(endpoint); err != nil {
		return nil, fmt.Errorf("endpoint validation failed: %w", err)
	}
	query := `{"query":"query { __schema { types { name fields { name args { name } } } } }"}`
	resp, err := e.client.Post(endpoint, "application/json", strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("graphql introspection failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	var result struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
						} `json:"args"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse GraphQL response: %w", err)
	}

	schema := &APISchema{BaseURL: endpoint}
	for _, t := range result.Data.Schema.Types {
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		for _, f := range t.Fields {
			ep := Endpoint{
				Path:   fmt.Sprintf("%s.%s", t.Name, f.Name),
				Method: "POST",
				Params: make(map[string]string),
			}
			for _, a := range f.Args {
				ep.Params[a.Name] = "query"
			}
			schema.Endpoints = append(schema.Endpoints, ep)
		}
	}

	e.mu.Lock()
	e.schema = schema
	e.mu.Unlock()
	return schema, nil
}

func (e *Engine) TestIDOR(ctx context.Context, baseURL string, endpoints []Endpoint) []TestResult {
	if !e.isInScope(baseURL) {
		return nil
	}
	var results []TestResult
	for _, ep := range endpoints {
		testURL := fmt.Sprintf("%s%s", strings.TrimRight(baseURL, "/"), ep.Path)

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		originalResp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		originalID := extractID(originalResp.Request.URL.String())
		originalResp.Body.Close()

		if originalID == "" {
			continue
		}

		alteredID := alterID(originalID)
		alteredURL := strings.Replace(testURL, originalID, alteredID, 1)

		altReq, err := http.NewRequestWithContext(ctx, "GET", alteredURL, nil)
		if err != nil {
			continue
		}
		alteredResp, err := e.client.Do(altReq)
		if err != nil {
			continue
		}
		if alteredResp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(alteredResp.Body, 4096))
			results = append(results, TestResult{
				Endpoint:   testURL,
				Test:       "idor",
				Vulnerable: true,
				Evidence:   fmt.Sprintf("Accessed %s as different user, got 200 with %d bytes", alteredURL, len(body)),
				Severity:   "high",
			})
		}
	}
	return results
}

func (e *Engine) TestMassAssignment(ctx context.Context, baseURL string, endpoints []Endpoint) []TestResult {
	if !e.isInScope(baseURL) {
		return nil
	}
	var results []TestResult
	for _, ep := range endpoints {
		if ep.Method != "POST" && ep.Method != "PUT" {
			continue
		}
		payload := `{"admin":true,"role":"admin","is_admin":true,"permissions":"*"}`
		testURL := fmt.Sprintf("%s%s", strings.TrimRight(baseURL, "/"), ep.Path)
		req, err := http.NewRequestWithContext(ctx, ep.Method, testURL, strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			bodyStr := string(body)
			if strings.Contains(bodyStr, `"admin":true`) || strings.Contains(bodyStr, `"role":"admin"`) {
				results = append(results, TestResult{
					Endpoint:   testURL,
					Test:       "mass_assignment",
					Vulnerable: true,
					Evidence:   "Admin role/privilege accepted via mass assignment",
					Severity:   "critical",
				})
			}
		}
	}
	return results
}

func (e *Engine) TestRateLimitBypass(ctx context.Context, baseURL string, path string, authorized bool) []TestResult {
	if !e.isInScope(baseURL) {
		return nil
	}
	var results []TestResult
	if !authorized {
		return nil
	}
	testURL := fmt.Sprintf("%s%s", strings.TrimRight(baseURL, "/"), path)
	if err := security.ValidateURL(testURL); err != nil {
		return nil
	}

	headers := []map[string]string{
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Forwarded-For": "10.0.0.1"},
		{"X-Real-IP": "127.0.0.1"},
		{"CF-Connecting-IP": "127.0.0.1"},
		{"True-Client-IP": "127.0.0.1"},
		{"X-Originating-IP": "127.0.0.1"},
		{"X-Remote-IP": "127.0.0.1"},
		{"X-Client-IP": "127.0.0.1"},
	}

	for _, h := range headers {
		for k, v := range h {
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set(k, v)
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				results = append(results, TestResult{
					Endpoint:   testURL,
					Test:       fmt.Sprintf("rate_limit_bypass via %s", k),
					Vulnerable: true,
					Evidence:   fmt.Sprintf("Bypassed rate limit using header %s: %s", k, v),
					Severity:   "medium",
				})
				break
			}
		}
	}
	return results
}

func (e *Engine) Schema() *APISchema {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.schema
}

func (e *Engine) Results() []TestResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]TestResult, len(e.results))
	copy(result, e.results)
	return result
}

func extractID(url string) string {
	parts := strings.Split(strings.TrimRight(url, "/"), "/")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		if len(last) >= 8 && len(last) <= 64 {
			return last
		}
	}
	return ""
}

func alterID(id string) string {
	if len(id) <= 1 {
		return "1"
	}
	if id[0] >= '0' && id[0] <= '9' {
		newID := string(id[0]+1) + id[1:]
		if newID != id {
			return newID
		}
		return "1" + id[1:]
	}
	return "other-" + id
}
