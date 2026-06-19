package apiattacks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ares/engine/internal/security"
)

type testKernel struct {
	decision security.Decision
}

func (k *testKernel) ValidateAction(_ context.Context, req security.ActionRequest) security.Verdict {
	return security.Verdict{
		Decision:  k.decision,
		Action:    req.Type,
		Timestamp: time.Now(),
		Source:    req.Source,
	}
}

type rewriteTransport struct {
	target string
	rt     http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	targetURL, _ := url.Parse(t.target)
	req.URL.Host = targetURL.Host
	req.URL.Scheme = targetURL.Scheme
	req.Host = targetURL.Host
	return t.rt.RoundTrip(req)
}

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", e.client.Timeout)
	}
	if e.results == nil {
		t.Error("results slice should be non-nil")
	}
	if e.schema != nil {
		t.Error("schema should be nil initially")
	}
}

func TestSchema_Nil(t *testing.T) {
	e := New()
	if s := e.Schema(); s != nil {
		t.Error("expected nil schema")
	}
}

func TestResults_Empty(t *testing.T) {
	e := New()
	r := e.Results()
	if len(r) != 0 {
		t.Errorf("expected 0 results, got %d", len(r))
	}
}

func TestExtractID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"root", "/", ""},
		{"too short", "/abc", ""},
		{"exact 8 chars", "/abcdefgh", "abcdefgh"},
		{"exact 64 chars", "/" + strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"over 64 chars", "/" + strings.Repeat("a", 65), ""},
		{"nested path", "/api/v1/users/12345678", "12345678"},
		{"no trailing slash", "/users/12345678", "12345678"},
		{"full URL", "http://example.com/users/12345678", "12345678"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractID(tt.input)
			if got != tt.want {
				t.Errorf("extractID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAlterID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "1"},
		{"single char", "a", "1"},
		{"single digit", "1", "1"},
		{"numeric start low", "12345", "22345"},
		{"numeric start nine", "92345", ":2345"},
		{"non-numeric start", "abcd", "other-abcd"},
		{"mixed start alpha", "abc123", "other-abc123"},
		{"zero start", "01234", "11234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := alterID(tt.input)
			if got != tt.want {
				t.Errorf("alterID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEndpoint_JSON(t *testing.T) {
	ep := Endpoint{
		Path:       "/api/users",
		Method:     "GET",
		Params:     map[string]string{"id": "query"},
		AuthType:   "bearer",
		BodySchema: "json",
	}
	data, err := json.Marshal(ep)
	if err != nil {
		t.Fatal(err)
	}
	var got Endpoint
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Path != ep.Path || got.Method != ep.Method || got.AuthType != ep.AuthType {
		t.Error("JSON round-trip mismatch")
	}
}

func TestAPISchema_JSON(t *testing.T) {
	s := APISchema{
		BaseURL: "http://example.com",
		Endpoints: []Endpoint{
			{Path: "/users", Method: "GET", Params: map[string]string{"id": "query"}},
		},
		AuthType: "oauth2",
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var got APISchema
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.BaseURL != s.BaseURL || len(got.Endpoints) != 1 || got.AuthType != s.AuthType {
		t.Error("JSON round-trip mismatch")
	}
}

func TestTestResult_JSON(t *testing.T) {
	tr := TestResult{
		Endpoint:   "/api/users",
		Test:       "idor",
		Vulnerable: true,
		Evidence:   "got 200",
		Severity:   "high",
	}
	data, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	var got TestResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Endpoint != tr.Endpoint || got.Test != tr.Test || got.Vulnerable != tr.Vulnerable {
		t.Error("JSON round-trip mismatch")
	}
}

func TestEndpoint_NilParams(t *testing.T) {
	ep := Endpoint{Path: "/test", Method: "POST"}
	if ep.Params != nil {
		t.Error("expected nil params")
	}
}

func TestIngestOpenAPI_Success(t *testing.T) {
	security.SetKernel(&testKernel{decision: security.DecisionAllow})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"servers":[{"url":"http://api.example.com"}],
			"paths":{
				"/users":{
					"get":{
						"parameters":[{"name":"id","in":"query","required":true}]
					},
					"post":{
						"requestBody":{
							"content":{"application/json":{"schema":{"type":"object"}}}
						}
					}
				},
				"/admin":{
					"delete":{
						"security":[{"apiKey":[]}]
					}
				}
			}
		}`)
	}))
	defer srv.Close()

	e := New()
	schema, err := e.IngestOpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("IngestOpenAPI failed: %v", err)
	}
	if schema.BaseURL != "http://api.example.com" {
		t.Errorf("expected base URL http://api.example.com, got %s", schema.BaseURL)
	}
	if len(schema.Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(schema.Endpoints))
	}
	var getUsers, postUsers *Endpoint
	for i := range schema.Endpoints {
		ep := &schema.Endpoints[i]
		if ep.Path == "/users" && ep.Method == "GET" {
			getUsers = ep
		}
		if ep.Path == "/users" && ep.Method == "POST" {
			postUsers = ep
		}
	}
	if getUsers == nil {
		t.Fatal("expected GET /users endpoint")
	}
	if v, ok := getUsers.Params["id"]; !ok || v != "query" {
		t.Errorf("expected param id=query, got id=%s (ok=%v)", v, ok)
	}
	if postUsers == nil {
		t.Fatal("expected POST /users endpoint")
	}
	if postUsers.BodySchema != "json" {
		t.Error("expected body_schema=json for POST /users")
	}
	// Verify engine stored the schema
	if e.Schema() == nil {
		t.Error("engine schema should not be nil after IngestOpenAPI")
	}
}

func TestIngestOpenAPI_KernelDeny(t *testing.T) {
	security.SetKernel(&testKernel{decision: security.DecisionDeny})

	e := New()
	_, err := e.IngestOpenAPI(context.Background(), "http://example.com/spec.json")
	if err == nil {
		t.Fatal("expected error from kernel deny")
	}
	if !strings.Contains(err.Error(), "kernel denied") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestIngestOpenAPI_InvalidJSON(t *testing.T) {
	security.SetKernel(&testKernel{decision: security.DecisionAllow})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `this is not json`)
	}))
	defer srv.Close()

	e := New()
	_, err := e.IngestOpenAPI(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestIngestOpenAPI_NetworkError(t *testing.T) {
	security.SetKernel(&testKernel{decision: security.DecisionAllow})

	e := New()
	_, err := e.IngestOpenAPI(context.Background(), "http://127.0.0.1:1/openapi.json")
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestIngestOpenAPI_NoServers(t *testing.T) {
	security.SetKernel(&testKernel{decision: security.DecisionAllow})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"paths":{"/test":{"get":{"parameters":[]}}}}`)
	}))
	defer srv.Close()

	e := New()
	schema, err := e.IngestOpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schema.BaseURL != "" {
		t.Errorf("expected empty base URL when no servers, got %s", schema.BaseURL)
	}
	if len(schema.Endpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(schema.Endpoints))
	}
}

func TestIngestOpenAPI_EmptyPaths(t *testing.T) {
	security.SetKernel(&testKernel{decision: security.DecisionAllow})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"servers":[{"url":"http://example.com"}],"paths":{}}`)
	}))
	defer srv.Close()

	e := New()
	schema, err := e.IngestOpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(schema.Endpoints) != 0 {
		t.Errorf("expected 0 endpoints, got %d", len(schema.Endpoints))
	}
}

func TestIntrospectGraphQL_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"data":{
				"__schema":{
					"types":[
						{
							"name":"Query",
							"fields":[
								{"name":"user","args":[{"name":"id"},{"name":"name"}]},
								{"name":"posts","args":null}
							]
						},
						{
							"name":"Mutation",
							"fields":[
								{"name":"createUser","args":[{"name":"input"}]}
							]
						},
						{
							"name":"__Type",
							"fields":[{"name":"kind","args":null}]
						}
					]
				}
			}
		}`)
	}))
	defer srv.Close()

	e := New()
	e.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{target: srv.URL, rt: http.DefaultTransport},
	}

	schema, err := e.IntrospectGraphQL(context.Background(), "http://example.com/graphql")
	if err != nil {
		t.Fatalf("IntrospectGraphQL failed: %v", err)
	}
	if schema.BaseURL != "http://example.com/graphql" {
		t.Errorf("expected base URL http://example.com/graphql, got %s", schema.BaseURL)
	}
	// Query type has 2 fields, Mutation has 1 field, __Type is skipped
	if len(schema.Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(schema.Endpoints))
	}
	if schema.Endpoints[0].Path != "Query.user" {
		t.Errorf("expected Query.user, got %s", schema.Endpoints[0].Path)
	}
	if v, ok := schema.Endpoints[0].Params["id"]; !ok || v != "query" {
		t.Errorf("expected param id=query, got id=%s (ok=%v)", v, ok)
	}
	if e.Schema() == nil {
		t.Error("engine schema should be set after IntrospectGraphQL")
	}
}

func TestIntrospectGraphQL_EmptyEndpoint(t *testing.T) {
	e := New()
	_, err := e.IntrospectGraphQL(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestIntrospectGraphQL_InvalidURL(t *testing.T) {
	e := New()
	_, err := e.IntrospectGraphQL(context.Background(), "://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestIntrospectGraphQL_InvalidScheme(t *testing.T) {
	e := New()
	_, err := e.IntrospectGraphQL(context.Background(), "ftp://example.com/graphql")
	if err == nil {
		t.Fatal("expected error for invalid scheme")
	}
}

func TestIntrospectGraphQL_InvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `this is not valid json`)
	}))
	defer srv.Close()

	e := New()
	e.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{target: srv.URL, rt: http.DefaultTransport},
	}

	_, err := e.IntrospectGraphQL(context.Background(), "http://example.com/graphql")
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestIntrospectGraphQL_NoTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"__schema":{"types":[]}}}`)
	}))
	defer srv.Close()

	e := New()
	e.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{target: srv.URL, rt: http.DefaultTransport},
	}

	schema, err := e.IntrospectGraphQL(context.Background(), "http://example.com/graphql")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(schema.Endpoints) != 0 {
		t.Errorf("expected 0 endpoints, got %d", len(schema.Endpoints))
	}
}

func TestIntrospectGraphQL_AllIntrospectionTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"data":{
				"__schema":{
					"types":[
						{"name":"__Type","fields":[{"name":"kind","args":null}]},
						{"name":"__Schema","fields":[{"name":"types","args":null}]}
					]
				}
			}
		}`)
	}))
	defer srv.Close()

	e := New()
	e.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{target: srv.URL, rt: http.DefaultTransport},
	}

	schema, err := e.IntrospectGraphQL(context.Background(), "http://example.com/graphql")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All types start with __, so none should be in endpoints
	if len(schema.Endpoints) != 0 {
		t.Errorf("expected 0 endpoints (all __ types skipped), got %d", len(schema.Endpoints))
	}
}

func TestIDOR_Vulnerable(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users/12345678", Method: "GET"},
	}
	results := e.TestIDOR(context.Background(), srv.URL, endpoints)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Test != "idor" {
		t.Errorf("expected test=idor, got %s", results[0].Test)
	}
	if !results[0].Vulnerable {
		t.Error("expected vulnerable=true")
	}
	if results[0].Severity != "high" {
		t.Errorf("expected severity=high, got %s", results[0].Severity)
	}
	if len(requests) != 2 {
		t.Errorf("expected 2 requests, got %d", len(requests))
	}
}

func TestIDOR_NotVulnerable(t *testing.T) {
	var requestNum int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestNum++
		if requestNum == 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users/12345678", Method: "GET"},
	}
	results := e.TestIDOR(context.Background(), srv.URL, endpoints)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestIDOR_EmptyEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New()
	results := e.TestIDOR(context.Background(), srv.URL, []Endpoint{})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty endpoints, got %d", len(results))
	}
}

func TestIDOR_ShortID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New()
	// Short ID (< 8 chars) should be skipped by extractID
	endpoints := []Endpoint{
		{Path: "/api/users/abc", Method: "GET"},
	}
	results := e.TestIDOR(context.Background(), srv.URL, endpoints)
	if len(results) != 0 {
		t.Errorf("expected 0 results for short ID, got %d", len(results))
	}
}

func TestIDOR_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users/12345678", Method: "GET"},
	}
	results := e.TestIDOR(ctx, srv.URL, endpoints)
	if len(results) != 0 {
		t.Errorf("expected 0 results with cancelled context, got %d", len(results))
	}
}

func TestMassAssignment_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"admin":true,"role":"admin","message":"created"}`)
	}))
	defer srv.Close()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users", Method: "POST"},
	}
	results := e.TestMassAssignment(context.Background(), srv.URL, endpoints)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Test != "mass_assignment" {
		t.Errorf("expected test=mass_assignment, got %s", results[0].Test)
	}
	if !results[0].Vulnerable {
		t.Error("expected vulnerable=true")
	}
	if results[0].Severity != "critical" {
		t.Errorf("expected severity=critical, got %s", results[0].Severity)
	}
}

func TestMassAssignment_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":1,"name":"test"}`)
	}))
	defer srv.Close()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users", Method: "POST"},
	}
	results := e.TestMassAssignment(context.Background(), srv.URL, endpoints)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestMassAssignment_NonPostMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"admin":true}`)
	}))
	defer srv.Close()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users", Method: "GET"},
		{Path: "/api/users", Method: "DELETE"},
		{Path: "/api/users", Method: "PATCH"},
	}
	results := e.TestMassAssignment(context.Background(), srv.URL, endpoints)
	if len(results) != 0 {
		t.Errorf("expected 0 results for non-POST/PUT endpoints, got %d", len(results))
	}
}

func TestMassAssignment_PUTMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"admin":true,"message":"created"}`)
	}))
	defer srv.Close()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users", Method: "PUT"},
	}
	results := e.TestMassAssignment(context.Background(), srv.URL, endpoints)
	if len(results) != 1 {
		t.Fatalf("expected 1 result for PUT, got %d", len(results))
	}
	if !results[0].Vulnerable {
		t.Error("expected vulnerable=true for PUT admin field")
	}
}

func TestMassAssignment_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"bad request"}`)
	}))
	defer srv.Close()

	e := New()
	endpoints := []Endpoint{
		{Path: "/api/users", Method: "POST"},
	}
	results := e.TestMassAssignment(context.Background(), srv.URL, endpoints)
	if len(results) != 0 {
		t.Errorf("expected 0 results for non-2xx response, got %d", len(results))
	}
}

func TestMassAssignment_EmptyEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New()
	results := e.TestMassAssignment(context.Background(), srv.URL, []Endpoint{})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty endpoints, got %d", len(results))
	}
}

func TestRateLimitBypass_Unauthorized(t *testing.T) {
	e := New()
	results := e.TestRateLimitBypass(context.Background(), "http://example.com", "/api/data", false)
	if len(results) != 0 {
		t.Errorf("expected 0 results for unauthorized, got %d", len(results))
	}
}

func TestRateLimitBypass_InvalidURL(t *testing.T) {
	e := New()
	results := e.TestRateLimitBypass(context.Background(), "://invalid", "/path", true)
	if len(results) != 0 {
		t.Errorf("expected 0 results for invalid URL, got %d", len(results))
	}
}

func TestRateLimitBypass_BlockedHost(t *testing.T) {
	e := New()
	results := e.TestRateLimitBypass(context.Background(), "http://169.254.169.254", "/latest/meta-data", true)
	if len(results) != 0 {
		t.Errorf("expected 0 results for blocked host, got %d", len(results))
	}
}

func TestRateLimitBypass_EmptyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New()
	e.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{target: srv.URL, rt: http.DefaultTransport},
	}
	results := e.TestRateLimitBypass(context.Background(), "http://example.com", "", true)
	// Empty path after TrimRight gives testURL = "http://example.com"
	// Since all header-spoofed requests return 200, at least one result expected
	if len(results) == 0 {
		t.Error("expected at least one result with empty path")
	}
}

func TestRateLimitBypass_AllHeaders(t *testing.T) {
	var mu sync.Mutex
	requestHeaders := make([]string, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestHeaders = append(requestHeaders, r.Header.Get("X-Forwarded-For"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New()
	e.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{target: srv.URL, rt: http.DefaultTransport},
	}

	results := e.TestRateLimitBypass(context.Background(), "http://example.com", "/api/data", true)
	if len(results) == 0 {
		t.Fatal("expected at least one rate limit bypass result")
	}
	if !results[0].Vulnerable {
		t.Error("expected vulnerable=true")
	}
	if results[0].Severity != "medium" {
		t.Errorf("expected severity=medium, got %s", results[0].Severity)
	}
}

func TestRateLimitBypass_NoBypassHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := New()
	e.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &rewriteTransport{target: srv.URL, rt: http.DefaultTransport},
	}

	results := e.TestRateLimitBypass(context.Background(), "http://example.com", "/api/data", true)
	if len(results) != 0 {
		t.Errorf("expected 0 results when all requests return 429, got %d", len(results))
	}
}

func TestResults_ThreadSafety(t *testing.T) {
	e := New()
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			e.results = append(e.results, TestResult{Endpoint: fmt.Sprintf("/test/%d", i)})
		}
		done <- true
	}()
	for i := 0; i < 100; i++ {
		_ = e.Results()
	}
	<-done
}

func TestSchema_ThreadSafety(t *testing.T) {
	e := New()
	done := make(chan bool)
	go func() {
		e.mu.Lock()
		e.schema = &APISchema{BaseURL: "http://example.com"}
		e.mu.Unlock()
		done <- true
	}()
	for i := 0; i < 50; i++ {
		_ = e.Schema()
	}
	<-done
}

func TestMultipleTestResults(t *testing.T) {
	e := New()
	e.results = []TestResult{
		{Endpoint: "/a", Test: "sql", Vulnerable: true, Evidence: "error", Severity: "critical"},
		{Endpoint: "/b", Test: "xss", Vulnerable: false, Evidence: "", Severity: "low"},
	}
	r := e.Results()
	if len(r) != 2 {
		t.Fatalf("expected 2 results, got %d", len(r))
	}
	if !r[0].Vulnerable || r[1].Vulnerable {
		t.Error("unexpected vulnerable values")
	}
}

func TestEndpointDefaultValues(t *testing.T) {
	ep := Endpoint{}
	if ep.Path != "" {
		t.Error("expected empty path")
	}
	if ep.Params != nil {
		t.Error("expected nil params")
	}
}

func TestAPISchemaDefaultValues(t *testing.T) {
	s := APISchema{}
	if s.BaseURL != "" {
		t.Error("expected empty base URL")
	}
	if s.Endpoints != nil {
		t.Error("expected nil endpoints")
	}
}

func TestTestResultDefaultValues(t *testing.T) {
	tr := TestResult{}
	if tr.Vulnerable {
		t.Error("expected vulnerable=false")
	}
}

func TestExtractID_TrailingSlash(t *testing.T) {
	got := extractID("/users/12345678/")
	if got != "12345678" {
		t.Errorf("expected 12345678, got %q", got)
	}
}

func TestAlterID_EmptyString(t *testing.T) {
	got := alterID("")
	if got != "1" {
		t.Errorf("expected 1, got %s", got)
	}
}

func TestAlterID_SingleDigit(t *testing.T) {
	got := alterID("1")
	if got != "1" {
		t.Errorf("expected 1, got %s", got)
	}
	got = alterID("9")
	if got != "1" {
		t.Errorf("expected 1, got %s", got)
	}
}

func TestAlterID_NinePrefix(t *testing.T) {
	got := alterID("99999")
	if got != ":9999" {
		t.Errorf("expected :9999, got %s", got)
	}
}
