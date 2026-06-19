package apidiscovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ares/engine/internal/scanctx"
)

func TestAuthTypeConstants(t *testing.T) {
	if AuthNone != "none" {
		t.Errorf("AuthNone = %q, want none", AuthNone)
	}
	if AuthBasic != "basic" {
		t.Errorf("AuthBasic = %q, want basic", AuthBasic)
	}
	if AuthBearer != "bearer" {
		t.Errorf("AuthBearer = %q, want bearer", AuthBearer)
	}
	if AuthAPIKey != "api_key" {
		t.Errorf("AuthAPIKey = %q, want api_key", AuthAPIKey)
	}
	if AuthOAuth2 != "oauth2" {
		t.Errorf("AuthOAuth2 = %q, want oauth2", AuthOAuth2)
	}
	if AuthCookie != "cookie" {
		t.Errorf("AuthCookie = %q, want cookie", AuthCookie)
	}
}

func TestParamLocationConstants(t *testing.T) {
	if ParamQuery != "query" {
		t.Errorf("ParamQuery = %q, want query", ParamQuery)
	}
	if ParamHeader != "header" {
		t.Errorf("ParamHeader = %q, want header", ParamHeader)
	}
	if ParamPath != "path" {
		t.Errorf("ParamPath = %q, want path", ParamPath)
	}
	if ParamBody != "body" {
		t.Errorf("ParamBody = %q, want body", ParamBody)
	}
}

func TestNewDiscoverer(t *testing.T) {
	d := NewDiscoverer("http://example.com", 10*time.Second)
	if d == nil {
		t.Fatal("NewDiscoverer() returned nil")
	}
	if d.baseURL != "http://example.com" {
		t.Errorf("baseURL = %q, want http://example.com", d.baseURL)
	}
	if d.client == nil {
		t.Error("client is nil")
	}
	if d.headers["User-Agent"] == "" {
		t.Error("User-Agent header not set")
	}
}

func TestNewDiscovererTrimsSlash(t *testing.T) {
	d := NewDiscoverer("http://example.com/", 5*time.Second)
	if d.baseURL != "http://example.com" {
		t.Errorf("baseURL = %q, want http://example.com", d.baseURL)
	}
}

func TestDiscovererSetHeader(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	d.SetHeader("X-Test", "value")
	if got := d.getHeader("X-Test"); got != "value" {
		t.Errorf("getHeader = %q, want value", got)
	}
}

func TestDiscovererDoRequest(t *testing.T) {
	var method string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		_ = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	resp, err := d.doRequest(d.client, "POST", ts.URL+"/test", nil, map[string]string{"X-Custom": "val"})
	if err != nil {
		t.Fatalf("doRequest() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if method != "POST" {
		t.Errorf("method = %q, want POST", method)
	}
}

func TestDiscoverAll(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.DiscoverAll()
	if result == nil {
		t.Fatal("DiscoverAll() returned nil")
	}
	if result.TargetURL != ts.URL {
		t.Errorf("TargetURL = %q, want %q", result.TargetURL, ts.URL)
	}
	if result.Timestamp == "" {
		t.Error("Timestamp is empty")
	}
}

func TestDiscoverSwaggerOpenAPI3(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openapi.json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"openapi": "3.0.0",
				"info": {"version": "1.0.0"},
				"paths": {
					"/users": {
						"get": {
							"summary": "List users",
							"parameters": [
								{"name": "page", "in": "query", "type": "integer", "required": false}
							]
						}
					}
				},
				"components": {
					"securitySchemes": {
						"bearerAuth": {"type": "http", "scheme": "bearer"}
					}
				},
				"security": [{"bearerAuth": []}]
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.DiscoverAll()
	if result.SpecURL == "" {
		t.Fatal("SpecURL should not be empty")
	}
	if !strings.Contains(result.SpecVersion, "OpenAPI 3.x") {
		t.Errorf("SpecVersion = %q, want OpenAPI 3.x", result.SpecVersion)
	}
	if len(result.Endpoints) == 0 {
		t.Error("expected discovered endpoints")
	}
	if len(result.AuthTypes) == 0 {
		t.Error("expected auth types")
	}
}

func TestDiscoverSwagger2(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "swagger.json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"swagger": "2.0",
				"info": {"version": "1.0.0"},
				"basePath": "/api",
				"paths": {
					"/users": {
						"get": {
							"summary": "List users",
							"parameters": [
								{"name": "id", "in": "path", "type": "string", "required": true}
							]
						}
					}
				},
				"securityDefinitions": {
					"apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
				}
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.DiscoverAll()
	if result.SpecURL == "" {
		t.Fatal("SpecURL should not be empty")
	}
	if !strings.Contains(result.SpecVersion, "Swagger 2.0") {
		t.Errorf("SpecVersion = %q, want Swagger 2.0", result.SpecVersion)
	}
}

func TestCheckSwaggerHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "2.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.checkSwaggerHeaders()
	if result == nil {
		t.Fatal("checkSwaggerHeaders() returned nil")
	}
	if result.SpecVersion != "2.0" {
		t.Errorf("SpecVersion = %q, want 2.0", result.SpecVersion)
	}
}

func TestCheckSwaggerHeadersNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.checkSwaggerHeaders()
	if result != nil {
		t.Error("expected nil when no swagger headers")
	}
}

func TestDiscoverGraphQL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "graphql") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.DiscoverAll()
	if !result.GraphQLDetected {
		t.Error("expected GraphQL detection")
	}
	if result.GraphQLEndpoint == "" {
		t.Error("GraphQLEndpoint should not be empty")
	}
}

func TestCheckGraphQLHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-GraphQL", "enabled")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.checkGraphQLHeaders()
	if result == nil {
		t.Fatal("checkGraphQLHeaders() returned nil")
	}
	if !result.GraphQLDetected {
		t.Error("expected GraphQL detection")
	}
}

func TestCheckGraphQLHeadersContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/graphql")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.checkGraphQLHeaders()
	if result == nil {
		t.Fatal("checkGraphQLHeaders() returned nil")
	}
	if !result.GraphQLDetected {
		t.Error("expected GraphQL detection via Content-Type")
	}
}

func TestCheckGraphQLHeadersNoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.checkGraphQLHeaders()
	if result != nil {
		t.Error("expected nil when no graphql headers")
	}
}

func TestDiscoverGRPC(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" && strings.Contains(r.URL.Path, "grpc") {
			w.WriteHeader(http.StatusOK)
		} else {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.DiscoverAll()
	if !result.GRPCDetected {
		t.Error("expected gRPC detection")
	}
}

func TestProbeGraphQLEndpoint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	url, detected := d.probeGraphQLEndpoint(ts.URL)
	if !detected {
		t.Error("expected endpoint detection")
	}
	if url != ts.URL {
		t.Errorf("url = %q, want %q", url, ts.URL)
	}
}

func TestProbeGraphQLEndpointErrorResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":[{"message":"error"}]}`))
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	url, detected := d.probeGraphQLEndpoint(ts.URL)
	if detected {
		t.Log("detected via errors in response")
	}
	_ = url
}

func TestProbeGraphQLEndpointNoData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	_, detected := d.probeGraphQLEndpoint(ts.URL)
	if detected {
		t.Error("expected false for empty response")
	}
}

func TestDetectAPIVersions(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "v1") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	versions := d.detectAPIVersions()
	if len(versions) == 0 {
		t.Log("no versions detected (API may not respond)")
	}
}

func TestParseOpenAPI3PathsEmpty(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	doc := openapi3Doc{OpenAPI: "3.0.0"}
	endpoints := d.parseOpenAPI3Paths(doc, []byte(`{"paths":{}}`))
	if len(endpoints) != 0 {
		t.Errorf("expected 0 endpoints, got %d", len(endpoints))
	}
}

func TestParseOpenAPI3PathsInvalidJSON(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	doc := openapi3Doc{OpenAPI: "3.0.0"}
	endpoints := d.parseOpenAPI3Paths(doc, []byte(`invalid`))
	if endpoints != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestParseSwagger2PathsEmpty(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	doc := swagger2Doc{Swagger: "2.0"}
	endpoints := d.parseSwagger2Paths(doc, []byte(`{"paths":{}}`))
	if len(endpoints) != 0 {
		t.Errorf("expected 0 endpoints, got %d", len(endpoints))
	}
}

func TestParseSwagger2PathsInvalidJSON(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	doc := swagger2Doc{Swagger: "2.0"}
	endpoints := d.parseSwagger2Paths(doc, []byte(`invalid`))
	if endpoints != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestExtractOpenAPI3Auth(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	doc := openapi3Doc{
		Components: struct {
			SecuritySchemes map[string]any `json:"securitySchemes"`
		}{
			SecuritySchemes: map[string]any{
				"basic":  map[string]any{"type": "http", "scheme": "basic"},
				"bearer": map[string]any{"type": "http", "scheme": "bearer"},
				"apiKey": map[string]any{"type": "apiKey"},
				"oauth":  map[string]any{"type": "oauth2"},
			},
		},
	}
	auths := d.extractOpenAPI3Auth(doc)
	if len(auths) == 0 {
		t.Fatal("expected auth types")
	}
	seen := make(map[AuthType]bool)
	for _, a := range auths {
		seen[a] = true
	}
	if !seen[AuthBasic] {
		t.Error("expected AuthBasic")
	}
	if !seen[AuthBearer] {
		t.Error("expected AuthBearer")
	}
	if !seen[AuthAPIKey] {
		t.Error("expected AuthAPIKey")
	}
	if !seen[AuthOAuth2] {
		t.Error("expected AuthOAuth2")
	}
}

func TestExtractSwagger2Auth(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	defs := map[string]any{
		"basic":  map[string]any{"type": "basic"},
		"apiKey": map[string]any{"type": "apiKey"},
		"oauth":  map[string]any{"type": "oauth2"},
	}
	raw, _ := json.Marshal(defs)
	var doc swagger2Doc
	json.Unmarshal(raw, &doc.SecurityDefinitions)
	doc.SecurityDefinitions = defs
	auths := d.extractSwagger2Auth(doc)
	if len(auths) == 0 {
		t.Fatal("expected auth types")
	}
}

func TestExtractGRPCCustomMethods(t *testing.T) {
	d := NewDiscoverer("http://example.com", 5*time.Second)
	methods := d.extractGRPCCustomMethods("http://example.com/grpc")
	if len(methods) == 0 {
		t.Error("expected gRPC methods")
	}
}

func TestGuessGRPCHTTPBridge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`grpc service available`))
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	methods := d.guessGRPCHTTPBridge()
	if len(methods) > 0 {
		t.Logf("gRPC bridge methods: %v", methods)
	}
}

func TestProbeGRPCReflection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	services := d.probeGRPCReflection()
	if len(services) > 0 {
		t.Logf("gRPC services: %v", services)
	}
}

func TestNewScanner(t *testing.T) {
	s := NewScanner()
	if s == nil {
		t.Fatal("NewScanner() returned nil")
	}
	if s.maxConcurrency != 10 {
		t.Errorf("maxConcurrency = %d, want 10", s.maxConcurrency)
	}
	if s.rateLimiter == nil {
		t.Error("rateLimiter is nil")
	}
}

func TestWithConcurrency(t *testing.T) {
	s := NewScanner(WithConcurrency(50))
	if s.maxConcurrency != 50 {
		t.Errorf("maxConcurrency = %d, want 50", s.maxConcurrency)
	}
}

func TestWithConcurrencyZero(t *testing.T) {
	s := NewScanner(WithConcurrency(0))
	if s.maxConcurrency != 10 {
		t.Errorf("maxConcurrency = %d, want 10 (default)", s.maxConcurrency)
	}
}

func TestWithTimeout(t *testing.T) {
	s := NewScanner(WithTimeout(60 * time.Second))
	if s.timeout != 60*time.Second {
		t.Errorf("timeout = %v, want 60s", s.timeout)
	}
}

func TestWithTimeoutZero(t *testing.T) {
	s := NewScanner(WithTimeout(0))
	if s.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", s.timeout)
	}
}

func TestScannerScanTarget(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := NewScanner(WithConcurrency(2))
	result := s.ScanTarget(context.Background(), ts.URL)
	if result == nil {
		t.Fatal("ScanTarget() returned nil")
	}
	if result.TargetURL != ts.URL {
		t.Errorf("TargetURL = %q, want %q", result.TargetURL, ts.URL)
	}
}

func TestScannerScanTargetError(t *testing.T) {
	s := NewScanner()
	result := s.ScanTarget(context.Background(), "http://127.0.0.1:1")
	if result == nil {
		t.Fatal("ScanTarget() returned nil")
	}
}

func TestScannerScanTargets(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := NewScanner(WithConcurrency(2))
	results := s.ScanTargets(context.Background(), []string{ts.URL, ts.URL})
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestScannerScanTargetsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := NewScanner()
	results := s.ScanTargets(ctx, []string{"http://example.com"})
	if results == nil {
		t.Error("expected non-nil results slice")
	}
}

func TestNewIntegration(t *testing.T) {
	s := NewScanner()
	i := NewIntegration(s)
	if i == nil {
		t.Fatal("NewIntegration() returned nil")
	}
	if i.GetScanner() != s {
		t.Error("GetScanner() returned different scanner")
	}
}

func TestNewDefaultIntegration(t *testing.T) {
	i := NewDefaultIntegration()
	if i == nil {
		t.Fatal("NewDefaultIntegration() returned nil")
	}
	if i.GetScanner() == nil {
		t.Error("GetScanner() returned nil")
	}
}

func TestIntegrationDiscoverAndEnrichNilContext(t *testing.T) {
	i := NewDefaultIntegration()
	i.DiscoverAndEnrich(context.Background(), nil)
}

func TestIntegrationDiscoverAndEnrich(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	i := NewDefaultIntegration()
	sc := scanctx.NewScanContext("test-id", ts.URL)
	i.DiscoverAndEnrich(context.Background(), sc)
}

func TestHasScheme(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"example.com", false},
		{"", false},
		{"ftp://example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := hasScheme(tt.input); got != tt.want {
				t.Errorf("hasScheme(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestStringsTrimRight(t *testing.T) {
	tests := []struct {
		s, cutset, want string
	}{
		{"http://example.com/", "/", "http://example.com"},
		{"http://example.com", "/", "http://example.com"},
		{"", "/", ""},
		{"hello///", "/", "hello"},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := stringsTrimRight(tt.s, tt.cutset); got != tt.want {
				t.Errorf("stringsTrimRight(%q, %q) = %q, want %q", tt.s, tt.cutset, got, tt.want)
			}
		})
	}
}

func TestNewHandler(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "/api", "test-token")
	if h == nil {
		t.Fatal("NewHandler() returned nil")
	}
	if h.basePath != "/api" {
		t.Errorf("basePath = %q, want /api", h.basePath)
	}
}

func TestHandlerGenerateID(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "/api", "test-token")
	id1 := h.generateID()
	id2 := h.generateID()
	if id1 == "" || id2 == "" {
		t.Error("generateID() returned empty")
	}
	if id1 == id2 {
		t.Error("generateID() returned duplicate")
	}
}

func TestHandlerRegisterRoutes(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
}

func TestHandlerHandleDiscover(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")

	body := `{"target":"https://example.com"}`
	req := httptest.NewRequest("POST", "/api/discover", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleDiscover(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", resp.StatusCode)
	}
}

func TestHandlerHandleDiscoverPrivateIPBlocked(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	body := `{"target":"` + ts.URL + `"}`
	req := httptest.NewRequest("POST", "/api/discover", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleDiscover(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (private IP blocked)", resp.StatusCode)
	}
}

func TestHandlerHandleDiscoverInvalidMethod(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	req := httptest.NewRequest("GET", "/api/discover", nil)
	w := httptest.NewRecorder()
	h.handleDiscover(w, req)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Result().StatusCode)
	}
}

func TestHandlerHandleDiscoverInvalidBody(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	req := httptest.NewRequest("POST", "/api/discover", strings.NewReader(`invalid json`))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleDiscover(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandlerHandleDiscoverEmptyTarget(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	req := httptest.NewRequest("POST", "/api/discover", strings.NewReader(`{"target":""}`))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleDiscover(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandlerHandleGetResultsNotFound(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	req := httptest.NewRequest("GET", "/api/discover/nonexistent/results", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleGetResults(w, req)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Result().StatusCode)
	}
}

func TestHandlerHandleGetResultsMissingID(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	req := httptest.NewRequest("GET", "/api/discover/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleGetResults(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandlerHandleGetResultsPending(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	h.mu.Lock()
	h.jobs["test-1"] = &scanJob{
		ID:     "test-1",
		Target: "http://example.com",
		Status: "running",
	}
	h.mu.Unlock()

	req := httptest.NewRequest("GET", "/api/discover/test-1/results", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleGetResults(w, req)
	if w.Result().StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", w.Result().StatusCode)
	}
}

func TestHandlerHandleGetResultsInvalidMethod(t *testing.T) {
	s := NewScanner()
	h := NewHandler(s, "", "test-token")
	req := httptest.NewRequest("POST", "/api/discover/test-1/results", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.handleGetResults(w, req)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Result().StatusCode)
	}
}

func TestDiscoverAllDedupAuthTypes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	d := NewDiscoverer(ts.URL, 5*time.Second)
	result := d.DiscoverAll()
	if result == nil {
		t.Fatal("nil result")
	}
}

func TestIntegrationDiscoverAndEnrichWithSwagger(t *testing.T) {
	apiCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		if strings.Contains(r.URL.Path, "swagger.json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"swagger": "2.0",
				"info": {"version": "1.0.0"},
				"paths": {"/users": {"get": {"summary": "list"}}}
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	i := NewDefaultIntegration()
	sc := scanctx.NewScanContext("test-id", ts.URL)
	i.DiscoverAndEnrich(context.Background(), sc)
}
