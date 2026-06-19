package apidiscovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBasic  AuthType = "basic"
	AuthBearer AuthType = "bearer"
	AuthAPIKey AuthType = "api_key"
	AuthOAuth2 AuthType = "oauth2"
	AuthCookie AuthType = "cookie"
)

type ParamLocation string

const (
	ParamQuery  ParamLocation = "query"
	ParamHeader ParamLocation = "header"
	ParamPath   ParamLocation = "path"
	ParamBody   ParamLocation = "body"
)

type EndpointParam struct {
	Name     string        `json:"name"`
	Location ParamLocation `json:"location"`
	Type     string        `json:"type"`
	Required bool          `json:"required"`
	Example  string        `json:"example,omitempty"`
}

type DiscoveredEndpoint struct {
	Method          string          `json:"method"`
	Path            string          `json:"path"`
	Params          []EndpointParam `json:"params,omitempty"`
	Auth            AuthType        `json:"auth"`
	Description     string          `json:"description,omitempty"`
	ResponseExample string          `json:"response_example,omitempty"`
	Source          string          `json:"source"`
}

type APIDiscoveryResult struct {
	TargetURL       string               `json:"target_url"`
	Endpoints       []DiscoveredEndpoint `json:"endpoints"`
	AuthTypes       []AuthType           `json:"auth_types"`
	SpecURL         string               `json:"spec_url,omitempty"`
	SpecVersion     string               `json:"spec_version,omitempty"`
	GraphQLDetected bool                 `json:"graphql_detected"`
	GraphQLEndpoint string               `json:"graphql_endpoint,omitempty"`
	GRPCDetected    bool                 `json:"grpc_detected"`
	GRPCEndpoints   []string             `json:"grpc_endpoints,omitempty"`
	APIVersions     []string             `json:"api_versions,omitempty"`
	UndocumentedEPs []string             `json:"undocumented_endpoints,omitempty"`
	Error           string               `json:"error,omitempty"`
	ScanDuration    string               `json:"scan_duration"`
	Timestamp       string               `json:"timestamp"`
}

type swaggerPaths map[string]map[string]*swaggerOp

type swaggerOp struct {
	OperationID string                     `json:"operationId"`
	Summary     string                     `json:"summary"`
	Parameters  []swaggerParam             `json:"parameters"`
	Security    []map[string][]string      `json:"security"`
	Responses   map[string]json.RawMessage `json:"responses"`
}

type swaggerParam struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Example  any    `json:"example,omitempty"`
}

type openapi3Doc struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Version string `json:"version"`
	} `json:"info"`
	Paths      map[string]any `json:"paths"`
	Components struct {
		SecuritySchemes map[string]any `json:"securitySchemes"`
	} `json:"components"`
	Security []map[string][]string `json:"security"`
}

type swagger2Doc struct {
	Swagger string `json:"swagger"`
	Info    struct {
		Version string `json:"version"`
	} `json:"info"`
	BasePath            string                `json:"basePath"`
	Paths               map[string]any        `json:"paths"`
	SecurityDefinitions map[string]any        `json:"securityDefinitions"`
	Security            []map[string][]string `json:"security"`
}

var commonSwaggerPaths = []string{
	"/swagger.json",
	"/swagger/v1/swagger.json",
	"/api/docs",
	"/api/swagger",
	"/openapi.json",
	"/docs",
	"/api/v1/openapi.json",
	"/api/v2/openapi.json",
	"/swagger-ui.html",
	"/api/v3/openapi.json",
	"/api/openapi.json",
	"/v1/swagger.json",
	"/v2/swagger.json",
	"/swagger-resources",
	"/api/swagger-ui.html",
}

var commonGraphQLPaths = []string{
	"/graphql",
	"/gql",
	"/graphql/v1",
	"/api/graphql",
	"/query",
	"/v1/graphql",
	"/v2/graphql",
}

var commonGRPCPaths = []string{
	"/grpc",
	"/api/v1/grpc",
}

type Discoverer struct {
	client  *http.Client
	timeout time.Duration
	baseURL string
	headers map[string]string
	mu      sync.RWMutex
}

func NewDiscoverer(baseURL string, timeout time.Duration) *Discoverer {
	return &Discoverer{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		timeout: timeout,
		baseURL: strings.TrimRight(baseURL, "/"),
		headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (compatible; Ares/2.0)",
			"Accept":     "*/*",
		},
	}
}

func (d *Discoverer) SetHeader(key, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.headers[key] = value
}

func (d *Discoverer) getHeader(key string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.headers[key]
}

func (d *Discoverer) doRequest(ctx *http.Client, method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	d.mu.RLock()
	for k, v := range d.headers {
		req.Header.Set(k, v)
	}
	d.mu.RUnlock()

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return ctx.Do(req)
}

func (d *Discoverer) DiscoverAll() *APIDiscoveryResult {
	start := time.Now()
	result := &APIDiscoveryResult{
		TargetURL: d.baseURL,
		Timestamp: start.Format(time.RFC3339),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		specResult := d.discoverSwagger()
		mu.Lock()
		if specResult != nil {
			result.SpecURL = specResult.SpecURL
			result.SpecVersion = specResult.SpecVersion
			result.Endpoints = append(result.Endpoints, specResult.Endpoints...)
			result.AuthTypes = append(result.AuthTypes, specResult.AuthTypes...)
		}
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		gqlResult := d.discoverGraphQL()
		mu.Lock()
		if gqlResult != nil {
			result.GraphQLDetected = gqlResult.GraphQLDetected
			result.GraphQLEndpoint = gqlResult.GraphQLEndpoint
			result.Endpoints = append(result.Endpoints, gqlResult.Endpoints...)
		}
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		grpcResult := d.discoverGRPC()
		mu.Lock()
		if grpcResult != nil {
			result.GRPCDetected = grpcResult.GRPCDetected
			result.GRPCEndpoints = grpcResult.GRPCEndpoints
		}
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		versions := d.detectAPIVersions()
		mu.Lock()
		result.APIVersions = versions
		mu.Unlock()
	}()

	wg.Wait()

	result.ScanDuration = time.Since(start).Round(time.Millisecond).String()

	seen := make(map[string]bool)
	var deduped []AuthType
	for _, a := range result.AuthTypes {
		if !seen[string(a)] {
			seen[string(a)] = true
			deduped = append(deduped, a)
		}
	}
	result.AuthTypes = deduped

	return result
}

func (d *Discoverer) discoverSwagger() *APIDiscoveryResult {
	res := &APIDiscoveryResult{}

	for _, path := range commonSwaggerPaths {
		url := d.baseURL + path
		resp, err := d.doRequest(d.client, "GET", url, nil, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "html") && !strings.Contains(path, ".json") {
			continue
		}

		var openapi3 openapi3Doc
		if err := json.Unmarshal(body, &openapi3); err == nil && openapi3.OpenAPI != "" {
			res.SpecURL = url
			res.SpecVersion = fmt.Sprintf("OpenAPI 3.x (%s)", openapi3.Info.Version)
			res.Endpoints = d.parseOpenAPI3Paths(openapi3, body)
			res.AuthTypes = d.extractOpenAPI3Auth(openapi3)
			return res
		}

		var swagger2 swagger2Doc
		if err := json.Unmarshal(body, &swagger2); err == nil && swagger2.Swagger != "" {
			res.SpecURL = url
			res.SpecVersion = fmt.Sprintf("Swagger 2.0 (%s)", swagger2.Info.Version)
			res.Endpoints = d.parseSwagger2Paths(swagger2, body)
			res.AuthTypes = d.extractSwagger2Auth(swagger2)
			return res
		}
	}

	headerResult := d.checkSwaggerHeaders()
	if headerResult != nil {
		return headerResult
	}

	return nil
}

func (d *Discoverer) checkSwaggerHeaders() *APIDiscoveryResult {
	resp, err := d.doRequest(d.client, "GET", d.baseURL, nil, nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	headers := []string{"X-Swagger-Version", "X-OpenAPI-Version", "X-API-Version"}
	for _, h := range headers {
		if val := resp.Header.Get(h); val != "" {
			return &APIDiscoveryResult{
				SpecURL:     d.baseURL,
				SpecVersion: val,
			}
		}
	}

	return nil
}

func (d *Discoverer) parseOpenAPI3Paths(doc openapi3Doc, raw []byte) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint
	seen := make(map[string]bool)

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return nil
	}
	var pathsRaw json.RawMessage
	if err := json.Unmarshal(rawMap["paths"], &pathsRaw); err != nil {
		return nil
	}

	var pathsMap map[string]json.RawMessage
	if err := json.Unmarshal(pathsRaw, &pathsMap); err != nil {
		return nil
	}

	for path, methodsRaw := range pathsMap {
		var methodsMap map[string]json.RawMessage
		if err := json.Unmarshal(methodsRaw, &methodsMap); err != nil {
			continue
		}
		for method := range methodsMap {
			method = strings.ToUpper(method)
			if method == "PARAMETERS" || method == "SERVERS" || method == "SUMMARY" || method == "DESCRIPTION" {
				continue
			}
			key := method + ":" + path
			if seen[key] {
				continue
			}
			seen[key] = true

			ep := DiscoveredEndpoint{
				Method: method,
				Path:   path,
				Source: "openapi3",
			}

			var opObj map[string]json.RawMessage
			json.Unmarshal(methodsRaw, &opObj)

			if paramsRaw, ok := opObj["parameters"]; ok {
				var params []swaggerParam
				if json.Unmarshal(paramsRaw, &params) == nil {
					for _, p := range params {
						loc := ParamQuery
						switch p.In {
						case "header":
							loc = ParamHeader
						case "path":
							loc = ParamPath
						case "body":
							loc = ParamBody
						}
						t := p.Type
						if t == "" {
							t = "string"
						}
						epParam := EndpointParam{
							Name:     p.Name,
							Location: loc,
							Type:     t,
							Required: p.Required,
						}
						if p.Example != nil {
							epParam.Example = fmt.Sprintf("%v", p.Example)
						}
						ep.Params = append(ep.Params, epParam)
					}
				}
			}

			if secRaw, ok := opObj["security"]; ok {
				var sec []map[string][]string
				if json.Unmarshal(secRaw, &sec) == nil && len(sec) > 0 {
					ep.Auth = AuthOAuth2
				}
			}

			if summaryRaw, ok := opObj["summary"]; ok {
				var summary string
				if json.Unmarshal(summaryRaw, &summary) == nil {
					ep.Description = summary
				}
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

func (d *Discoverer) parseSwagger2Paths(doc swagger2Doc, raw []byte) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint
	seen := make(map[string]bool)
	basePath := doc.BasePath
	if basePath == "" {
		basePath = ""
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return nil
	}
	var pathsRaw json.RawMessage
	if err := json.Unmarshal(rawMap["paths"], &pathsRaw); err != nil {
		return nil
	}

	var pathsMap map[string]json.RawMessage
	if err := json.Unmarshal(pathsRaw, &pathsMap); err != nil {
		return nil
	}

	for path, methodsRaw := range pathsMap {
		fullPath := basePath + path
		var methodsMap map[string]json.RawMessage
		if err := json.Unmarshal(methodsRaw, &methodsMap); err != nil {
			continue
		}
		for method := range methodsMap {
			method = strings.ToUpper(method)
			if method == "PARAMETERS" {
				continue
			}
			key := method + ":" + fullPath
			if seen[key] {
				continue
			}
			seen[key] = true

			ep := DiscoveredEndpoint{
				Method: method,
				Path:   fullPath,
				Source: "swagger2",
			}

			var opMap map[string]json.RawMessage
			if json.Unmarshal(methodsRaw, &opMap) == nil {
				if paramsRaw, ok := opMap["parameters"]; ok {
					var params []swaggerParam
					if json.Unmarshal(paramsRaw, &params) == nil {
						for _, p := range params {
							loc := ParamQuery
							switch p.In {
							case "header":
								loc = ParamHeader
							case "path":
								loc = ParamPath
							case "body":
								loc = ParamBody
							case "formData":
								loc = ParamBody
							}
							t := p.Type
							if t == "" {
								t = "string"
							}
							epParam := EndpointParam{
								Name:     p.Name,
								Location: loc,
								Type:     t,
								Required: p.Required,
							}
							if p.Example != nil {
								epParam.Example = fmt.Sprintf("%v", p.Example)
							}
							ep.Params = append(ep.Params, epParam)
						}
					}
				}

				if summaryRaw, ok := opMap["summary"]; ok {
					var summary string
					if json.Unmarshal(summaryRaw, &summary) == nil {
						ep.Description = summary
					}
				}

				if secRaw, ok := opMap["security"]; ok {
					var sec []map[string][]string
					if json.Unmarshal(secRaw, &sec) == nil && len(sec) > 0 {
						ep.Auth = AuthOAuth2
					}
				}
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

func (d *Discoverer) extractOpenAPI3Auth(doc openapi3Doc) []AuthType {
	var auths []AuthType
	seen := make(map[AuthType]bool)

	if doc.Components.SecuritySchemes != nil {
		schemes := make(map[string]map[string]any)
		if raw, err := json.Marshal(doc.Components.SecuritySchemes); err == nil {
			json.Unmarshal(raw, &schemes)
			for _, scheme := range schemes {
				if typ, ok := scheme["type"].(string); ok {
					switch typ {
					case "http":
						if schemeVal, ok := scheme["scheme"].(string); ok {
							switch strings.ToLower(schemeVal) {
							case "basic":
								seen[AuthBasic] = true
							case "bearer":
								seen[AuthBearer] = true
							}
						}
					case "apiKey":
						seen[AuthAPIKey] = true
					case "oauth2":
						seen[AuthOAuth2] = true
					}
				}
			}
		}
	}

	for _, sec := range doc.Security {
		for scheme := range sec {
			_ = scheme
			seen[AuthOAuth2] = true
		}
	}

	for a := range seen {
		auths = append(auths, a)
	}
	return auths
}

func (d *Discoverer) extractSwagger2Auth(doc swagger2Doc) []AuthType {
	var auths []AuthType
	seen := make(map[AuthType]bool)

	if doc.SecurityDefinitions != nil {
		defs := make(map[string]map[string]any)
		if raw, err := json.Marshal(doc.SecurityDefinitions); err == nil {
			json.Unmarshal(raw, &defs)
			for _, def := range defs {
				if typ, ok := def["type"].(string); ok {
					switch typ {
					case "basic":
						seen[AuthBasic] = true
					case "apiKey":
						seen[AuthAPIKey] = true
					case "oauth2":
						seen[AuthOAuth2] = true
					}
				}
			}
		}
	}

	for a := range seen {
		auths = append(auths, a)
	}
	return auths
}

func (d *Discoverer) discoverGraphQL() *APIDiscoveryResult {
	res := &APIDiscoveryResult{}

	for _, path := range commonGraphQLPaths {
		url := d.baseURL + path
		_, detected := d.probeGraphQLEndpoint(url)
		if detected {
			res.GraphQLDetected = true
			res.GraphQLEndpoint = url

			ep := DiscoveredEndpoint{
				Method: "POST",
				Path:   path,
				Params: []EndpointParam{
					{Name: "query", Location: ParamBody, Type: "string", Required: true, Example: "{ __schema { types { name } } }"},
				},
				Auth:   AuthNone,
				Source: "graphql",
			}
			res.Endpoints = append(res.Endpoints, ep)

			return res
		}
	}

	headerResult := d.checkGraphQLHeaders()
	if headerResult != nil {
		return headerResult
	}

	return nil
}

func (d *Discoverer) probeGraphQLEndpoint(url string) (string, bool) {
	introspectionQuery := `{"query":"{ __schema { queryType { name } } }"}`

	resp, err := d.doRequest(d.client, "POST", url, strings.NewReader(introspectionQuery), map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}

	if resp.StatusCode == http.StatusOK {
		var result struct {
			Data struct {
				Schema struct {
					QueryType map[string]any `json:"queryType"`
				} `json:"__schema"`
			} `json:"data"`
			Errors []map[string]any `json:"errors"`
		}
		if err := json.Unmarshal(body, &result); err == nil {
			if result.Data.Schema.QueryType != nil {
				return url, true
			}
		}
	}

	bodyStr := strings.ToLower(string(body))
	if strings.Contains(bodyStr, "graphql") ||
		strings.Contains(bodyStr, "\"errors\"") ||
		strings.Contains(bodyStr, "\"data\"") {
		return url, true
	}

	return "", false
}

func (d *Discoverer) checkGraphQLHeaders() *APIDiscoveryResult {
	resp, err := d.doRequest(d.client, "GET", d.baseURL, nil, map[string]string{
		"X-GraphQL-Test": "1",
	})
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	gqlHeaders := []string{"X-GraphQL", "X-GraphQL-Engine", "X-GraphQL-Version", "X-GraphQL-Type"}
	for _, h := range gqlHeaders {
		if val := resp.Header.Get(h); val != "" {
			return &APIDiscoveryResult{
				GraphQLDetected: true,
				GraphQLEndpoint: d.baseURL,
				Endpoints: []DiscoveredEndpoint{
					{
						Method: "POST",
						Path:   "/graphql",
						Source: "graphql-header",
					},
				},
			}
		}
	}

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "graphql") {
		return &APIDiscoveryResult{
			GraphQLDetected: true,
			GraphQLEndpoint: d.baseURL,
		}
	}

	return nil
}

func (d *Discoverer) discoverGRPC() *APIDiscoveryResult {
	res := &APIDiscoveryResult{}

	for _, path := range commonGRPCPaths {
		url := d.baseURL + path
		resp, err := d.doRequest(d.client, "OPTIONS", url, nil, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 500 {
			res.GRPCDetected = true
			res.GRPCEndpoints = append(res.GRPCEndpoints, url)
		}
	}

	resp, err := d.doRequest(d.client, "GET", d.baseURL, nil, nil)
	if err == nil {
		defer resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "application/grpc") ||
			strings.Contains(ct, "application/grpc-web") ||
			strings.Contains(ct, "application/x-protobuf") {
			res.GRPCDetected = true
		}
		if strings.Contains(resp.Header.Get("X-GRPC"), "true") {
			res.GRPCDetected = true
		}
		if strings.HasPrefix(resp.Header.Get("X-HTTP2-Settings"), "grpc") {
			res.GRPCDetected = true
		}
	}

	if res.GRPCDetected {
		services := d.probeGRPCReflection()
		if len(services) > 0 {
			res.GRPCEndpoints = append(res.GRPCEndpoints, services...)
		}
	}

	return res
}

func (d *Discoverer) probeGRPCReflection() []string {
	var services []string

	reflectionEndpoints := []string{
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
	}

	for _, ep := range reflectionEndpoints {
		url := d.baseURL + ep

		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Header.Set("User-Agent", "grpc-go/1.59.0")

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		ct := resp.Header.Get("Content-Type")
		grpcStatus := resp.Header.Get("Grpc-Status")

		if strings.Contains(ct, "application/grpc") {
			if grpcStatus == "0" || grpcStatus == "12" {
				services = d.listGRPCServices(url)
				if len(services) == 0 {
					services = d.extractGRPCCustomMethods(url)
				}
			}
		}
		resp.Body.Close()

		if len(services) > 0 {
			break
		}
	}

	if len(services) == 0 {
		services = d.guessGRPCHTTPBridge()
	}

	return services
}

func (d *Discoverer) listGRPCServices(reflectionURL string) []string {
	// Protobuf-encoded ServerReflectionRequest with list_services field
	// Field 7 (list_services), wire type 2 (length-delimited), tag = (7<<3)|2 = 0x3a
	// Value: string "*" = length 1, byte 0x2a
	// Full protobuf message: \x3a\x01\x2a
	// gRPC frame: 1 byte comp(0) + 4 bytes big-endian len(3) + 3 bytes message
	protoBody := []byte{
		0x00, 0x00, 0x00, 0x00, 0x03, // gRPC frame: uncompressed, length=3
		0x3a, 0x01, 0x2a, // protobuf: field 7 (list_services), string "*"
	}

	req, err := http.NewRequest("POST", reflectionURL, bytes.NewReader(protoBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("User-Agent", "grpc-go/1.59.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) < 6 {
		return nil
	}

	// Skip 5-byte gRPC frame header
	msg := body[5:]

	// Parse ListServicesResponse from protobuf bytes
	// ListServicesResponse has field 1 (service) repeated, type message (wire type 2)
	// Each ServiceResponse has field 1 (name) type string
	var services []string
	i := 0
	for i < len(msg) {
		if i >= len(msg) {
			break
		}
		tag := msg[i]
		i++
		if tag == 0x0a { // field 1 (service), wire type 2 (length-delimited)
			if i >= len(msg) {
				break
			}
			msgLen := int(msg[i])
			i++
			if i+msgLen > len(msg) {
				break
			}
			svcMsg := msg[i : i+msgLen]
			i += msgLen
			// Parse ServiceResponse for field 1 (name)
			if len(svcMsg) > 0 && svcMsg[0] == 0x0a {
				nameLen := int(svcMsg[1])
				if 2+nameLen <= len(svcMsg) {
					svcName := string(svcMsg[2 : 2+nameLen])
					if svcName != "" {
						services = append(services, svcName)
					}
				}
			}
		} else if tag == 0x12 { // field 2 (unused in response but skip it)
			if i >= len(msg) {
				break
			}
			i++
			i += int(msg[i-1])
		} else {
			break
		}
	}
	return services
}

func (d *Discoverer) extractGRPCCustomMethods(reflectionURL string) []string {
	var methods []string

	commonGRPCServices := []string{
		"ListServices",
		"ServerReflectionInfo",
		"UserService",
		"AuthService",
		"AccountService",
		"PaymentService",
		"OrderService",
		"ProductService",
		"InventoryService",
		"NotificationService",
		"EmailService",
		"FileService",
		"UploadService",
		"DownloadService",
		"SearchService",
		"AnalyticsService",
		"MetricsService",
		"HealthService",
		"AdminService",
		"ConfigService",
	}

	for _, svc := range commonGRPCServices {
		methods = append(methods, fmt.Sprintf("grpc://%s", svc))
	}

	return methods
}

func (d *Discoverer) guessGRPCHTTPBridge() []string {
	var methods []string

	grpcBridgePaths := []string{
		"/v1", "/v1/",
		"/api/v1", "/api/v1/",
		"/rpc", "/rpc/",
		"/api/rpc", "/api/rpc/",
	}

	for _, path := range grpcBridgePaths {
		url := d.baseURL + path
		resp, err := d.doRequest(d.client, "GET", url, nil, nil)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		if strings.Contains(bodyStr, "grpc") ||
			strings.Contains(bodyStr, "protobuf") ||
			strings.Contains(bodyStr, "method not found") ||
			strings.Contains(bodyStr, "unknown service") {
			methods = append(methods, fmt.Sprintf("grpc-bridge://%s", path))
		}
	}

	return methods
}

func (d *Discoverer) detectAPIVersions() []string {
	var versions []string
	seen := make(map[string]bool)

	versionPatterns := []string{
		"/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/", "/api/v3/",
		"/v1", "/v2", "/v3", "/api/v1", "/api/v2", "/api/v3",
	}

	for _, vp := range versionPatterns {
		url := d.baseURL + vp
		resp, err := d.doRequest(d.client, "GET", url, nil, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != 0 {
			ver := strings.Trim(vp, "/")
			if !seen[ver] {
				seen[ver] = true
				versions = append(versions, ver)
			}
		}
	}

	acceptHeaders := []string{
		"application/vnd.api+json;version=1",
		"application/vnd.api+json;version=2",
		"application/vnd.api+json;version=3",
	}
	for _, accept := range acceptHeaders {
		resp, err := d.doRequest(d.client, "GET", d.baseURL, nil, map[string]string{
			"Accept": accept,
		})
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			ver := strings.Split(accept, "version=")
			if len(ver) > 1 {
				v := "accept-header:v" + ver[1]
				if !seen[v] {
					seen[v] = true
					versions = append(versions, v)
				}
			}
		}
	}

	return versions
}
