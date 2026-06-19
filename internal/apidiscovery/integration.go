package apidiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ares/engine/internal/scanctx"
)

var blockedSSRFHosts = map[string]bool{
	"localhost":                true,
	"127.0.0.1":                true,
	"0.0.0.0":                  true,
	"169.254.169.254":          true,
	"metadata.google.internal": true,
	"instance-data":            true,
}

func validateExternalURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("blocked scheme: %s", parsed.Scheme)
	}
	host := parsed.Hostname()
	if blockedSSRFHosts[strings.ToLower(host)] {
		return fmt.Errorf("blocked destination: %s", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("blocked destination: internal IP (%s)", ip)
		}
	}
	return nil
}

type Integration struct {
	scanner *Scanner
}

func NewIntegration(scanner *Scanner) *Integration {
	return &Integration{scanner: scanner}
}

func NewDefaultIntegration() *Integration {
	return &Integration{scanner: NewScanner()}
}

func (i *Integration) DiscoverAndEnrich(ctx context.Context, sc *scanctx.ScanContext) {
	if sc == nil {
		return
	}

	target := sc.Target
	if target == "" {
		return
	}

	if !hasScheme(target) {
		target = "https://" + target
	}

	result := i.scanner.ScanTarget(ctx, target)

	epStrings := make([]string, 0, len(result.Endpoints))
	for _, ep := range result.Endpoints {
		fullURL := fmt.Sprintf("%s%s (%s)", stringsTrimRight(target, "/"), ep.Path, ep.Method)
		epStrings = append(epStrings, fullURL)
	}

	if len(epStrings) > 0 {
		sc.AddEndpoints(epStrings)
	}

	if result.SpecURL != "" {
		sc.AddNote(fmt.Sprintf("API spec found: %s (%s)", result.SpecURL, result.SpecVersion))
	}

	if result.GraphQLDetected {
		sc.AddNote(fmt.Sprintf("GraphQL endpoint: %s", result.GraphQLEndpoint))
		sc.AddTechStack("graphql")
	}

	if result.GRPCDetected {
		sc.AddNote(fmt.Sprintf("gRPC detected: %v", result.GRPCEndpoints))
		sc.AddTechStack("grpc")
	}

	if len(result.APIVersions) > 0 {
		sc.AddNote(fmt.Sprintf("API versions: %v", result.APIVersions))
	}

	if len(result.Endpoints) > 0 {
		sc.AddNote(fmt.Sprintf("Discovered %d API endpoints", len(result.Endpoints)))
		sc.AddTechStack("rest-api")
	}

	sc.Log("apidiscovery", "Discovered API endpoints", fmt.Sprintf("endpoints=%d graphql=%v grpc=%v spec=%s",
		len(result.Endpoints), result.GraphQLDetected, result.GRPCDetected, result.SpecURL))
}

func (i *Integration) GetScanner() *Scanner {
	return i.scanner
}

type APIMap struct {
	Endpoints   []EndpointEntry `json:"endpoints"`
	AuthSchemes []string        `json:"auth_schemes"`
	DataModels  []string        `json:"data_models"`
	GraphQL     *GraphQLSchema  `json:"graphql,omitempty"`
	SpecSource  string          `json:"spec_source"`
}

type EndpointEntry struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Params []string `json:"params"`
	Auth   string   `json:"auth"`
}

type GraphQLSchema struct {
	Endpoint  string   `json:"endpoint"`
	Queries   []string `json:"queries"`
	Mutations []string `json:"mutations"`
	Types     []string `json:"types"`
}

func (i *Integration) ImportSchema(source string) (*APIMap, error) {
	var raw []byte
	var err error

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		if err := validateExternalURL(source); err != nil {
			return nil, fmt.Errorf("SSRF blocked: %w", err)
		}
		client := &http.Client{Timeout: 30 * time.Second}
		resp, fetchErr := client.Get(source)
		if fetchErr != nil {
			return nil, fmt.Errorf("failed to fetch spec: %w", fetchErr)
		}
		defer resp.Body.Close()
		raw, err = io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	} else {
		raw, err = os.ReadFile(source)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read spec: %w", err)
	}

	apiMap := &APIMap{SpecSource: source}

	var openapi3Doc struct {
		OpenAPI string                     `json:"openapi"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &openapi3Doc); err == nil && openapi3Doc.OpenAPI != "" {
		apiMap.Endpoints = parseOpenAPI3Endpoints(openapi3Doc, raw)
		apiMap.AuthSchemes = extractAuthFromSpec(raw)
		return apiMap, nil
	}

	var swagger2Doc struct {
		Swagger string                     `json:"swagger"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &swagger2Doc); err == nil && swagger2Doc.Swagger != "" {
		apiMap.Endpoints = parseSwagger2Endpoints(swagger2Doc, raw)
		apiMap.AuthSchemes = extractAuthFromSpec(raw)
		return apiMap, nil
	}

	return nil, fmt.Errorf("unrecognized spec format")
}

func (i *Integration) IntrospectGraphQL(endpoint string) (*GraphQLSchema, error) {
	if err := validateExternalURL(endpoint); err != nil {
		return nil, fmt.Errorf("SSRF blocked: %w", err)
	}
	introspectionQuery := `{
		"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"
	}`

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(endpoint, "application/json", strings.NewReader(introspectionQuery))
	if err != nil {
		return nil, fmt.Errorf("introspection failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data struct {
			Schema struct {
				QueryType    map[string]any `json:"queryType"`
				MutationType map[string]any `json:"mutationType"`
				Types        []struct {
					Name   string `json:"name"`
					Kind   string `json:"kind"`
					Fields []struct {
						Name string `json:"name"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse introspection: %w", err)
	}

	schema := &GraphQLSchema{Endpoint: endpoint}
	if result.Data.Schema.QueryType != nil {
		schema.Queries = extractFieldNames(result.Data.Schema.QueryType)
	}
	if result.Data.Schema.MutationType != nil {
		schema.Mutations = extractFieldNames(result.Data.Schema.MutationType)
	}

	for _, t := range result.Data.Schema.Types {
		if t.Kind == "OBJECT" && !strings.HasPrefix(t.Name, "__") {
			schema.Types = append(schema.Types, t.Name)
		}
	}

	return schema, nil
}

func (m *APIMap) SystemPromptSection() string {
	if len(m.Endpoints) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n=== API SCHEMA (from spec) ===\n")
	sb.WriteString(fmt.Sprintf("Source: %s\n", m.SpecSource))
	sb.WriteString(fmt.Sprintf("Total endpoints: %d\n\n", len(m.Endpoints)))

	sb.WriteString("ENDPOINTS:\n")
	for _, ep := range m.Endpoints {
		sb.WriteString(fmt.Sprintf("  %s %s", ep.Method, ep.Path))
		if len(ep.Params) > 0 {
			sb.WriteString(fmt.Sprintf(" params=[%s]", strings.Join(ep.Params, ", ")))
		}
		if ep.Auth != "" {
			sb.WriteString(fmt.Sprintf(" auth=%s", ep.Auth))
		}
		sb.WriteString("\n")
	}

	if len(m.AuthSchemes) > 0 {
		sb.WriteString(fmt.Sprintf("\nAUTH SCHEMES: %s\n", strings.Join(m.AuthSchemes, ", ")))
	}

	if m.GraphQL != nil {
		sb.WriteString(fmt.Sprintf("\nGRAPHQL endpoint: %s\n", m.GraphQL.Endpoint))
		if len(m.GraphQL.Queries) > 0 {
			sb.WriteString(fmt.Sprintf("  Queries: %s\n", strings.Join(m.GraphQL.Queries[:min(len(m.GraphQL.Queries), 20)], ", ")))
		}
		if len(m.GraphQL.Mutations) > 0 {
			sb.WriteString(fmt.Sprintf("  Mutations: %s\n", strings.Join(m.GraphQL.Mutations[:min(len(m.GraphQL.Mutations), 20)], ", ")))
		}
	}

	sb.WriteString("\nUse this schema for targeted testing. Test each endpoint for vulnerabilities.\n")
	sb.WriteString("For IDOR testing, focus on endpoints with {id}, :id, or similar path parameters.\n")
	return sb.String()
}

func parseOpenAPI3Endpoints(doc struct {
	OpenAPI string                     `json:"openapi"`
	Paths   map[string]json.RawMessage `json:"paths"`
}, raw []byte) []EndpointEntry {
	var endpoints []EndpointEntry
	for path, methodsRaw := range doc.Paths {
		var methods map[string]json.RawMessage
		if err := json.Unmarshal(methodsRaw, &methods); err != nil {
			continue
		}
		for method := range methods {
			method = strings.ToUpper(method)
			if method == "PARAMETERS" || method == "SERVERS" || method == "SUMMARY" || method == "DESCRIPTION" {
				continue
			}
			var op map[string]json.RawMessage
			json.Unmarshal(methodsRaw, &op)

			entry := EndpointEntry{Method: method, Path: path}
			if paramsRaw, ok := op["parameters"]; ok {
				var params []struct {
					Name string `json:"name"`
					In   string `json:"in"`
				}
				if json.Unmarshal(paramsRaw, &params) == nil {
					for _, p := range params {
						entry.Params = append(entry.Params, fmt.Sprintf("%s:%s", p.Name, p.In))
					}
				}
			}
			if secRaw, ok := op["security"]; ok && len(secRaw) > 0 {
				entry.Auth = "required"
			}
			endpoints = append(endpoints, entry)
		}
	}
	return endpoints
}

func parseSwagger2Endpoints(doc struct {
	Swagger string                     `json:"swagger"`
	Paths   map[string]json.RawMessage `json:"paths"`
}, raw []byte) []EndpointEntry {
	var endpoints []EndpointEntry
	for path, methodsRaw := range doc.Paths {
		var methods map[string]json.RawMessage
		if err := json.Unmarshal(methodsRaw, &methods); err != nil {
			continue
		}
		for method := range methods {
			method = strings.ToUpper(method)
			if method == "PARAMETERS" {
				continue
			}
			endpoints = append(endpoints, EndpointEntry{Method: method, Path: path})
		}
	}
	return endpoints
}

func extractAuthFromSpec(raw []byte) []string {
	var auths []string
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return auths
	}

	var schemes map[string]json.RawMessage
	for _, key := range []string{"components", "securityDefinitions"} {
		if raw, ok := doc[key]; ok {
			var inner map[string]json.RawMessage
			if err := json.Unmarshal(raw, &inner); err == nil {
				if secRaw, ok := inner["securitySchemes"]; ok {
					schemes = make(map[string]json.RawMessage)
					json.Unmarshal(secRaw, &schemes)
				} else {
					schemes = inner
				}
			}
			break
		}
	}

	for name, schemeRaw := range schemes {
		var scheme map[string]any
		if err := json.Unmarshal(schemeRaw, &scheme); err == nil {
			if typ, ok := scheme["type"].(string); ok {
				auths = append(auths, fmt.Sprintf("%s(%s)", name, typ))
			}
		}
	}
	return auths
}

func extractFieldNames(obj map[string]any) []string {
	var names []string
	if fields, ok := obj["fields"].([]any); ok {
		for _, f := range fields {
			if field, ok := f.(map[string]any); ok {
				if name, ok := field["name"].(string); ok {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hasScheme(target string) bool {
	for i := 0; i < len(target); i++ {
		if target[i] == ':' {
			return i > 0
		}
	}
	return false
}

func stringsTrimRight(s, cutset string) string {
	for len(s) > 0 && len(cutset) > 0 && s[len(s)-1] == cutset[len(cutset)-1] {
		s = s[:len(s)-1]
	}
	return s
}
