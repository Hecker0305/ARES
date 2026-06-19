package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/security"
)

type Schema struct {
	Types         []TypeDef `json:"types"`
	Queries       []Field   `json:"queries"`
	Mutations     []Field   `json:"mutations"`
	Subscriptions []Field   `json:"subscriptions"`
	Enums         []EnumDef `json:"enums"`
}

type TypeDef struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Fields      []Field  `json:"fields"`
	InputFields []Field  `json:"inputFields"`
	Interfaces  []string `json:"interfaces"`
}

type Field struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Args       []InputArg `json:"args"`
	Required   bool       `json:"required"`
	Deprecated bool       `json:"deprecated"`
}

type InputArg struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type EnumDef struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type FieldInfo struct {
	Name         string
	Type         FieldType
	Args         []FieldArg
	IsDeprecated bool
}

type FieldArg struct {
	Name         string
	Type         FieldType
	DefaultValue any
}

type EnumValue struct {
	Name         string
	IsDeprecated bool
}

type FieldType struct {
	Kind   string
	Name   string
	OfType *FieldType
}

type FullType struct {
	Name        string
	Kind        string
	Fields      []FieldInfo
	InputFields []FieldInfo
	EnumValues  []EnumValue
	Interfaces  []TypeRef
}

type TypeRef struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type IntrospectionQuery struct {
	Data struct {
		Schema SchemaIntrospection `json:"__schema"`
	} `json:"data"`
}

type SchemaIntrospection struct {
	QueryType        *TypeRef   `json:"queryType"`
	MutationType     *TypeRef   `json:"mutationType"`
	SubscriptionType *TypeRef   `json:"subscriptionType"`
	Types            []FullType `json:"types"`
}

type Pipeline struct {
	client                      *http.Client
	schemaURL                   string
	headers                     map[string]string
	schema                      *Schema
	schemaMu                    sync.RWMutex
	introspectionEnabled        bool
	requireAuthForIntrospection bool
}

func NewPipeline(schemaURL string, headers map[string]string) *Pipeline {
	return &Pipeline{
		client:                      &http.Client{Timeout: 30 * time.Second},
		schemaURL:                   schemaURL,
		headers:                     headers,
		introspectionEnabled:        false,
		requireAuthForIntrospection: true,
	}
}

func (p *Pipeline) EnableIntrospection() {
	p.introspectionEnabled = true
}

func (p *Pipeline) SetRequireAuthForIntrospection(required bool) {
	p.requireAuthForIntrospection = required
}

func (p *Pipeline) hasAuthHeader() bool {
	for k, v := range p.headers {
		if strings.EqualFold(k, "Authorization") && v != "" {
			return true
		}
	}
	return false
}

func validateEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http/https schemes allowed: %s", u.Scheme)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("endpoint %s is not allowed", host)
		}
	}
	// Also check localhost hostname variants
	if host == "localhost" || host == "localhost.localdomain" {
		return fmt.Errorf("endpoint %s is not allowed", host)
	}
	return nil
}

func (p *Pipeline) Introspect(ctx context.Context) (*Schema, error) {
	if !p.introspectionEnabled {
		return nil, fmt.Errorf("GraphQL introspection is disabled in production; enable explicitly via EnableIntrospection()")
	}
	if p.requireAuthForIntrospection && !p.hasAuthHeader() {
		return nil, fmt.Errorf("GraphQL introspection requires Authorization header")
	}
	if err := validateEndpoint(p.schemaURL); err != nil {
		return nil, fmt.Errorf("schema URL validation failed: %w", err)
	}
	query := `{"query":"{ __schema { queryType { name kind } mutationType { name kind } subscriptionType { name kind } types { name kind ...FullType } } } fragment FullType on __Type { name kind fields(includeDeprecated: true) { name args { name type defaultValue } type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } isDeprecated args { name type defaultValue } } inputFields { name type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } enumValues(includeDeprecated: true) { name isDeprecated } interfaces { name kind } } }"}`
	body := strings.NewReader(query)
	req, err := http.NewRequestWithContext(ctx, "POST", p.schemaURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var iq IntrospectionQuery
	if err := json.Unmarshal(respBody, &iq); err != nil {
		return nil, fmt.Errorf("parse introspection: %w", err)
	}

	schema := &Schema{}
	for _, ft := range iq.Data.Schema.Types {
		name := ft.Name
		kind := ft.Kind
		if name == "" || strings.HasPrefix(name, "__") {
			continue
		}

		td := TypeDef{Name: name, Kind: kind}
		if td.Kind == "OBJECT" || td.Kind == "INTERFACE" {
			for _, f := range ft.Fields {
				field := Field{
					Name:       f.Name,
					Type:       f.Type.Name,
					Deprecated: f.IsDeprecated,
				}
				for _, a := range f.Args {
					field.Args = append(field.Args, InputArg{
						Name:     a.Name,
						Type:     a.Type.Name,
						Required: strings.Contains(a.Type.Kind, "NON_NULL"),
					})
				}
				td.Fields = append(td.Fields, field)
			}
			schema.Queries = append(schema.Queries, td.Fields...)
		}
		if td.Kind == "INPUT_OBJECT" {
			for _, f := range ft.InputFields {
				td.Fields = append(td.Fields, Field{
					Name:     f.Name,
					Type:     f.Type.Name,
					Required: strings.Contains(f.Type.Kind, "NON_NULL"),
				})
			}
		}
		if td.Kind == "ENUM" {
			ed := EnumDef{Name: td.Name}
			for _, ev := range ft.EnumValues {
				ed.Values = append(ed.Values, ev.Name)
			}
			schema.Enums = append(schema.Enums, ed)
		}
		schema.Types = append(schema.Types, td)
	}

	if iq.Data.Schema.MutationType != nil && iq.Data.Schema.MutationType.Name != "" {
		for _, t := range schema.Types {
			if t.Name == iq.Data.Schema.MutationType.Name {
				schema.Mutations = t.Fields
				break
			}
		}
	}
	if iq.Data.Schema.SubscriptionType != nil && iq.Data.Schema.SubscriptionType.Name != "" {
		for _, t := range schema.Types {
			if t.Name == iq.Data.Schema.SubscriptionType.Name {
				schema.Subscriptions = t.Fields
				break
			}
		}
	}

	p.schemaMu.Lock()
	p.schema = schema
	p.schemaMu.Unlock()

	return schema, nil
}

var validCookieValue = regexp.MustCompile(`^[a-zA-Z0-9\-_\.=;]+$`)

func (p *Pipeline) TestIDOR(ctx context.Context, endpoint string, victimSession, attackerSession string) []string {
	if err := security.ValidateURL(endpoint); err != nil {
		return nil
	}
	if !validCookieValue.MatchString(victimSession) || !validCookieValue.MatchString(attackerSession) {
		return nil
	}
	var findings []string

	queries := p.getFields()
	for _, f := range queries {
		if !strings.Contains(strings.ToLower(f.Name), "user") && !strings.Contains(strings.ToLower(f.Name), "account") && !strings.Contains(strings.ToLower(f.Name), "profile") {
			continue
		}

		q := fmt.Sprintf(`{"query":"{%s(id: 1){id name email}}"}`, f.Name)
		victimReq, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(q))
		victimReq.Header.Set("Content-Type", "application/json")
		victimReq.Header.Set("Cookie", victimSession)

		attackerReq, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(q))
		attackerReq.Header.Set("Content-Type", "application/json")
		attackerReq.Header.Set("Cookie", attackerSession)

		victimResp, vErr := p.client.Do(victimReq)
		attackerResp, aErr := p.client.Do(attackerReq)

		var vData, aData map[string]interface{}
		if vErr == nil {
			json.NewDecoder(victimResp.Body).Decode(&vData)
			victimResp.Body.Close()
		}
		if aErr == nil {
			json.NewDecoder(attackerResp.Body).Decode(&aData)
			attackerResp.Body.Close()
		}

		if vData != nil && aData != nil {
			vID := extractID(vData)
			aID := extractID(aData)
			if vID != aID && vID != "" && aID != "" && vID != "null" {
				findings = append(findings, fmt.Sprintf("IDOR: %s returned different data for id=1 with different sessions", f.Name))
			}
		}
	}
	return findings
}

func (p *Pipeline) TestMassAssignment(ctx context.Context, endpoint string, authCookie string) []string {
	if err := security.ValidateURL(endpoint); err != nil {
		return nil
	}
	var findings []string

	for _, mut := range p.GetMutations() {
		if len(mut.Args) == 0 {
			continue
		}

		testFields := []string{"role", "admin", "isAdmin", "permissions", "groups", "active", "verified"}
		for _, tf := range testFields {
			foundField := false
			for _, arg := range mut.Args {
				if arg.Name == tf || strings.Contains(strings.ToLower(arg.Name), tf) {
					foundField = true
					break
				}
			}
			if !foundField {
				continue
			}

			for _, sensitiveField := range []string{"role", "admin", "isAdmin"} {
				query := fmt.Sprintf(`{"query":"mutation{}{%s(%s:"admin"){id}}"}`, mut.Name, sensitiveField)
				req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(query))
				req.Header.Set("Content-Type", "application/json")
				if authCookie != "" {
					req.Header.Set("Cookie", authCookie)
				}

				resp, err := p.client.Do(req)
				if err != nil {
					continue
				}

				if resp.StatusCode == 200 {
					var result map[string]interface{}
					json.NewDecoder(resp.Body).Decode(&result)
					if result["errors"] == nil {
						findings = append(findings, fmt.Sprintf("Mass assignment: mutation %s accepts %s without authorization check", mut.Name, sensitiveField))
					}
				}
				resp.Body.Close()
			}
		}
	}
	return findings
}

func (p *Pipeline) TestAuthChecks(ctx context.Context, endpoint string) []string {
	if err := security.ValidateURL(endpoint); err != nil {
		return nil
	}
	var findings []string

	for _, q := range p.GetQueries() {
		if len(q.Args) == 0 {
			continue
		}

		query := fmt.Sprintf(`{"query":"{%s(id:1){id}}"}`, q.Name)
		req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(query))
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			if result["errors"] == nil {
				findings = append(findings, fmt.Sprintf("Missing auth: query %s returns data without authentication", q.Name))
			}
		}
		resp.Body.Close()
	}

	for _, m := range p.GetMutations() {
		query := fmt.Sprintf(`{"query":"mutation{}{%s()}"}`, m.Name)
		req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(query))
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			if result["errors"] == nil {
				findings = append(findings, fmt.Sprintf("Missing auth: mutation %s executes without authentication", m.Name))
			}
		}
		resp.Body.Close()
	}
	return findings
}

func (p *Pipeline) TestBatchQuery(ctx context.Context, endpoint string) []string {
	if err := security.ValidateURL(endpoint); err != nil {
		return nil
	}
	var findings []string

	batch := `{"query":"{ u1: user(id: 1) { id email } u2: user(id: 2) { id email } u3: user(id: 3) { id email } }"}`
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(batch))
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		findings = append(findings, "GraphQL batching enabled — enumerate multiple IDs in single query")
	}
	return findings
}

func (p *Pipeline) TestFieldSuggestions(ctx context.Context, endpoint string) []string {
	if !p.introspectionEnabled {
		return []string{"GraphQL introspection disabled — schema not exposed"}
	}
	if err := security.ValidateURL(endpoint); err != nil {
		return nil
	}
	var findings []string

	query := `{"query":"{ __type(name: \"Query\") { fields { name } } }"}`
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(query))
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		findings = append(findings, "GraphQL introspection enabled — schema fully exposed")
	}
	return findings
}

func (p *Pipeline) getFields() []Field {
	p.schemaMu.RLock()
	defer p.schemaMu.RUnlock()
	if p.schema == nil {
		return nil
	}
	return p.schema.Queries
}

func (p *Pipeline) GetMutations() []Field {
	p.schemaMu.RLock()
	defer p.schemaMu.RUnlock()
	if p.schema == nil {
		return nil
	}
	return p.schema.Mutations
}

func (p *Pipeline) GetQueries() []Field {
	p.schemaMu.RLock()
	defer p.schemaMu.RUnlock()
	if p.schema == nil {
		return nil
	}
	return p.schema.Queries
}

func extractID(data map[string]interface{}) string {
	if d, ok := data["data"].(map[string]interface{}); ok {
		for _, v := range d {
			if m, ok := v.(map[string]interface{}); ok {
				if id, ok := m["id"]; ok {
					return fmt.Sprintf("%v", id)
				}
			}
		}
	}
	return ""
}

func RunPipeline(ctx context.Context, schemaURL string, headers map[string]string, victimSession, attackerSession, authCookie string) map[string][]string {
	results := make(map[string][]string)

	p := NewPipeline(schemaURL, headers)

	schema, err := p.Introspect(ctx)
	if err != nil || schema == nil || len(schema.Queries) == 0 {
		return results
	}

	results["schema"] = []string{
		fmt.Sprintf("GraphQL schema: %d types, %d queries, %d mutations",
			len(schema.Types), len(schema.Queries), len(schema.Mutations)),
	}

	results["idor"] = p.TestIDOR(ctx, schemaURL, victimSession, attackerSession)
	results["mass-assignment"] = p.TestMassAssignment(ctx, schemaURL, authCookie)
	results["missing-auth"] = p.TestAuthChecks(ctx, schemaURL)
	results["batch-enum"] = p.TestBatchQuery(ctx, schemaURL)
	results["introspection"] = p.TestFieldSuggestions(ctx, schemaURL)

	return results
}
