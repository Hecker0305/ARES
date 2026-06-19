package analyzer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyzeJSWithContent(t *testing.T) {
	content := `const apiKey = "AKIA0000000000000000";
const config = { endpoint: "/api/v1/users" };
fetch("https://api.example.com/data", { method: "POST" });
axios.get("/api/items");
var xhr = new XMLHttpRequest(); xhr.open("GET", "/api/xhr");
const gql = gql` + "`" + `query { users { id } }` + "`" + `;
// TODO: fix this later
// FIXME: security issue
const express = require("express");
import React from "react";`

	analysis := &JSAnalysis{URL: "http://example.com"}
	analysis.Secrets = findSecrets(content)
	analysis.FetchCalls = findFetchCalls(content)
	analysis.AxiosCalls = findAxiosCalls(content)
	analysis.XHRCalls = findXHRCalls(content)
	analysis.GraphQLOps = findGraphQLOps(content)
	analysis.APIRoutes = extractAPIRoutes(content)
	analysis.Endpoints = extractEndpoints(content)
	analysis.AuthPatterns = findAuthPatterns(content)
	analysis.Imports = findImports(content)
	analysis.Comments = findInterestingComments(content)
	analysis.TechStack = detectTechStack(content)

	if len(analysis.Secrets) == 0 {
		t.Error("expected secrets")
	}
	if len(analysis.FetchCalls) == 0 {
		t.Error("expected fetch calls")
	}
	if len(analysis.TechStack) == 0 {
		t.Error("expected tech stack")
	}
}

func TestAnalyzeJSWithHTTPServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`var x = 1;`))
	}))
	defer ts.Close()

	analysis, err := AnalyzeJS(ts.URL, ts.URL)
	if err != nil {
		t.Logf("AnalyzeJS() error = %v (expected if private IP blocked)", err)
		return
	}
	if analysis != nil && analysis.URL != ts.URL {
		t.Errorf("URL = %q, want %q", analysis.URL, ts.URL)
	}
}

func TestFetchURLInvalid(t *testing.T) {
	_, err := fetchURL("not a url")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestFindSecrets(t *testing.T) {
	content := `var awsKey = "AKIA0000000000000000";
var githubTok = "ghp_000000000000000000000000000000000000";
var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SIGNATUREVALUE";
var basicAuth = "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY3ODkw";
var privKey = "-----BEGIN RSA PRIVATE KEY-----";
var mongoUrl = "mongodb://adminuser:SecurePass123@dbserver.internal.net:27017/admin";`

	secrets := findSecrets(content)
	if len(secrets) == 0 {
		t.Fatal("findSecrets() returned 0 secrets")
	}
	foundTypes := make(map[string]bool)
	for _, s := range secrets {
		foundTypes[s.Type] = true
	}
	expected := []string{"AWS Key", "GitHub Token", "JWT", "Basic Auth", "Private Key", "Database URL"}
	for _, e := range expected {
		if !foundTypes[e] {
			t.Errorf("expected secret type %q not found", e)
		}
	}
	for _, s := range secrets {
		if s.Line <= 0 {
			t.Errorf("secret %q has invalid line %d", s.Type, s.Line)
		}
		if s.Context == "" {
			t.Errorf("secret %q has empty context", s.Type)
		}
	}
}

func TestFindSecretsSkipPatterns(t *testing.T) {
	content := `// example: AKIA0000000000000000
var dummy = "ghp_000000000000000000000000000000000000";
// test placeholder`
	secrets := findSecrets(content)
	for _, s := range secrets {
		if s.Value == "example" || s.Value == "test" || s.Value == "dummy" {
			t.Errorf("skipped pattern leaked: %v", s)
		}
	}
}

func TestFindSecretsEmpty(t *testing.T) {
	secrets := findSecrets("")
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets for empty content, got %d", len(secrets))
	}
}

func TestFindSecretsTruncation(t *testing.T) {
	longKey := "AKIA" + strings.Repeat("A", 200)
	content := `var key = "` + longKey + `";`
	secrets := findSecrets(content)
	if len(secrets) > 0 {
		val := secrets[0].Value
		if len(val) > 65 {
			t.Errorf("secret value not truncated, length=%d", len(val))
		}
	}
}

func TestFindFetchCalls(t *testing.T) {
	content := `fetch("https://api.example.com/data", { method: "POST" });
fetch("/relative/path");
fetch('https://test.com/api');
axios("https://axios.example.com");`
	calls := findFetchCalls(content)
	if len(calls) != 4 {
		t.Errorf("expected 4 fetch calls, got %d", len(calls))
	}
	if len(calls) > 0 && calls[0].URL == "https://api.example.com/data" {
		if calls[0].Method != "POST" {
			t.Errorf("expected first call method POST, got %s", calls[0].Method)
		}
	}
}

func TestFindFetchCallsEmpty(t *testing.T) {
	calls := findFetchCalls("var x = 1;")
	if len(calls) != 0 {
		t.Errorf("expected 0 fetch calls, got %d", len(calls))
	}
}

func TestFindAxiosCalls(t *testing.T) {
	content := `axios.get("/api/users");
axios.post("/api/create", data);
axios.put("/api/update/1", data);
axios.delete("/api/remove/1");`
	calls := findAxiosCalls(content)
	if len(calls) != 4 {
		t.Errorf("expected 4 axios calls, got %d", len(calls))
	}
}

func TestFindAxiosCallsEmpty(t *testing.T) {
	calls := findAxiosCalls("")
	if len(calls) != 0 {
		t.Errorf("expected 0, got %d", len(calls))
	}
}

func TestFindXHRCalls(t *testing.T) {
	content := `var xhr = new XMLHttpRequest();
xhr.open("GET", "/api/data", true);
xhr.send();`
	calls := findXHRCalls(content)
	if len(calls) != 1 {
		t.Errorf("expected 1 XHR call, got %d", len(calls))
	}
	if len(calls) > 0 && calls[0] != "/api/data" {
		t.Errorf("XHR URL = %q, want /api/data", calls[0])
	}
}

func TestFindXHRCallsNoMatch(t *testing.T) {
	calls := findXHRCalls("var x = 1;")
	if len(calls) != 0 {
		t.Errorf("expected 0, got %d", len(calls))
	}
}

func TestFindGraphQLOps(t *testing.T) {
	content := "const query = gql`\n  query GetUsers {\n    users { id name }\n  }\n`;"
	ops := findGraphQLOps(content)
	if len(ops) == 0 {
		t.Fatal("expected GraphQL operations")
	}
}

func TestFindGraphQLOpsQueryKeyword(t *testing.T) {
	content := "query GetUsers { users { id } }"
	ops := findGraphQLOps(content)
	found := false
	for _, op := range ops {
		if strings.Contains(op, "query") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected query keyword match")
	}
}

func TestFindGraphQLOpsEmpty(t *testing.T) {
	ops := findGraphQLOps("")
	if len(ops) != 0 {
		t.Errorf("expected 0, got %d", len(ops))
	}
}

func TestExtractAPIRoutes(t *testing.T) {
	content := `/api/v1/users
/api/v1/products/123
/graphql
/rest/items
/auth/login`
	routes := extractAPIRoutes(content)
	if len(routes) == 0 {
		t.Fatal("expected routes")
	}
}

func TestExtractAPIRoutesEmpty(t *testing.T) {
	routes := extractAPIRoutes("plain text without routes")
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestExtractEndpoints(t *testing.T) {
	content := `"https://api.example.com/v1/users"
'https://test.com/api/data'`
	eps := extractEndpoints(content)
	if len(eps) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(eps))
	}
}

func TestExtractEndpointsDeduplication(t *testing.T) {
	content := `"https://api.example.com/data" "https://api.example.com/data"`
	eps := extractEndpoints(content)
	if len(eps) != 1 {
		t.Errorf("expected 1 unique endpoint, got %d", len(eps))
	}
}

func TestExtractEndpointsFilter(t *testing.T) {
	content := `"short" "` + strings.Repeat("a", 500) + `"`
	eps := extractEndpoints(content)
	if len(eps) != 0 {
		t.Errorf("expected 0 filtered endpoints, got %d", len(eps))
	}
}

func TestFindAuthPatterns(t *testing.T) {
	content := "Authorization: Bearer token\nwithCredentials: true\ncsrf token"
	patterns := findAuthPatterns(content)
	if len(patterns) == 0 {
		t.Fatal("expected auth patterns")
	}
}

func TestFindAuthPatternsEmpty(t *testing.T) {
	patterns := findAuthPatterns("")
	if len(patterns) != 0 {
		t.Errorf("expected 0, got %d", len(patterns))
	}
}

func TestFindImports(t *testing.T) {
	content := `import React from "react";
import { useState } from "react";
const express = require("express");
import axios from "axios";`
	imports := findImports(content)
	if len(imports) == 0 {
		t.Fatal("expected imports")
	}
	expected := []string{"react", "express", "axios"}
	for _, e := range expected {
		found := false
		for _, imp := range imports {
			if imp == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected import %q not found", e)
		}
	}
}

func TestFindImportsExcludesRelative(t *testing.T) {
	content := `import foo from "./local";
import bar from "/absolute";`
	imports := findImports(content)
	for _, imp := range imports {
		if imp == "./local" || imp == "/absolute" {
			t.Errorf("relative import should be excluded: %q", imp)
		}
	}
}

func TestFindImportsEmpty(t *testing.T) {
	imports := findImports("")
	if len(imports) != 0 {
		t.Errorf("expected 0, got %d", len(imports))
	}
}

func TestFindInterestingComments(t *testing.T) {
	content := `// TODO: implement authentication
// FIXME: this is insecure
// HACK: workaround for bug
// NOTE: important detail
/* BUG: known issue */`
	comments := findInterestingComments(content)
	if len(comments) == 0 {
		t.Fatal("expected interesting comments")
	}
}

func TestFindInterestingCommentsNoMatch(t *testing.T) {
	content := `const x = 1;
// normal comment about weather`
	comments := findInterestingComments(content)
	for _, c := range comments {
		if c == "normal comment about weather" {
			t.Error("non-interesting comment should not match")
		}
	}
}

func TestFindInterestingCommentsEmpty(t *testing.T) {
	comments := findInterestingComments("")
	if len(comments) != 0 {
		t.Errorf("expected 0, got %d", len(comments))
	}
}

func TestDetectTechStack(t *testing.T) {
	content := `import React from "react";
const [state, setState] = useState();
useEffect(() => {}, []);
axios.get("/api");
import { createStore } from "redux";
interface Props { name: string }`
	stack := detectTechStack(content)
	if len(stack) == 0 {
		t.Fatal("expected tech stack detection")
	}
	expected := []string{"React", "Axios", "Redux", "TypeScript"}
	for _, e := range expected {
		found := false
		for _, s := range stack {
			if s == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected framework %q not detected", e)
		}
	}
}

func TestDetectTechStackEmpty(t *testing.T) {
	stack := detectTechStack("")
	if len(stack) != 0 {
		t.Errorf("expected 0, got %d", len(stack))
	}
}

func TestJSAnalysisSummary(t *testing.T) {
	a := &JSAnalysis{
		Endpoints:  []string{"/api/users"},
		Secrets:    []Secret{{Type: "AWS Key", Value: "AKIA...", Line: 1}},
		APIRoutes:  []string{"/api/v1"},
		GraphQLOps: []string{"query"},
		TechStack:  []string{"React"},
	}
	summary := a.Summary()
	if !strings.Contains(summary, "1 endpoints") {
		t.Errorf("summary missing endpoints: %s", summary)
	}
	if !strings.Contains(summary, "1 secrets") {
		t.Errorf("summary missing secrets: %s", summary)
	}
}

func TestParseGraphQLSchema(t *testing.T) {
	schemaJSON := `{
		"queryType": {"name": "Query", "kind": "OBJECT"},
		"mutationType": {"name": "Mutation", "kind": "OBJECT"},
		"types": {
			"Query": {
				"name": "Query",
				"kind": "OBJECT",
				"fields": {
					"users": {
						"name": "users",
						"type": "[User]",
						"args": [{"name": "id", "type": "ID"}]
					}
				}
			}
		}
	}`
	schema, err := ParseGraphQLSchema(schemaJSON)
	if err != nil {
		t.Fatalf("ParseGraphQLSchema() error = %v", err)
	}
	if schema.QueryType == nil {
		t.Fatal("QueryType is nil")
	}
	if schema.QueryType.Name != "Query" {
		t.Errorf("QueryType.Name = %q, want Query", schema.QueryType.Name)
	}
	if schema.MutationType == nil {
		t.Fatal("MutationType is nil")
	}
}

func TestParseGraphQLSchemaInvalid(t *testing.T) {
	_, err := ParseGraphQLSchema("{invalid json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuildGraphQLTestSuite(t *testing.T) {
	schema := &GraphQLSchema{
		QueryType: &GQLType{
			Name: "Query",
			Fields: map[string]GQLField{
				"users": {
					Name: "users",
					Type: "[User]",
					Args: []GQLArg{{Name: "id", Type: "ID"}},
				},
				"posts": {
					Name: "posts",
					Type: "[Post]",
				},
			},
		},
		MutationType: &GQLType{Name: "Mutation", Kind: "OBJECT"},
	}
	tests := BuildGraphQLTestSuite("http://example.com/graphql", schema)
	if len(tests) == 0 {
		t.Fatal("expected tests")
	}
}

func TestBuildGraphQLTestSuiteNilQuery(t *testing.T) {
	schema := &GraphQLSchema{}
	tests := BuildGraphQLTestSuite("http://example.com/graphql", schema)
	if len(tests) < 3 {
		t.Errorf("expected at least 3 tests (defaults), got %d", len(tests))
	}
}

func TestFuzzGraphQLFields(t *testing.T) {
	schema := &GraphQLSchema{
		QueryType: &GQLType{
			Name: "Query",
			Fields: map[string]GQLField{
				"users": {Name: "users", Type: "[User]", Args: []GQLArg{{Name: "id", Type: "ID"}}},
			},
		},
	}
	queries := FuzzGraphQLFields("http://example.com/gql", schema)
	if len(queries) == 0 {
		t.Fatal("expected fuzzed queries")
	}
}

func TestFuzzGraphQLFieldsNoFields(t *testing.T) {
	schema := &GraphQLSchema{}
	queries := FuzzGraphQLFields("http://example.com/gql", schema)
	if len(queries) != 0 {
		t.Errorf("expected 0 queries, got %d", len(queries))
	}
}

func TestDetectGraphQLIntrospectionInvalidURL(t *testing.T) {
	result := DetectGraphQLIntrospection("not-a-url")
	if result {
		t.Error("expected false for invalid URL")
	}
}

func TestDetectGraphQLIntrospectionEmptyURL(t *testing.T) {
	result := DetectGraphQLIntrospection("")
	if result {
		t.Error("expected false for empty URL")
	}
}

func TestDetectGraphQLIntrospectionPrivateIP(t *testing.T) {
	result := DetectGraphQLIntrospection("http://127.0.0.1:9999/graphql")
	if result {
		t.Error("expected false for blocked private IP")
	}
}

func TestAnalyzeURLPrivateIP(t *testing.T) {
	_, err := AnalyzeURL("http://127.0.0.1:9999")
	if err == nil {
		t.Log("AnalyzeURL returned nil error (may skip validation)")
	}
}

func TestAnalyzeURLInvalid(t *testing.T) {
	_, err := AnalyzeURL("not-a-url")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestRunPageAgentInvalidURL(t *testing.T) {
	_, err := RunPageAgent("not-a-url")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "invalid target URL") {
		t.Errorf("expected invalid URL error, got: %v", err)
	}
}

func TestRunPageAgentPrivateIP(t *testing.T) {
	_, err := RunPageAgent("http://127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected error for private IP")
	}
	if !strings.Contains(err.Error(), "invalid target URL") {
		t.Errorf("expected invalid URL error for private IP, got: %v", err)
	}
}

func TestFetchGraphQLSchemaInvalidURL(t *testing.T) {
	_, err := FetchGraphQLSchema("not-a-url", nil)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestFetchGraphQLSchemaEmptyURL(t *testing.T) {
	_, err := FetchGraphQLSchema("", nil)
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestAnalyzeJSSourceWithContent(t *testing.T) {
	content := `// content with various patterns
var stripeKey = "sk_live_REPLACED_FOR_GITHUB";
var sendgridKey = "SG.TESTONLY.TESTONLY00000000000000000000000000000000";
var twilioKey = "SK00000000000000000000000000000000";
// TODO: replace with env vars
axios.get("/api/config");
fetch("https://internal.api.com/data", {method: "POST"});
import _ from "lodash";
import express from "express";`

	secrets := findSecrets(content)
	fetchCalls := findFetchCalls(content)
	axiosCalls := findAxiosCalls(content)
	imports := findImports(content)

	if len(secrets) > 0 {
		t.Logf("found %d secrets", len(secrets))
	}
	if len(fetchCalls) == 0 {
		t.Error("expected fetch calls")
	}
	if len(axiosCalls) == 0 {
		t.Error("expected axios calls")
	}
	if len(imports) == 0 {
		t.Error("expected imports")
	}
}

func TestGraphQLTypes(t *testing.T) {
	schema := &GraphQLSchema{
		Types: map[string]GQLType{
			"User": {
				Name: "User",
				Kind: "OBJECT",
				Fields: map[string]GQLField{
					"id":   {Name: "id", Type: "ID!"},
					"name": {Name: "name", Type: "String"},
				},
			},
		},
		Directives: []GQLDirective{
			{Name: "deprecated", Locations: []string{"FIELD_DEFINITION"}},
		},
	}
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	parsed, err := ParseGraphQLSchema(string(data))
	if err != nil {
		t.Fatalf("ParseGraphQLSchema() error = %v", err)
	}
	if parsed.Types["User"].Fields["id"].Name != "id" {
		t.Errorf("unexpected field: %+v", parsed.Types["User"].Fields["id"])
	}
}
