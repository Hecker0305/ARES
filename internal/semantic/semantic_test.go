package semantic

import (
	"testing"
)

func TestClassifyEndpoint(t *testing.T) {
	em := ClassifyEndpoint("/api/users/{id}", "GET")
	if em.Path != "/api/users/{id}" {
		t.Errorf("expected /api/users/{id}, got %s", em.Path)
	}
	if em.Method != "GET" {
		t.Errorf("expected GET, got %s", em.Method)
	}
}

func TestHighRiskEndpoints(t *testing.T) {
	model := &AppModel{
		Target: "example.com",
		Endpoints: []EndpointModel{
			{Path: "/admin", RiskLevel: "high"},
			{Path: "/public", RiskLevel: "low"},
		},
	}
	high := model.HighRiskEndpoints()
	if len(high) != 1 {
		t.Errorf("expected 1 high risk, got %d", len(high))
	}
}

func TestAttackPriorities(t *testing.T) {
	model := &AppModel{
		Endpoints: []EndpointModel{
			{Path: "/api/login", Method: "POST", Threat: "authentication bypass"},
			{Path: "/api/search", Method: "GET", Threat: "sql injection"},
		},
	}
	priorities := model.AttackPriorities()
	if len(priorities) == 0 {
		t.Error("expected at least 1 priority")
	}
}

func TestSuggestPayloads(t *testing.T) {
	model := &AppModel{
		Endpoints: []EndpointModel{
			{Path: "/api/search", RiskLevel: "high"},
		},
	}
	payloads := model.SuggestPayloads()
	if payloads == nil {
		t.Error("expected non-nil payloads")
	}
}

func TestExcludedPaths(t *testing.T) {
	model := &AppModel{
		Endpoints: []EndpointModel{
			{Path: "/health"},
			{Path: "/metrics"},
			{Path: "/api/users"},
		},
	}
	_ = model.ExcludedPaths()
}

func TestModelString(t *testing.T) {
	model := &AppModel{
		Target:    "example.com",
		Endpoints: []EndpointModel{{Path: "/", Method: "GET"}},
	}
	s := model.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

func TestModelToJSON(t *testing.T) {
	model := &AppModel{
		Target:    "example.com",
		TechStack: []string{"nginx", "python"},
	}
	json := ModelToJSON(model)
	if json == "" {
		t.Error("expected non-empty JSON")
	}
}

func TestParseClassification(t *testing.T) {
	em, err := ParseClassification(
		`{"purpose":"user authentication","threat":"brute force","risk_level":"high","data_type":"credentials","auth_required":true}`,
		"/login", "POST",
	)
	if err != nil {
		t.Fatalf("ParseClassification error: %v", err)
	}
	if em.Purpose != "user authentication" {
		t.Errorf("expected user authentication, got %s", em.Purpose)
	}
}

func TestBuildFromReconnData(t *testing.T) {
	model, err := BuildFromReconnData(
		[]string{"GET /api/users", "POST /api/login"},
		[]string{"nginx", "python"},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildFromReconnData error: %v", err)
	}
	if model == nil {
		t.Fatal("expected non-nil model")
	}
	if len(model.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(model.Endpoints))
	}
}
