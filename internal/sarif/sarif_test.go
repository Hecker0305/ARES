package sarif

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewGenerator(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	if g == nil {
		t.Fatal("expected non-nil Generator")
	}
	if g.toolName != "ARES" {
		t.Errorf("expected toolName ARES, got %s", g.toolName)
	}
	if g.toolVersion != "1.0.0" {
		t.Errorf("expected toolVersion 1.0.0, got %s", g.toolVersion)
	}
	if len(g.findings) != 0 {
		t.Errorf("expected 0 findings initially, got %d", len(g.findings))
	}
}

func TestAddFinding(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	g.AddFinding(Finding{ID: "test-1", Type: "sqli"})
	if len(g.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(g.findings))
	}
	if g.findings[0].ID != "test-1" {
		t.Errorf("expected ID test-1, got %s", g.findings[0].ID)
	}
}

func TestAddFindings(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	findings := []Finding{
		{ID: "f1", Type: "sqli"},
		{ID: "f2", Type: "xss"},
	}
	g.AddFindings(findings)
	if len(g.findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(g.findings))
	}
}

func TestGenerate_BasicReport(t *testing.T) {
	g := NewGenerator("ARES-Engine", "2.0.0")
	g.AddFinding(Finding{
		ID:         "find-1",
		Type:       "sqli",
		Severity:   "critical",
		Target:     "http://example.com/page?id=1",
		Evidence:   "SQL syntax error",
		Confidence: 0.95,
		CWE:        "CWE-89",
		Timestamp:  time.Now(),
	})

	data, err := g.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if report.Schema != "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json" {
		t.Errorf("unexpected schema: %s", report.Schema)
	}
	if report.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "ARES-Engine" {
		t.Errorf("expected driver name ARES-Engine, got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", run.Tool.Driver.Version)
	}
	if run.Tool.Driver.Organization != "ARES Security" {
		t.Errorf("expected organization ARES Security, got %s", run.Tool.Driver.Organization)
	}
}

func TestGenerate_Rules(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	g.AddFinding(Finding{ID: "f1", Type: "xss", Severity: "high", CWE: "CWE-79"})
	g.AddFinding(Finding{ID: "f2", Type: "sqli", Severity: "critical", CWE: "CWE-89"})
	g.AddFinding(Finding{ID: "f3", Type: "xss", Severity: "high", CWE: "CWE-79"})

	data, _ := g.Generate()
	var report Report
	json.Unmarshal(data, &report)

	rules := report.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 unique rules, got %d", len(rules))
	}

	ruleMap := make(map[string]Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	if rule, ok := ruleMap["xss"]; !ok {
		t.Error("expected rule for xss")
	} else {
		if rule.ShortDescription == nil || rule.ShortDescription.Text != "xss vulnerability detected" {
			t.Errorf("unexpected short description: %v", rule.ShortDescription)
		}
		if rule.Properties == nil || len(rule.Properties.Tags) == 0 {
			t.Error("expected rule properties with tags")
		}
	}

	if rule, ok := ruleMap["sqli"]; !ok {
		t.Error("expected rule for sqli")
	} else {
		if rule.HelpURI != "https://cwe.mitre.org/data/definitions/89.html" {
			t.Errorf("unexpected help URI: %s", rule.HelpURI)
		}
	}
}

func TestGenerate_Results(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	now := time.Now()
	g.AddFinding(Finding{
		ID:          "f1",
		Type:        "rce",
		Severity:    "critical",
		Target:      "http://example.com/cmd",
		Payload:     "id",
		Evidence:    "uid=0(root)",
		Confidence:  0.99,
		CWE:         "CWE-78",
		CVE:         "CVE-2024-1234",
		Remediation: "Sanitize user input",
		FilePath:    "src/handler.go",
		Line:        42,
		Timestamp:   now,
	})

	data, _ := g.Generate()
	var report Report
	json.Unmarshal(data, &report)

	results := report.Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.RuleID != "rce" {
		t.Errorf("expected ruleId rce, got %s", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("expected level error, got %s", r.Level)
	}
	if r.Message.Text == "" {
		t.Error("expected non-empty message text")
	}

	if r.Properties == nil {
		t.Fatal("expected result properties")
	}
	if r.Properties.Severity != "critical" {
		t.Errorf("expected severity critical, got %s", r.Properties.Severity)
	}
	if r.Properties.CWE != "CWE-78" {
		t.Errorf("expected CWE-78, got %s", r.Properties.CWE)
	}
	if r.Properties.CVE != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", r.Properties.CVE)
	}
	if r.Properties.Confidence != 0.99 {
		t.Errorf("expected confidence 0.99, got %f", r.Properties.Confidence)
	}
	if r.Properties.Remediation != "Sanitize user input" {
		t.Errorf("unexpected remediation: %s", r.Properties.Remediation)
	}
	if r.Properties.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestGenerate_LocationEncoding(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	g.AddFinding(Finding{
		ID:       "f1",
		Type:     "lfi",
		Severity: "high",
		Target:   "http://example.com/file=../../etc/passwd",
		FilePath: "src/controller.go",
		Line:     15,
	})

	data, _ := g.Generate()
	var report Report
	json.Unmarshal(data, &report)

	result := report.Runs[0].Results[0]
	if len(result.Locations) != 2 {
		t.Fatalf("expected 2 locations (file + URL), got %d", len(result.Locations))
	}

	fileLoc := result.Locations[0]
	if fileLoc.PhysicalLocation == nil {
		t.Fatal("expected physical location for file")
	}
	if fileLoc.PhysicalLocation.ArtifactLocation.URI != "src/controller.go" {
		t.Errorf("expected URI src/controller.go, got %s", fileLoc.PhysicalLocation.ArtifactLocation.URI)
	}
	if fileLoc.PhysicalLocation.Region == nil || fileLoc.PhysicalLocation.Region.StartLine != 15 {
		t.Errorf("expected startLine 15, got %v", fileLoc.PhysicalLocation.Region)
	}

	urlLoc := result.Locations[1]
	if len(urlLoc.LogicalLocations) != 1 {
		t.Fatalf("expected 1 logical location, got %d", len(urlLoc.LogicalLocations))
	}
	if urlLoc.LogicalLocations[0].Name != "http://example.com/file=../../etc/passwd" {
		t.Errorf("unexpected logical location name: %s", urlLoc.LogicalLocations[0].Name)
	}
	if urlLoc.LogicalLocations[0].Kind != "url" {
		t.Errorf("expected kind url, got %s", urlLoc.LogicalLocations[0].Kind)
	}
}

func TestGenerate_Fingerprints(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	g.AddFinding(Finding{
		ID:      "f1",
		Type:    "ssrf",
		Payload: "http://internal/admin",
	})

	data, _ := g.Generate()
	var report Report
	json.Unmarshal(data, &report)

	r := report.Runs[0].Results[0]
	if r.Fingerprints == nil {
		t.Fatal("expected fingerprints")
	}
	if _, ok := r.Fingerprints["payloadHash"]; !ok {
		t.Error("expected payloadHash fingerprint")
	}
}

func TestGenerate_EmptyFindings(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	data, err := g.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report Report
	json.Unmarshal(data, &report)
	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(report.Runs[0].Results))
	}
	if len(report.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(report.Runs[0].Tool.Driver.Rules))
	}
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "none"},
		{"unknown", "warning"},
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"", "warning"},
	}
	for _, tt := range tests {
		got := severityToLevel(tt.severity)
		if got != tt.want {
			t.Errorf("severityToLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestHumanReadableName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sqli", "SQL Injection"},
		{"xss", "Cross-Site Scripting"},
		{"ssrf", "Server-Side Request Forgery"},
		{"rce", "Remote Code Execution"},
		{"idor", "Insecure Direct Object Reference"},
		{"csrf", "Cross-Site Request Forgery"},
		{"lfi", "Local File Inclusion"},
		{"rfi", "Remote File Inclusion"},
		{"xxe", "XML External Entity"},
		{"ssti", "Server-Side Template Injection"},
		{"nosqli", "NoSQL Injection"},
		{"deserial", "Insecure Deserialization"},
		{"traversal", "Path Traversal"},
		{"oauth", "OAuth/OIDC Misconfiguration"},
		{"prototype_pollution", "Prototype Pollution"},
	}
	for _, tt := range tests {
		got := humanReadableName(tt.input)
		if got != tt.want {
			t.Errorf("humanReadableName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHumanReadableName_Unknown(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"custom_vuln", "Custom Vuln"},
		{"multi_word_type", "Multi Word Type"},
		{"single", "Single"},
		{"", ""},
	}
	for _, tt := range tests {
		got := humanReadableName(tt.input)
		if got != tt.want {
			t.Errorf("humanReadableName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	h1 := fingerprint("hello")
	h2 := fingerprint("hello")
	h3 := fingerprint("world")

	if h1 != h2 {
		t.Error("fingerprint should be deterministic")
	}
	if h1 == h3 {
		t.Error("different inputs should produce different fingerprints")
	}
	if len(h1) != 16 {
		t.Errorf("expected 16 char hex string, got %d chars: %s", len(h1), h1)
	}
}

func TestFingerprint_Empty(t *testing.T) {
	h := fingerprint("")
	if h == "" {
		t.Error("fingerprint of empty string should not be empty")
	}
	if len(h) != 16 {
		t.Errorf("expected 16 char hex string, got %d chars: %s", len(h), h)
	}
}

func TestResult_RuleIndex(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	g.AddFinding(Finding{ID: "f1", Type: "a"})
	g.AddFinding(Finding{ID: "f2", Type: "b"})

	data, _ := g.Generate()
	var report Report
	json.Unmarshal(data, &report)

	results := report.Runs[0].Results
	for i, r := range results {
		if r.RuleIndex != i {
			t.Errorf("result %d: expected RuleIndex %d, got %d", i, i, r.RuleIndex)
		}
	}
}

func TestGenerate_ValidJSON(t *testing.T) {
	g := NewGenerator("ARES", "1.0.0")
	for i := 0; i < 100; i++ {
		g.AddFinding(Finding{
			ID:        strings.ToTitle(string(rune('a' + i%26))),
			Type:      "test_type",
			Severity:  []string{"low", "medium", "high", "critical"}[i%4],
			Timestamp: time.Now(),
		})
	}

	data, err := g.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(report.Runs[0].Results) != 100 {
		t.Errorf("expected 100 results, got %d", len(report.Runs[0].Results))
	}
}
