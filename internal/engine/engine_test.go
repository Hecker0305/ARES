package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/ares/engine/internal/agent"
)

func TestNewEngine(t *testing.T) {
	cfg := ScanConfig{
		MaxIterations:  100,
		StuckThreshold: 20,
		MaxWorkers:     3,
	}
	e := NewEngine(cfg)
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.Phase() != PhaseRecon {
		t.Errorf("expected PhaseRecon, got %v", e.Phase())
	}
}

func TestEngineSetPhase(t *testing.T) {
	e := NewEngine(ScanConfig{})
	e.SetPhase(PhaseExploit)
	if e.Phase() != PhaseExploit {
		t.Errorf("expected PhaseExploit, got %v", e.Phase())
	}
}

func TestEngineConfig(t *testing.T) {
	cfg := ScanConfig{MaxIterations: 50}
	e := NewEngine(cfg)
	c := e.Config()
	if c.MaxIterations != 50 {
		t.Errorf("expected 50, got %d", c.MaxIterations)
	}
}

func TestEngineUptime(t *testing.T) {
	e := NewEngine(ScanConfig{})
	u := e.Uptime()
	if u < 0 {
		t.Error("expected non-negative uptime")
	}
}

func TestNewExecutor(t *testing.T) {
	cfg := ScanConfig{MaxIterations: 100}
	ex := NewExecutor(cfg)
	if ex == nil {
		t.Fatal("expected non-nil executor")
	}
	if ex.state == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestBuildCommandSpec(t *testing.T) {
	tests := []struct {
		tool    string
		wantErr bool
	}{
		{"nmap", false},
		{"curl", false},
		{"nikto", false},
		{"nuclei", false},
		{"sqlmap", false},
		{"ffuf", false},
		{"dalfox", false},
		{"gobuster", false},
		{"whatweb", false},
		{"subfinder", false},
		{"unknown", true},
		{"", true},
	}
	for _, tt := range tests {
		spec, err := buildCommandSpec(tt.tool, nil)
		if tt.wantErr && err == nil {
			t.Errorf("buildCommandSpec(%q) expected error", tt.tool)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("buildCommandSpec(%q) unexpected error: %v", tt.tool, err)
		}
		if !tt.wantErr && spec.Binary != tt.tool {
			t.Errorf("expected binary %s, got %s", tt.tool, spec.Binary)
		}
	}
}

func TestValidateTargetArg(t *testing.T) {
	tests := []struct {
		target  string
		wantErr bool
	}{
		{"example.com", false},
		{"192.168.1.1", false},
		{"", true},
		{"-flag", true},
		{"cmd\ninjection", true},
		{"cmd\rinjection", true},
		{"--output", true},
		{"target|ls", true},
		{"target;rm", true},
		{"target$(id)", true},
	}
	for _, tt := range tests {
		err := validateTargetArg(tt.target)
		if tt.wantErr && err == nil {
			t.Errorf("validateTargetArg(%q) expected error", tt.target)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("validateTargetArg(%q) unexpected error: %v", tt.target, err)
		}
	}
}

func TestValidateURLArg(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://example.com", false},
		{"https://example.com/path", false},
		{"", true},
		{"ftp://example.com", true},
		{"javascript:alert(1)", true},
		{"not-a-url", true},
	}
	for _, tt := range tests {
		err := validateURLArg(tt.url)
		if tt.wantErr && err == nil {
			t.Errorf("validateURLArg(%q) expected error", tt.url)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("validateURLArg(%q) unexpected error: %v", tt.url, err)
		}
	}
}

func TestNewScoringEngine(t *testing.T) {
	s := NewScoringEngine()
	if s == nil {
		t.Fatal("expected non-nil scoring engine")
	}
}

func TestCalculateScore(t *testing.T) {
	s := NewScoringEngine()
	f := agent.FindingData{
		Confidence:  0.9,
		Severity:    "critical",
		RawResponse: "successfully extracted data",
		Payload:     "' OR '1'='1",
	}
	score := s.CalculateScore(f)
	if score <= 0 || score > 1.0 {
		t.Errorf("expected score between 0 and 1, got %f", score)
	}
}

func TestSeverityToScore(t *testing.T) {
	s := NewScoringEngine()
	tests := []struct {
		severity string
		want     float64
	}{
		{"critical", 1.0},
		{"high", 0.8},
		{"medium", 0.5},
		{"low", 0.3},
		{"info", 0.1},
		{"unknown", 0.5},
	}
	for _, tt := range tests {
		got := s.severityToScore(tt.severity)
		if got != tt.want {
			t.Errorf("severityToScore(%q) = %f, want %f", tt.severity, got, tt.want)
		}
	}
}

func TestRankFindings(t *testing.T) {
	s := NewScoringEngine()
	findings := []agent.FindingData{
		{Severity: "low", Confidence: 0.3, RawResponse: ""},
		{Severity: "critical", Confidence: 0.9, RawResponse: "found"},
	}
	ranked := s.RankFindings(findings)
	if len(ranked) != 2 {
		t.Errorf("expected 2 ranked findings, got %d", len(ranked))
	}
	if ranked[0].Severity != "critical" {
		t.Error("expected critical finding first")
	}
}

func TestNewFPFilter(t *testing.T) {
	f := NewFPFilter()
	if f == nil {
		t.Fatal("expected non-nil filter")
	}
}

func TestFPFilter_FilterNil(t *testing.T) {
	f := NewFPFilter()
	v := f.Filter(nil)
	if v != VerdictFalsePositive {
		t.Errorf("expected VerdictFalsePositive for nil, got %s", v)
	}
}

func TestFPFilter_FilterEmptyPayload(t *testing.T) {
	f := NewFPFilter()
	v := f.Filter(&FindingCandidate{Payload: "", Output: ""})
	if v != VerdictFalsePositive {
		t.Errorf("expected VerdictFalsePositive for empty, got %s", v)
	}
}

func TestFPFilter_FilterSQLMatch(t *testing.T) {
	f := NewFPFilter()
	v := f.Filter(&FindingCandidate{
		Payload:    "' OR '1'='1",
		Output:     "SQL syntax error near mysql_fetch",
		Confidence: 0.9,
	})
	if v != VerdictVerified {
		t.Errorf("expected VerdictVerified, got %s", v)
	}
}

func TestCheckOOB(t *testing.T) {
	f := NewFPFilter()
	f.SetOOBServer("oob.server.com")
	got := f.checkOOB(&FindingCandidate{
		Payload: "test",
		Output:  "dns callback received",
	})
	if !got {
		t.Error("expected OOB detection")
	}
}

func TestCheckOOB_NoServer(t *testing.T) {
	f := NewFPFilter()
	got := f.checkOOB(&FindingCandidate{Output: "dns"})
	if got {
		t.Error("expected no OOB detection without server")
	}
}

func TestCheckReflectedPayload(t *testing.T) {
	f := NewFPFilter()
	got := f.checkReflectedPayload(&FindingCandidate{
		Payload: "<script>alert(1)</script>",
		Output:  "Reflected: <script>alert(1)</script> in response",
	})
	if !got {
		t.Error("expected reflected payload detection")
	}
}

func TestCheckCloudMetadata(t *testing.T) {
	f := NewFPFilter()
	got := f.checkCloudMetadata("169.254.169.254 metadata endpoint")
	if !got {
		t.Error("expected cloud metadata detection")
	}
}

func TestProofPatternMatch(t *testing.T) {
	f := NewFPFilter()
	result := f.ProofPatternMatch("root:x:0:0:root:/root:/bin/bash")
	if !result.Matched {
		t.Error("expected pattern match for /etc/passwd output")
	}
}

func TestExecutorConcurrency(t *testing.T) {
	cfg := ScanConfig{MaxIterations: 10}
	ex := NewExecutor(cfg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ex.State()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ex.Reset()
	}()
	wg.Wait()
}

func TestDispatchTool_Unknown(t *testing.T) {
	cfg := ScanConfig{MaxIterations: 10}
	ex := NewExecutor(cfg)
	result, err := ex.DispatchTool(context.Background(), "unknown_tool", nil)
	if err == nil {
		t.Error("DispatchTool should return error for unknown tool")
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Error == "" {
		t.Error("expected error message in result")
	}
}

func TestScoringEngineConcurrency(t *testing.T) {
	s := NewScoringEngine()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.CalculateScore(agent.FindingData{Confidence: 0.8, Severity: "high"})
			s.AdaptiveThreshold()
			s.RankFindings([]agent.FindingData{
				{Severity: "low", Confidence: 0.3},
				{Severity: "high", Confidence: 0.8},
			})
		}()
	}
	wg.Wait()
}
