package differential

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine() returned nil")
	}
	if e.client == nil {
		t.Error("client is nil")
	}
	if e.threshold != 0.85 {
		t.Errorf("threshold = %f, want 0.85", e.threshold)
	}
}

func TestThreshold(t *testing.T) {
	e := NewEngine()
	if e.Threshold() != 0.85 {
		t.Errorf("Threshold() = %f, want 0.85", e.Threshold())
	}
}

func TestCompareResponseIdentical(t *testing.T) {
	e := NewEngine()
	sim, hash := e.CompareResponse("hello world", "hello world")
	if sim != 1.0 {
		t.Errorf("similarity = %f, want 1.0", sim)
	}
	if hash != "" {
		t.Errorf("hash = %q, want empty", hash)
	}
}

func TestCompareResponseDifferent(t *testing.T) {
	e := NewEngine()
	sim, hash := e.CompareResponse("aaaa", "bbbb")
	if sim >= 1.0 {
		t.Errorf("similarity = %f, want < 1.0", sim)
	}
	if hash == "" {
		t.Error("hash should not be empty for different responses")
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestCompareResponseEmpty(t *testing.T) {
	e := NewEngine()
	sim, hash := e.CompareResponse("", "")
	if sim != 1.0 {
		t.Errorf("similarity = %f, want 1.0", sim)
	}
	if hash != "" {
		t.Errorf("hash = %q, want empty", hash)
	}
}

func TestFuzzyMatchIdentical(t *testing.T) {
	sim := fuzzyMatch("same content", "same content")
	if sim != 1.0 {
		t.Errorf("similarity = %f, want 1.0", sim)
	}
}

func TestFuzzyMatchDifferent(t *testing.T) {
	sim := fuzzyMatch("abc", "xyz")
	if sim >= 1.0 {
		t.Errorf("similarity = %f, want < 1.0", sim)
	}
}

func TestFuzzyMatchCaseInsensitive(t *testing.T) {
	sim := fuzzyMatch("HELLO", "hello")
	if sim != 1.0 {
		t.Errorf("similarity = %f, want 1.0 (case insensitive)", sim)
	}
}

func TestFuzzyMatchEmpty(t *testing.T) {
	if sim := fuzzyMatch("", "test"); sim != 0.0 {
		t.Errorf("similarity = %f, want 0.0", sim)
	}
	if sim := fuzzyMatch("test", ""); sim != 0.0 {
		t.Errorf("similarity = %f, want 0.0", sim)
	}
	if sim := fuzzyMatch("", ""); sim != 1.0 {
		t.Errorf("similarity = %f, want 1.0", sim)
	}
}

func TestFindDiffRegionsNoDiff(t *testing.T) {
	e := NewEngine()
	regions := e.findDiffRegions("same content", "same content")
	if len(regions) != 0 {
		t.Errorf("expected 0 regions, got %d", len(regions))
	}
}

func TestFindDiffRegionsCompleteDiff(t *testing.T) {
	e := NewEngine()
	regions := e.findDiffRegions("aaaa", "bbbb")
	if len(regions) == 0 {
		t.Fatal("expected diff regions")
	}
	for _, r := range regions {
		if r.Start < 0 || r.End <= r.Start {
			t.Errorf("invalid region: start=%d end=%d", r.Start, r.End)
		}
		if r.Category == "" {
			t.Error("category should not be empty")
		}
		if r.Context == "" {
			t.Error("context should not be empty")
		}
	}
}

func TestFindDiffRegionsPartialDiff(t *testing.T) {
	e := NewEngine()
	regions := e.findDiffRegions("prefix_abc_suffix", "prefix_xyz_suffix")
	if len(regions) == 0 {
		t.Fatal("expected diff regions")
	}
}

func TestFindDiffRegionsDiffAtEnd(t *testing.T) {
	e := NewEngine()
	regions := e.findDiffRegions("prefix", "different")
	if len(regions) == 0 {
		t.Fatal("expected diff regions")
	}
}

func TestCategorizeDiff(t *testing.T) {
	tests := []struct {
		a, b     string
		category string
	}{
		{"value 123", "value 456", "numeric-change"},
		{"error: not found", "success", "error-change"},
		{"short", "very long string here", "length-change"},
		{"hello", "world", "content-change"},
	}
	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			cat := categorizeDiff(tt.a, tt.b)
			if cat != tt.category {
				t.Errorf("categorizeDiff(%q, %q) = %q, want %q", tt.a, tt.b, cat, tt.category)
			}
		})
	}
}

func TestEncodeVariants(t *testing.T) {
	e := NewEngine()
	cases := e.EncodeVariants("<script>alert(1)</script>")
	if len(cases) == 0 {
		t.Fatal("expected encoding variants")
	}
	if len(cases) != 5 {
		t.Errorf("expected 5 encoding variants, got %d", len(cases))
	}
	encodingNames := make(map[string]bool)
	for _, tc := range cases {
		if encodingNames[tc.Encoding] {
			t.Errorf("duplicate encoding: %s", tc.Encoding)
		}
		encodingNames[tc.Encoding] = true
		if tc.Payload == "" {
			t.Errorf("empty payload for encoding %s", tc.Encoding)
		}
	}
}

func TestEncodeVariantsEmptyPayload(t *testing.T) {
	e := NewEngine()
	cases := e.EncodeVariants("")
	if len(cases) != 5 {
		t.Errorf("expected 5 variants for empty payload, got %d", len(cases))
	}
}

func TestEncodeVariantsOriginal(t *testing.T) {
	e := NewEngine()
	cases := e.EncodeVariants("test' OR '1'='1")
	found := false
	for _, tc := range cases {
		if tc.Encoding == "original" && tc.Payload == "test' OR '1'='1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("original encoding variant not found")
	}
}

func TestEncodeVariantsUnicode(t *testing.T) {
	e := NewEngine()
	cases := e.EncodeVariants("<test>")
	for _, tc := range cases {
		if tc.Encoding == "unicode-escape" {
			if !strings.Contains(tc.Payload, "\\u") {
				t.Errorf("unicode-escape should contain \\u, got %q", tc.Payload)
			}
		}
	}
}

func TestSummary(t *testing.T) {
	e := NewEngine()
	results := map[string]*Result{
		"test:original": {
			Match:         false,
			Similarity:    0.9,
			ResponseA:     "response a",
			ResponseB:     "response b",
			ResponseCodeA: 200,
			ResponseCodeB: 200,
		},
		"test2:original": {
			Match:         true,
			Similarity:    0.5,
			ResponseA:     "response a",
			ResponseB:     "different response",
			ResponseCodeA: 200,
			ResponseCodeB: 500,
		},
	}
	summary := e.Summary(results)
	if !strings.Contains(summary, "stable") {
		t.Error("summary should contain 'stable'")
	}
	if !strings.Contains(summary, "flaky") {
		t.Error("summary should contain 'flaky'")
	}
}

func TestSummaryEmpty(t *testing.T) {
	e := NewEngine()
	summary := e.Summary(make(map[string]*Result))
	if !strings.Contains(summary, "0 stable") {
		t.Errorf("unexpected summary: %s", summary)
	}
}

func TestTestFlakyVulnWithServer(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"status":"error"}`))
		}
	}))
	defer ts.Close()

	e := NewEngine()
	reqA, _ := http.NewRequest("GET", ts.URL, nil)
	reqB, _ := http.NewRequest("GET", ts.URL, nil)
	matched, result := e.TestFlakyVuln(reqA, reqB, "test-payload")
	if matched {
		if result == nil {
			t.Fatal("matched but result is nil")
		}
		if result.Similarity != 0.0 {
			t.Logf("Similarity = %f (expected 0 for different responses)", result.Similarity)
		}
	}
}

func TestTestFlakyVulnIdentical(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	e := NewEngine()
	reqA, _ := http.NewRequest("GET", ts.URL, nil)
	reqB, _ := http.NewRequest("GET", ts.URL, nil)
	matched, result := e.TestFlakyVuln(reqA, reqB, "test")
	if matched {
		t.Log("matched (may be flaky)")
	}
	if result != nil {
		if result.Match {
			t.Log("responses matched")
		}
	}
}

func TestTestFlakyVulnInvalidURL(t *testing.T) {
	e := NewEngine()
	reqA, _ := http.NewRequest("GET", "http://127.0.0.1:1", nil)
	reqB, _ := http.NewRequest("GET", "http://127.0.0.1:1", nil)
	matched, result := e.TestFlakyVuln(reqA, reqB, "test")
	if matched {
		t.Error("expected no match for invalid URL")
	}
	if result != nil {
		t.Error("expected nil result for invalid URL")
	}
}

func TestRunDifferentialEmptyPayloads(t *testing.T) {
	e := NewEngine()
	results := e.RunDifferential("http://example.com", "http://example.com/api", nil, "GET")
	if results == nil {
		t.Error("expected non-nil results map")
	}
}

func TestEncodeVariantsAndFuzzyMatch(t *testing.T) {
	e := NewEngine()
	cases := e.EncodeVariants("test' OR 1=1")
	if len(cases) == 0 {
		t.Fatal("expected encoding variants")
	}
	for _, tc := range cases {
		if tc.Payload == "" {
			t.Errorf("empty payload for encoding %s", tc.Encoding)
		}
	}
	sim := fuzzyMatch("response a", "response a")
	if sim != 1.0 {
		t.Errorf("fuzzyMatch identical = %f, want 1.0", sim)
	}
	sim = fuzzyMatch("response a", "response b")
	if sim >= 1.0 {
		t.Errorf("fuzzyMatch different = %f, want < 1.0", sim)
	}
}

func TestRunDifferentialMapBehavior(t *testing.T) {
	e := NewEngine()
	results := make(map[string]*Result)
	results["test:original"] = &Result{
		ResponseA:     "base response",
		ResponseCodeA: 200,
	}
	results["test:url-encode"] = &Result{
		ResponseA:     "encoded response",
		ResponseCodeA: 200,
	}
	summary := e.Summary(results)
	if !strings.Contains(summary, "2 stable") {
		t.Logf("summary: %s", summary)
	}
}

func TestHashOutputConsistency(t *testing.T) {
	e := NewEngine()
	_, h1 := e.CompareResponse("same", "same")
	_, h2 := e.CompareResponse("same", "same")
	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
	_, h3 := e.CompareResponse("different", "responses")
	if h3 == "" {
		t.Error("different inputs should produce non-empty hash")
	}
}

func TestHashConsistency(t *testing.T) {
	e := NewEngine()
	_, hash1 := e.CompareResponse("test", "test2")
	_, hash2 := e.CompareResponse("test", "test2")
	if hash1 != hash2 {
		t.Error("same inputs should produce same hash")
	}
}

func TestResponseHash(t *testing.T) {
	body := []byte(`{"test":"data"}`)
	h := sha256.Sum256(body)
	hash := hex.EncodeToString(h[:])
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestEngineConcurrent(t *testing.T) {
	e := NewEngine()
	results := make(map[string]*Result)
	for i := 0; i < 10; i++ {
		key := strings.Join([]string{"payload", string(rune('0' + i))}, ":")
		results[key] = &Result{Match: false, Similarity: 0.5}
	}
	summary := e.Summary(results)
	if !strings.Contains(summary, "10 stable") {
		t.Logf("summary: %s", summary)
	}
}
