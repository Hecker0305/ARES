package verifier

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestVerifyReplay_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reflected: <script>alert(1)</script>"))
	}))
	defer srv.Close()

	e := NewEngine()
	e.disableSSRFCheck = true
	req := VerificationRequest{
		ID:             "vuln-1",
		VulnType:       "xss",
		Target:         srv.URL,
		Payload:        "<script>alert(1)</script>",
		ExpectedOutput: "reflected",
		Method:         MethodReplay,
	}
	result := e.Verify(req)
	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed, got %s (confidence=%.2f evidence=%s)", result.Verdict, result.Confidence, result.Evidence)
	}
}

func TestVerifyReplay_Suspected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("normal page content"))
	}))
	defer srv.Close()

	e := NewEngine()
	e.disableSSRFCheck = true
	req := VerificationRequest{
		ID:             "vuln-2",
		VulnType:       "xss",
		Target:         srv.URL,
		Payload:        "<script>alert(1)</script>",
		ExpectedOutput: "no reflection",
		Method:         MethodReplay,
	}
	result := e.Verify(req)
	if result.Verdict != VerdictFalsePos {
		t.Errorf("expected false_positive, got %s", result.Verdict)
	}
}

func TestVerifyExtraction_Confirmed(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:             "vuln-3",
		VulnType:       "lfi",
		Target:         "http://example.com",
		Payload:        "../../etc/passwd",
		ExpectedOutput: "root:x:0:0:root:/root:/bin/bash\nSECRET:admin:password",
		Method:         MethodExtraction,
	}
	result := e.Verify(req)
	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed, got %s", result.Verdict)
	}
	if result.Confidence < 0.85 {
		t.Errorf("expected high confidence, got %f", result.Confidence)
	}
}

func TestVerifyOOB_noCallback(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:       "vuln-4",
		VulnType: "rce",
		Target:   "http://example.com",
		Payload:  "nslookup collab.oob",
		Method:   MethodOOB,
	}
	result := e.Verify(req)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected inconclusive (no OOB), got %s", result.Verdict)
	}
}

func TestVerifyOOB_withCallbackID(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:       "vuln-4-cb",
		VulnType: "rce",
		Target:   "http://example.com",
		Payload:  "nslookup collab.oob",
		Method:   MethodOOB,
		Metadata: map[string]string{"callback_id": "cb-123"},
	}
	result := e.Verify(req)
	if result.Verdict != VerdictSuspected {
		t.Errorf("expected suspected with callback_id, got %s", result.Verdict)
	}
}

func TestVerifyLogical_FalsePositive(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:             "vuln-5",
		VulnType:       "sqli",
		Target:         "http://example.com",
		Payload:        "' OR '1'='1",
		ExpectedOutput: "normal page content",
		Method:         MethodLogical,
	}
	result := e.Verify(req)
	if result.Verdict != VerdictFalsePos {
		t.Errorf("expected false_positive, got %s", result.Verdict)
	}
}

func TestVerifyLogical_Confirmed(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:             "vuln-6",
		VulnType:       "sqli",
		Target:         "http://example.com",
		Payload:        "' OR '1'='1",
		ExpectedOutput: "error: syntax near '' OR '1'='1' at line 1",
		Method:         MethodLogical,
	}
	result := e.Verify(req)
	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed, got %s", result.Verdict)
	}
}

func TestVerifyMultiple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<script>alert(1)</script>"))
	}))
	defer srv.Close()

	e := NewEngine()
	e.disableSSRFCheck = true
	req := VerificationRequest{
		ID:             "vuln-7",
		VulnType:       "xss",
		Target:         srv.URL,
		Payload:        "<script>alert(1)</script>",
		ExpectedOutput: "<script>alert(1)</script>",
	}
	result := e.VerifyMultiple(req, []VerificationMethod{MethodReplay, MethodLogical})
	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed, got %s", result.Verdict)
	}
}

func TestGetHistory(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:       "vuln-8",
		VulnType: "sqli",
		Method:   MethodTiming,
	}
	e.Verify(req)
	e.Verify(req)
	history := e.GetHistory()
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}

func TestGetResults(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:       "vuln-9",
		VulnType: "lfi",
		Method:   MethodReplay,
	}
	e.Verify(req)
	results := e.GetResults("vuln-9")
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestVerifyAll(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:       "vuln-10",
		VulnType: "xss",
		Method:   MethodReplay,
	}
	results := e.VerifyAll(req)
	if len(results) == 0 {
		t.Error("expected at least 1 result")
	}
}

func TestRegisterMethod(t *testing.T) {
	e := NewEngine()
	customCalled := false
	e.RegisterMethod(MethodReplay, func(req VerificationRequest) VerificationResult {
		customCalled = true
		return VerificationResult{Verdict: VerdictConfirmed, Confidence: 1.0}
	})
	req := VerificationRequest{ID: "custom", Method: MethodReplay}
	e.Verify(req)
	if !customCalled {
		t.Error("expected custom method to be called")
	}
}

func TestUnregisteredMethod(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{
		ID:     "unknown",
		Method: VerificationMethod("nonexistent"),
	}
	result := e.Verify(req)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected inconclusive for unregistered method, got %s", result.Verdict)
	}
}

func TestStats(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{ID: "stats", Method: MethodReplay}
	e.Verify(req)
	stats := e.Stats()
	total, ok := stats["total_verifications"].(int)
	if !ok || total != 1 {
		t.Errorf("expected 1 verification in stats, got %v", stats["total_verifications"])
	}
}

func TestReset(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{ID: "reset", Method: MethodReplay}
	e.Verify(req)
	e.Reset()
	if len(e.GetHistory()) != 0 {
		t.Error("expected empty history after reset")
	}
}

func TestVerifyDifferential(t *testing.T) {
	e := NewEngine()
	e.disableSSRFCheck = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Payload") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "access denied")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "welcome")
		}
	}))
	defer srv.Close()

	req := VerificationRequest{
		ID:      "diff",
		Method:  MethodDiff,
		Target:  srv.URL,
		Payload: "admin=true",
	}
	result := e.Verify(req)
	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed for differential with behavioral change, got %s (evidence: %s)", result.Verdict, result.Evidence)
	}
}

func TestVerifyTiming(t *testing.T) {
	e := NewEngine()
	e.disableSSRFCheck = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Payload") != "" {
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Fprintf(w, "ok")
	}))
	defer srv.Close()

	req := VerificationRequest{
		ID:       "timing",
		Method:   MethodTiming,
		Target:   srv.URL,
		Payload:  "sleep=true",
		Metadata: map[string]string{"timing_threshold": "1.5"},
	}
	result := e.Verify(req)
	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed for timing with delay, got %s (evidence: %s)", result.Verdict, result.Evidence)
	}
}

func TestVerifyLogical_NoExpectedOutput(t *testing.T) {
	e := NewEngine()
	req := VerificationRequest{ID: "no-out", Method: MethodLogical, Payload: "test"}
	result := e.Verify(req)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected inconclusive with no expected output, got %s", result.Verdict)
	}
}

func TestDefaultThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "x appears here: x")
	}))
	defer srv.Close()

	e := NewEngine()
	e.disableSSRFCheck = true
	req := VerificationRequest{
		ID:             "default-threshold",
		Target:         srv.URL,
		Method:         MethodReplay,
		Payload:        "x",
		ExpectedOutput: "x",
	}
	result := e.Verify(req)
	t.Logf("Result: verdict=%s confidence=%.2f evidence=%s", result.Verdict, result.Confidence, result.Evidence)
}

func TestVerifyReplay_Reflected(t *testing.T) {
	reflectedPayload := "<img src=x onerror=alert(1)>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf("The input was: %s", reflectedPayload)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	e := NewEngine()
	e.disableSSRFCheck = true
	req := VerificationRequest{
		ID:             "vuln-reflected",
		VulnType:       "xss",
		Target:         srv.URL,
		Payload:        reflectedPayload,
		ExpectedOutput: reflectedPayload,
		Method:         MethodReplay,
	}
	result := e.Verify(req)
	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed for reflected payload, got %s", result.Verdict)
	}
	if !result.Reproducible {
		t.Error("expected reproducible=true")
	}
	if !strings.Contains(result.Evidence, "reflected") {
		t.Errorf("evidence should mention reflection: %s", result.Evidence)
	}
}
