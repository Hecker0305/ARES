// Package validator — fpfilter.go
//
// FPFilter is the false-positive filtering layer that mirrors XBOW's
// two-phase architecture:
//
//	Phase 1 — Creative:      The agent explores, runs tools, and the LLM
//	                          interprets output. This produces a candidate
//	                          finding with submitted proof text.
//
//	Phase 2 — Deterministic: FPFilter independently re-evaluates the proof
//	                          against mechanical rules. No LLM judgment is
//	                          involved. A finding is Verified only when
//	                          deterministic checks pass.
//
// Before this layer existed, ARES stored a finding as Verified whenever the
// agent provided any non-empty proof string and a valid method name. The
// ProofChecker in validator.go had all the right patterns but was never
// called at report time. This file wires it in as Gate 3.5.
package validator

import (
	"strings"
)

// Verdict classifies a finding after deterministic proof checking.
type Verdict string

const (
	// VerdictVerified means at least one deterministic proof pattern matched
	// (OOB callback, SQL error, reflected payload, /etc/passwd, SSTI eval,
	// cloud metadata, admin JSON, or time-based delay). Safe to surface in reports.
	VerdictVerified Verdict = "verified"

	// VerdictSuspected means the proof is structurally plausible (real HTTP
	// exchange, non-trivial content) but no deterministic pattern confirmed
	// exploitation. Stored in the report with a clear "suspected" label so
	// the human reviewer can make the final call.
	VerdictSuspected Verdict = "suspected"

	// VerdictFalsePositive means the submission matches a known noise pattern
	// (missing header, version disclosure, scanner-only, DNS config, etc.).
	// The finding is rejected before reaching the VulnStore.
	VerdictFalsePositive Verdict = "false_positive"
)

// FilterResult is the output of FPFilter.Filter.
type FilterResult struct {
	Verdict    Verdict
	Confidence float64 // 0.0–1.0
	ProofType  string  // "oob_callback", "error_based", "data_extracted", "structural", …
	Evidence   string  // what the checker found (truncated)
	Reason     string  // human-readable explanation emitted to the UI
}

// ReportArgs mirrors the fields the agent submits via report_vulnerability.
// Fields that reporting.go already extracts are re-used here without copying.
type ReportArgs struct {
	Title              string
	Description        string
	Severity           string
	ExploitationProof  string
	VerificationMethod string
	// Optional — populated when the agent also passes raw HTTP responses
	// or payload strings. If empty, ExploitationProof is used as Response.
	Response      string
	ExtractedData string
	Payload       string
	CallbackHit   bool
}

// FPFilter runs deterministic proof checking on vulnerability submissions.
type FPFilter struct {
	checker *ProofChecker
}

// NewFPFilter creates a new FPFilter backed by a ProofChecker.
func NewFPFilter() *FPFilter {
	return &FPFilter{checker: NewProofChecker()}
}

// Filter is the main entry point. It builds an ExploitResult from the agent's
// submission and runs it through ProofChecker without involving the LLM.
//
// Call this after the existing FP pattern gates (Gate 3) and before persisting
// to the VulnStore. The caller should:
//
//	switch result.Verdict {
//	case VerdictFalsePositive: reject — return error to agent
//	case VerdictVerified:      store with Verified=true, VerificationStatus="verified"
//	case VerdictSuspected:     store with Verified=false, VerificationStatus="suspected"
//	}
func (f *FPFilter) Filter(args *ReportArgs) FilterResult {
	if args == nil {
		return FilterResult{
			Verdict: VerdictFalsePositive,
			Reason:  "nil report args",
		}
	}

	// Definitively noisy patterns short-circuit before any further work.
	if isDefinitelyNoise(args) {
		return FilterResult{
			Verdict: VerdictFalsePositive,
			Reason:  "matches known noise pattern (missing header, version disclosure, scanner-only, DNS config, analytics key, rate-limit, Sentry DSN)",
		}
	}

	// Build an ExploitResult the ProofChecker understands.
	// Agents typically paste full HTTP responses into ExploitationProof;
	// treat that field as both Output and Response when Response is empty.
	r := &ExploitResult{
		Target:        args.Title, // best proxy we have
		Vulnerability: args.Title + " " + args.Description,
		Output:        args.ExploitationProof,
		Response:      args.Response,
		ExtractedData: args.ExtractedData,
		Payload:       args.Payload,
		CallbackHit:   args.CallbackHit,
		Confidence:    0.0,
	}
	if r.Response == "" && len(args.ExploitationProof) > 40 {
		// Proof field often contains the raw HTTP response — treat it as such.
		r.Response = args.ExploitationProof
	}

	// ── Phase 2: Deterministic verification ──
	if f.checker.Validate(r) {
		return FilterResult{
			Verdict:    VerdictVerified,
			Confidence: r.Confidence,
			ProofType:  r.ProofType,
			Evidence:   r.ProofEvidence,
			Reason:     "deterministic proof confirmed: " + r.ProofType,
		}
	}

	// ── Structural sufficiency check ──
	// No deterministic pattern matched, but the proof is large and contains
	// real HTTP exchange markers — keep as suspected for human review.
	if isStructurallySufficient(args) {
		return FilterResult{
			Verdict:    VerdictSuspected,
			Confidence: 0.40,
			ProofType:  "structural",
			Reason:     "proof submitted but no deterministic pattern matched — stored as suspected for human review",
		}
	}

	// ── Fallback: too thin to trust ──
	return FilterResult{
		Verdict:    VerdictSuspected,
		Confidence: 0.20,
		ProofType:  "unconfirmed",
		Reason:     "proof does not satisfy any deterministic check — low-confidence suspected finding",
	}
}

// isStructurallySufficient returns true when the proof is long enough and
// contains real HTTP exchange or structured-data markers — evidence that the
// agent actually interacted with the target rather than hallucinating output.
func isStructurallySufficient(args *ReportArgs) bool {
	proof := args.ExploitationProof
	if len(proof) < 120 {
		return false
	}
	lower := strings.ToLower(proof)
	// Must contain at least one real-exchange marker
	httpMarkers := []string{
		"http/1", "http/2", "curl ", "200 ok", "302 found",
		"301 moved", "400 bad request", "401 unauthorized",
		"403 forbidden", "500 internal", "content-type:",
		"set-cookie:", "location:", "x-request-id:",
	}
	for _, m := range httpMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	// Or contains structured data that implies real output
	dataMarkers := []string{`"id":`, `"email":`, `"user":`, `"token":`, `"admin":`, `"role":`, `<html`, `<?xml`, `<!doctype`}
	for _, m := range dataMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// isDefinitelyNoise returns true for submissions that are definitively
// informational findings regardless of severity label — the same patterns
// that reporting.go's checkFalsePositive catches, centralised here so the
// FPFilter is the single authority on noise classification.
//
// Note: reporting.go's checkFalsePositive (Gate 3) already rejects these
// at the tool level. isDefinitelyNoise provides a second, independent check
// at the store level so even if Gate 3 is modified or bypassed in future,
// the FPFilter still blocks noise from reaching VulnStore.
func isDefinitelyNoise(args *ReportArgs) bool {
	lower := strings.ToLower(args.Title + " " + args.Description + " " + args.ExploitationProof)
	noisePatterns := []string{
		// Missing security headers
		"missing header", "x-frame-options", "x-content-type-options",
		"content-security-policy", "strict-transport-security", "hsts missing",
		"referrer-policy", "permissions-policy missing", "x-xss-protection",
		// Version / tech disclosure
		"version disclosure", "server header", "x-powered-by",
		"banner grabbing", "technology disclosure",
		// Scanner-only
		"nuclei detected", "nuclei found", "scanner reported",
		"automated scan found", "wpscan found", "nmap detected",
		// DNS / email config
		"spf", "dmarc", "dkim", "txt record",
		// Analytics tokens
		"sentry dsn", "ingest.sentry.io",
		"writekey", "write_key", "analytics key",
		// Rate limiting
		"rate limit", "rate-limit", "no rate limit",
		"brute force", "account lockout", "login throttling",
		// Client-side public config
		"next_public_", "react_app_", "public_env", "window.__singletons",
		// SSL/TLS config issues
		"weak cipher", "tls 1.0", "tls 1.1", "ssl certificate expired",
		// HTTP method noise
		"trace method", "trace enabled", "options method",
		// CSV injection
		"csv injection", "formula injection", "excel injection",
	}
	for _, p := range noisePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
