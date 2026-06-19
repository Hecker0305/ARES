package validator

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ExploitResult struct {
	Target           string
	Vulnerability    string
	Success          bool
	Output           string
	Evidence         string
	CVSS             float64
	CVSSScore        float64
	Confirmed        bool
	Payload          string
	Response         string
	ExtractedData    string
	CallbackHit      bool
	Confidence       float64
	ValidationPassed bool
	ProofType        string
	ProofEvidence    string
}

type ExploitValidator interface {
	Validate(result *ExploitResult) bool
}

const MinConfidenceThreshold = 0.35

func PassesMinConfidence(r *ExploitResult) bool {
	if r == nil {
		return false
	}
	if r.CallbackHit || len(r.ExtractedData) > 20 {
		return true
	}
	if r.Confidence >= MinConfidenceThreshold {
		return true
	}
	return len(r.Response) > 100 || len(r.Output) > 100
}

var (
	sqlErrorPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(You have an error in your SQL syntax)`),
		regexp.MustCompile(`(?i)(ORA-\d{5}:)`),
		regexp.MustCompile(`(?i)(Microsoft OLE DB Provider for SQL Server)`),
		regexp.MustCompile(`(?i)(Unclosed quotation mark after the character string)`),
		regexp.MustCompile(`(?i)(PG::SyntaxError)`),
		regexp.MustCompile(`(?i)(SQLite3::Exception)`),
		regexp.MustCompile(`(?i)(Warning.*\Wmysqli?_)`),
		regexp.MustCompile(`(?i)(PostgreSQL.*ERROR)`),
		regexp.MustCompile(`(?i)(SQLSTATE\[\d+\])`),
		regexp.MustCompile(`(?i)(mysql_fetch_array\(\))`),
	}
	sqlUnionPattern = regexp.MustCompile(`(?i)(sqlmap identified|fetched data|Database:\s+\w|Table:\s+\w|\|\s+\w+\s+\|)`)
	xssPayloadPat   = regexp.MustCompile(`(?i)(<script[^>]*>|onerror=|onload=|alert\(|confirm\(|javascript:)`)
	ssrfMetaPat     = regexp.MustCompile(`(?i)(ami-id|instance-id|local-ipv4|iam/security-credentials|computeMetadata|AccessKeyId|SecretAccessKey|169\.254\.169\.254)`)
	lfiPat          = regexp.MustCompile(`root:(x|\*):0:0:|/bin/(bash|sh)\s*$`)
	sstiPat         = regexp.MustCompile(`\b49\b`)
)

type ProofChecker struct{}

func NewProofChecker() *ProofChecker { return &ProofChecker{} }

func (pc *ProofChecker) Validate(r *ExploitResult) bool {
	if r == nil {
		return false
	}
	vuln := strings.ToLower(r.Vulnerability)
	combined := r.Response + r.Output + r.ExtractedData

	if r.CallbackHit {
		r.ProofType, r.ProofEvidence = "oob_callback", fmt.Sprintf("OOB callback received for %s", r.Vulnerability)
		r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.95
		return true
	}

	if strings.Contains(vuln, "sql") {
		for _, re := range sqlErrorPatterns {
			if m := re.FindString(combined); m != "" {
				r.ProofType, r.ProofEvidence = "error_based", "SQL error: "+truncate(m, 100)
				r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.85
				return true
			}
		}
		if m := sqlUnionPattern.FindString(combined); m != "" {
			r.ProofType, r.ProofEvidence = "data_extracted", "SQLi confirmed: "+truncate(m, 100)
			r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.88
			return true
		}
	}

	if strings.Contains(vuln, "xss") && r.Payload != "" {
		if strings.Contains(combined, r.Payload) && xssPayloadPat.MatchString(r.Payload) {
			r.ProofType, r.ProofEvidence = "reflected", "XSS payload reflected unencoded: "+truncate(r.Payload, 80)
			r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.80
			return true
		}
	}

	if strings.Contains(vuln, "ssrf") {
		if m := ssrfMetaPat.FindString(combined); m != "" {
			r.ProofType, r.ProofEvidence = "data_extracted", "SSRF confirmed - cloud metadata: "+truncate(m, 100)
			r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.90
			return true
		}
	}

	if strings.Contains(vuln, "lfi") || strings.Contains(vuln, "traversal") || strings.Contains(vuln, "inclusion") {
		if lfiPat.MatchString(combined) {
			r.ProofType, r.ProofEvidence = "data_extracted", "LFI confirmed - /etc/passwd content in response"
			r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.92
			return true
		}
	}

	if strings.Contains(vuln, "ssti") || strings.Contains(vuln, "template") {
		if strings.Contains(r.Payload, "7*7") && sstiPat.MatchString(combined) {
			r.ProofType, r.ProofEvidence = "reflected", "SSTI confirmed - 7*7 evaluated to 49"
			r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.88
			return true
		}
	}

	if strings.Contains(vuln, "idor") || strings.Contains(vuln, "auth") || strings.Contains(vuln, "jwt") {
		cl := strings.ToLower(combined)
		if strings.Contains(cl, "\"admin\":true") || strings.Contains(cl, "\"role\":\"admin\"") {
			r.ProofType, r.ProofEvidence = "authenticated", "Admin privileges confirmed in response"
			r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.82
			return true
		}
		if strings.Contains(cl, "\"id\":") && strings.Contains(cl, "\"email\":") {
			r.ProofType, r.ProofEvidence = "authenticated", "Cross-user data object returned (IDOR)"
			r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.82
			return true
		}
	}

	if len(r.ExtractedData) > 30 && !strings.Contains(strings.ToLower(r.ExtractedData), "error") {
		r.ProofType, r.ProofEvidence = "data_extracted", "Data extracted: "+truncate(r.ExtractedData, 150)
		r.ValidationPassed, r.Confirmed, r.Confidence = true, true, 0.70
		return true
	}

	r.ValidationPassed, r.Confirmed, r.Confidence = false, false, 0.0
	return false
}

func TimeBasedProof(baselineURL, payloadURL string) (bool, string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	const samples = 5
	baselineDurations := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		t0 := time.Now()
		r, err := client.Get(baselineURL)
		if err != nil {
			return false, "", fmt.Errorf("baseline sample %d: %w", i+1, err)
		}
		r.Body.Close()
		baselineDurations = append(baselineDurations, time.Since(t0))
	}

	payloadDurations := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		t0 := time.Now()
		r, err := client.Get(payloadURL)
		if err != nil {
			return false, "", fmt.Errorf("payload sample %d: %w", i+1, err)
		}
		r.Body.Close()
		payloadDurations = append(payloadDurations, time.Since(t0))
	}

	var baselineSum, payloadSum time.Duration
	for _, d := range baselineDurations {
		baselineSum += d
	}
	for _, d := range payloadDurations {
		payloadSum += d
	}
	baselineAvg := baselineSum / time.Duration(samples)
	payloadAvg := payloadSum / time.Duration(samples)

	delta := payloadAvg - baselineAvg

	var baselineVariance, payloadVariance float64
	for _, d := range baselineDurations {
		diff := float64(d - baselineAvg)
		baselineVariance += diff * diff
	}
	for _, d := range payloadDurations {
		diff := float64(d - payloadAvg)
		payloadVariance += diff * diff
	}
	baselineStdDev := time.Duration(int64(baselineVariance / float64(samples)))
	payloadStdDev := time.Duration(int64(payloadVariance / float64(samples)))

	threshold := 3 * time.Second
	noiseFloor := baselineStdDev + payloadStdDev
	if noiseFloor > threshold/2 {
		threshold = noiseFloor * 2
	}

	if delta >= threshold {
		return true, fmt.Sprintf("Time-based confirmed: baseline=%.1fs(+/-%.1fs) payload=%.1fs(+/-%.1fs) delta=%.1fs samples=%d",
			baselineAvg.Seconds(), baselineStdDev.Seconds(),
			payloadAvg.Seconds(), payloadStdDev.Seconds(),
			delta.Seconds(), samples), nil
	}
	return false, fmt.Sprintf("No delay: delta=%.1fs (threshold=%.1fs, noise=%.1fs)",
		delta.Seconds(), threshold.Seconds(), noiseFloor.Seconds()), nil
}

var CVSSBand = map[string][2]float64{
	"critical": {9.0, 10.0},
	"high":     {7.0, 8.9},
	"medium":   {4.0, 6.9},
	"low":      {0.1, 3.9},
	"info":     {0.0, 0.0},
}

func ValidateCVSS(severity string, cvss float64) error {
	band, ok := CVSSBand[strings.ToLower(severity)]
	if !ok {
		return fmt.Errorf("unknown severity: %s", severity)
	}
	if severity == "info" && cvss == 0.0 {
		return nil
	}
	if cvss < band[0] || cvss > band[1] {
		return fmt.Errorf("CVSS %.1f outside [%.1f-%.1f] for %s", cvss, band[0], band[1], severity)
	}
	return nil
}

func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func ParseCVSS(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func ScoreFinding(r *ExploitResult) float64 {
	score := r.CVSS*2.0 + r.Confidence*10.0
	if r.CallbackHit {
		score += 25.0
	}
	if r.Confirmed {
		score += 5.0
	}
	if len(r.ExtractedData) > 30 {
		score += 3.0
	}
	switch r.ProofType {
	case "oob_callback":
		score += 20.0
	case "data_extracted":
		score += 15.0
	case "error_based":
		score += 10.0
	case "reflected":
		score += 8.0
	}
	return score
}

func ValidateTopUnvalidated(ctx context.Context, findings []*ExploitResult, n int) []*ExploitResult {
	if findings == nil {
		return nil
	}
	if n <= 0 {
		n = 10
	}

	pc := NewProofChecker()
	var validated []*ExploitResult

	for _, f := range findings {
		select {
		case <-ctx.Done():
			goto RANK
		default:
		}
		if !f.ValidationPassed {
			pc.Validate(f)
			if f.ValidationPassed {
				validated = append(validated, f)
			}
		}
	}

RANK:
	sort.Slice(validated, func(i, j int) bool {
		return ScoreFinding(validated[i]) > ScoreFinding(validated[j])
	})
	if len(validated) > n {
		validated = validated[:n]
	}
	return validated
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
