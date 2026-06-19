package engine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ares/engine/internal/logger"
)

type Verdict string

const (
	VerdictVerified      Verdict = "verified"
	VerdictSuspected     Verdict = "suspected"
	VerdictFalsePositive Verdict = "false_positive"
)

type PatternResult struct {
	Matched  bool
	Pattern  string
	Strength float64
}

type FindingCandidate struct {
	Type        string
	Target      string
	Payload     string
	Output      string
	VulnType    string
	Severity    string
	Confidence  float64
	RawResponse string
	Timestamp   string
}

type FPFilter struct {
	phase         string
	oobServer     string
	sqlRegexps    []*regexp.Regexp
	lfiRegexps    []*regexp.Regexp
	sstiRegexps   []*regexp.Regexp
	proofPatterns []struct {
		pattern *regexp.Regexp
		weight  float64
	}
}

func NewFPFilter() *FPFilter {
	f := &FPFilter{
		phase: "exploration",
	}
	f.initPatterns()
	return f
}

func (f *FPFilter) initPatterns() {
	sqlPatterns := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-\\d{5}",
		"postgresql",
		"unterminated",
		"sqlite3",
		"Microsoft SQL",
		"MySQL",
		"MariaDB",
		"Warning: mysql",
		"you have an error in your SQL",
		"SQLServer JDBC",
	}
	lfiPatterns := []string{
		"root:.*:0:0:",
		"daemon\\+",
		"bin\\+",
		"sys\\+",
		"/etc/passwd",
		"/etc/shadow",
	}
	sstiPatterns := []string{
		"49",
		"7\\*7",
		"{{7\\*7}}",
		"__import__",
		"eval\\(",
		"exec\\(",
	}

	f.sqlRegexps = compilePatterns(sqlPatterns)
	f.lfiRegexps = compilePatterns(lfiPatterns)
	f.sstiRegexps = compilePatterns(sstiPatterns)
	f.proofPatterns = []struct {
		pattern *regexp.Regexp
		weight  float64
	}{
		{regexp.MustCompile(`root:.*:0:0:`), 1.0},
		{regexp.MustCompile(`\[.*\]:.*:.*:`), 0.9},
		{regexp.MustCompile(`mysql_fetch`), 0.9},
		{regexp.MustCompile(`ORA-\d{5}`), 0.95},
		{regexp.MustCompile(`SQL syntax`), 0.7},
		{regexp.MustCompile(`You have an error in your SQL`), 0.8},
		{regexp.MustCompile(`Warning: mysql`), 0.7},
		{regexp.MustCompile(`7\*7\s*=\s*49`), 0.6},
		{regexp.MustCompile(`__import__`), 0.9},
		{regexp.MustCompile(`169\.254\.169\.254`), 0.6},
	}
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

func (f *FPFilter) Filter(result *FindingCandidate) Verdict {
	if result == nil {
		return VerdictFalsePositive
	}

	if result.Payload == "" || result.Output == "" {
		return VerdictFalsePositive
	}

	_, isFP := f.DenyIfFalsePositive(result)
	if isFP {
		logger.Info(fmt.Sprintf("[FPFilter] False positive detected: %s", result.Payload))
		return VerdictFalsePositive
	}

	proof := f.ProofPatternMatch(result.Output)
	if proof.Matched {
		if proof.Strength > 0.8 {
			return VerdictVerified
		} else if proof.Strength > 0.5 {
			return VerdictSuspected
		}
	}

	if result.Confidence > 0.8 {
		return VerdictVerified
	} else if result.Confidence > 0.5 {
		return VerdictSuspected
	}

	return VerdictSuspected
}

func (f *FPFilter) DenyIfFalsePositive(candidate *FindingCandidate) (*FindingCandidate, bool) {
	if candidate == nil {
		return nil, true
	}

	if f.checkOOB(candidate) {
		return candidate, false
	}

	if f.checkSQLErrors(candidate.Output) {
		matched, pattern := f.matchPattern(candidate.Output, f.sqlRegexps)
		if matched {
			candidate.Payload = pattern + " (SQL Error detected)"
			return candidate, false
		}
	}

	if f.checkReflectedPayload(candidate) {
		logger.Info("[FPFilter] Reflected payload detected in output")
		return nil, true
	}

	if f.checkLFI(candidate.Output) {
		matched, _ := f.matchPattern(candidate.Output, f.lfiRegexps)
		if matched {
			return candidate, false
		}
	}

	if f.checkSSTI(candidate) {
		return candidate, false
	}

	if f.checkCloudMetadata(candidate.Output) {
		return nil, true
	}

	if f.checkTimeDelay(candidate) {
		logger.Info("[FPFilter] Time-delay confirmed vulnerability")
		return candidate, false
	}

	return candidate, false
}

func (f *FPFilter) checkOOB(candidate *FindingCandidate) bool {
	if f.oobServer == "" {
		return false
	}

	oobIndicators := []string{
		"dns",
		"callback",
		"exfil",
		"burpcollaborator",
		"interactsh",
	}

	outputLower := strings.ToLower(candidate.Output)
	for _, indicator := range oobIndicators {
		if strings.Contains(outputLower, indicator) {
			return true
		}
	}

	return false
}

func (f *FPFilter) checkReflectedPayload(candidate *FindingCandidate) bool {
	if candidate.Payload == "" {
		return false
	}

	normalizedPayload := strings.ToLower(strings.TrimSpace(candidate.Payload))
	normalizedOutput := strings.ToLower(candidate.Output)

	if strings.Contains(normalizedOutput, normalizedPayload) {
		lengthPayload := len(normalizedPayload)
		lengthOutput := len(normalizedOutput)

		reflectionRatio := float64(lengthPayload) / float64(lengthOutput)
		if reflectionRatio > 0.3 && reflectionRatio < 1.0 {
			return true
		}
	}

	return false
}

func (f *FPFilter) checkSQLErrors(output string) bool {
	matched, _ := f.matchPattern(output, f.sqlRegexps)
	return matched
}

func (f *FPFilter) checkLFI(output string) bool {
	matched, _ := f.matchPattern(output, f.lfiRegexps)
	return matched
}

func (f *FPFilter) checkSSTI(candidate *FindingCandidate) bool {
	sstiPayloads := []string{"{{7*7}}", "${7*7}", "<%= 7*7 %>"}

	for _, p := range sstiPayloads {
		if strings.Contains(candidate.Payload, p) {
			expected := "49"
			if strings.Contains(candidate.Output, expected) {
				return true
			}
		}
	}

	matched, _ := f.matchPattern(candidate.Output, f.sstiRegexps)
	return matched
}

func (f *FPFilter) checkCloudMetadata(output string) bool {
	cloudPatterns := []string{
		"169.254.169.254",
		"metadata.google.internal",
		"aws.amazonaws.com",
		"instance-data",
	}

	outputLower := strings.ToLower(output)
	for _, pattern := range cloudPatterns {
		if strings.Contains(outputLower, pattern) {
			logger.Info("[FPFilter] Cloud metadata pattern detected - likely not a real vuln")
			return true
		}
	}

	return false
}

func (f *FPFilter) checkTimeDelay(candidate *FindingCandidate) bool {
	timePatterns := []string{
		"SLEEP",
		"WAITFOR",
		"benchmark",
		"sleep\\(",
		"delay\\(",
	}

	for _, p := range timePatterns {
		matched, err := regexp.MatchString(p, candidate.Payload)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func (f *FPFilter) ProofPatternMatch(output string) PatternResult {
	for _, p := range f.proofPatterns {
		if p.pattern.MatchString(output) {
			return PatternResult{
				Matched:  true,
				Pattern:  p.pattern.String(),
				Strength: p.weight,
			}
		}
	}

	return PatternResult{Matched: false, Pattern: "", Strength: 0.0}
}

func (f *FPFilter) matchPattern(text string, patterns []*regexp.Regexp) (bool, string) {
	for _, re := range patterns {
		if re.MatchString(text) {
			return true, re.String()
		}
	}
	return false, ""
}

func (f *FPFilter) SetPhase(phase string) {
	f.phase = phase
}

func (f *FPFilter) SetOOBServer(server string) {
	f.oobServer = server
}

func (f *FPFilter) Phase() string {
	return f.phase
}

func (v Verdict) String() string {
	return string(v)
}
