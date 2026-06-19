// Benchmark runner for ARES.
// Usage: go run tests/benchmark/runner.go --target dvwa --url http://localhost:4280
//
// Spins up a vulnerable target (or connects to existing), runs ARES scan,
// compares findings against expected results, and computes precision/recall/F1.
//
// Targets available: dvwa, webgoat
// Reports written to tests/benchmark/report/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ExpectedFinding struct {
	Type            string   `json:"type"`
	Endpoint        string   `json:"endpoint"`
	Param           string   `json:"param"`
	Method          string   `json:"method"`
	Severity        string   `json:"severity"`
	CWE             string   `json:"cwe"`
	MinConfidence   float64  `json:"min_confidence"`
	EvidencePattern string   `json:"evidence_pattern"`
}

type BenchmarkResult struct {
	Target     string  `json:"target"`
	Total      int     `json:"total_expected"`
	Detected   int     `json:"detected"`
	Missed     int     `json:"missed"`
	FalsePos   int     `json:"false_positives"`
	Precision  float64 `json:"precision"`
	Recall     float64 `json:"recall"`
	F1         float64 `json:"f1"`
	Duration   string  `json:"duration"`
	Timestamp  string  `json:"timestamp"`
	Details    []FindingMatch `json:"details"`
}

type FindingMatch struct {
	ExpectedType string `json:"expected_type"`
	ExpectedCWE  string `json:"expected_cwe"`
	Found        bool   `json:"found"`
	Confidence   float64 `json:"confidence,omitempty"`
	ActualType   string `json:"actual_type,omitempty"`
}

func main() {
	target := flag.String("target", "dvwa", "Target app name (dvwa, webgoat)")
	url := flag.String("url", "http://localhost:4280", "Target URL")
	aresBin := flag.String("ares", "", "Path to ARES binary (default: build from source)")
	flag.Parse()

	start := time.Now()

	// 1. Build ARES if needed
	binary := *aresBin
	if binary == "" {
		binary = buildARES()
		if binary == "" {
			fmt.Fprintf(os.Stderr, "FAILED to build ARES\n")
			os.Exit(1)
		}
		defer os.Remove(binary)
	}

	// 2. Load expected findings
	expectedPath := filepath.Join("tests", "benchmark", "expected", fmt.Sprintf("%s_*.json", *target))
	matches, _ := filepath.Glob(expectedPath)
	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "No expected findings found for target %q\n", *target)
		os.Exit(1)
	}

	var expected []ExpectedFinding
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", m, err)
			os.Exit(1)
		}
		var fe []ExpectedFinding
		if err := json.Unmarshal(data, &fe); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", m, err)
			os.Exit(1)
		}
		expected = append(expected, fe...)
	}

	fmt.Printf("Benchmarking ARES against %s (%s)\n", *target, *url)
	fmt.Printf("Expected findings: %d\n", len(expected))

	// 3. Run ARES scan
	reportFile := filepath.Join("tests", "benchmark", "report", fmt.Sprintf("report_%s_%d.json", *target, time.Now().Unix()))
	scanID, err := runScan(binary, *url, reportFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Scan completed (ID: %s)\n", scanID)

	// 4. Load actual findings from report
	actualFindings := loadFindings(reportFile)

	// 5. Compare: compute precision, recall, F1
	result := compare(expected, actualFindings, *target, time.Since(start))

	// 6. Write report
	result.Timestamp = time.Now().UTC().Format(time.RFC3339)
	result.Duration = time.Since(start).String()
	reportData, _ := json.MarshalIndent(result, "", "  ")
	reportPath := filepath.Join("tests", "benchmark", "report", fmt.Sprintf("result_%s_%d.json", *target, time.Now().Unix()))
	os.WriteFile(reportPath, reportData, 0644)

	fmt.Printf("\n=== BENCHMARK RESULTS ===\n")
	fmt.Printf("Target:     %s\n", result.Target)
	fmt.Printf("Precision:  %.2f%%\n", result.Precision*100)
	fmt.Printf("Recall:     %.2f%%\n", result.Recall*100)
	fmt.Printf("F1 Score:   %.2f%%\n", result.F1*100)
	fmt.Printf("Detected:   %d/%d\n", result.Detected, result.Total)
	fmt.Printf("False Pos:  %d\n", result.FalsePos)
	fmt.Printf("Duration:   %s\n", result.Duration)
}

func buildARES() string {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("ares-bench-%d", time.Now().UnixNano()))
	cmd := exec.Command("go", "build", "-o", tmp, "./cmd/ares")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "Build failed: %v\n%s\n", err, out)
		return ""
	}
	return tmp
}

func runScan(binary, targetURL, reportPath string) (string, error) {
	cmd := exec.Command(binary,
		"-target", targetURL,
		"-output", reportPath,
		"-phases", "recon,scan,exploit,report",
		"-max-iter", "30",
	)
	cmd.Env = append(os.Environ(),
		"ARES_DISABLE_PROMPT=true",
		"ARES_SKIP_OWNERSHIP_CHECK=true",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}
	// Parse scan ID from output
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "scan_id") || strings.Contains(line, "Scan ID") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[len(parts)-1]), nil
			}
		}
	}
	return "unknown", nil
}

func loadFindings(path string) []map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read report %s: %v\n", path, err)
		return nil
	}
	var report struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not parse report: %v\n", err)
		return nil
	}
	return report.Findings
}

func compare(expected []ExpectedFinding, actual []map[string]interface{}, target string, dur time.Duration) BenchmarkResult {
	result := BenchmarkResult{
		Target:   target,
		Duration: dur.String(),
	}

	detected := 0
	for _, exp := range expected {
		match := FindingMatch{
			ExpectedType: exp.Type,
			ExpectedCWE:  exp.CWE,
			Found:        false,
		}
		for _, act := range actual {
			actualType, _ := act["type"].(string)
			actualCWE, _ := act["cwe"].(string)
			actualEndpoint, _ := act["target"].(string)
			confidence, _ := act["confidence"].(float64)

			if strings.Contains(actualEndpoint, exp.Endpoint) {
				if exp.CWE == "" || actualCWE == exp.CWE || actualType == exp.Type {
					if confidence >= exp.MinConfidence {
						match.Found = true
						match.Confidence = confidence
						match.ActualType = actualType
						detected++
						break
					}
				}
			}
		}
		if !match.Found {
			result.Missed++
		}
		result.Details = append(result.Details, match)
	}

	// Count false positives: actual findings that don't match any expected
	fpCount := 0
	for _, act := range actual {
		matched := false
		for _, exp := range expected {
			actualEndpoint, _ := act["target"].(string)
			if strings.Contains(actualEndpoint, exp.Endpoint) {
				matched = true
				break
			}
		}
		if !matched {
			fpCount++
		}
	}

	result.Total = len(expected)
	result.Detected = detected
	result.FalsePos = fpCount

	if detected+fpCount > 0 {
		result.Precision = float64(detected) / float64(detected+fpCount)
	}
	if result.Total > 0 {
		result.Recall = float64(detected) / float64(result.Total)
	}
	if result.Precision+result.Recall > 0 {
		result.F1 = 2 * result.Precision * result.Recall / (result.Precision + result.Recall)
	}

	return result
}
