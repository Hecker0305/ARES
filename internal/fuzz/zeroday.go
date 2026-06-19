package fuzz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/differential"
)

type ZeroDayResult struct {
	Type        string  `json:"type"`
	Target      string  `json:"target"`
	Payload     string  `json:"payload"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Evidence    string  `json:"evidence"`
}

type ZeroDayConfig struct {
	BehavioralFuzz bool
	ParserDiffs    bool
	TimingAnalysis bool
	MutationCount  int
	Concurrency    int
	RequestTimeout time.Duration
	MaxMemoryMB    int64
	CPULimit       float64
	MaxRequests    int
}

type ZeroDayEngine struct {
	cfg          ZeroDayConfig
	fuzzer       *AdaptiveFuzzer
	diffEng      *differential.Engine
	results      []ZeroDayResult
	mu           sync.Mutex
	requestCount int
	requestMu    sync.Mutex
}

func NewZeroDayEngine(cfg ZeroDayConfig) *ZeroDayEngine {
	if cfg.MutationCount <= 0 {
		cfg.MutationCount = 100
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.MaxMemoryMB <= 0 {
		cfg.MaxMemoryMB = 512
	}
	if cfg.CPULimit <= 0 {
		cfg.CPULimit = 80.0
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 500
	}

	return &ZeroDayEngine{
		cfg: cfg,
		fuzzer: NewAdaptiveFuzzer(FuzzConfig{
			Mutations:    cfg.MutationCount,
			Concurrency:  cfg.Concurrency,
			Timeout:      cfg.RequestTimeout,
			AdaptiveMode: true,
			WAFDetection: true,
			MaxMemoryMB:  cfg.MaxMemoryMB,
		}),
		diffEng: differential.NewEngine(),
	}
}

func (e *ZeroDayEngine) canMakeRequest() bool {
	e.requestMu.Lock()
	defer e.requestMu.Unlock()
	if e.requestCount >= e.cfg.MaxRequests {
		return false
	}
	e.requestCount++
	return true
}

func (e *ZeroDayEngine) Run(ctx context.Context, target string) ([]ZeroDayResult, error) {
	e.mu.Lock()
	e.results = nil
	e.mu.Unlock()

	runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	resultCh := make(chan []ZeroDayResult, 3)

	if e.cfg.BehavioralFuzz {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := e.runBehavioralFuzz(runCtx, target)
			if err != nil {
				errCh <- fmt.Errorf("behavioral fuzz: %w", err)
				return
			}
			resultCh <- results
		}()
	}

	if e.cfg.ParserDiffs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := e.runParserDifferentials(runCtx, target)
			if err != nil {
				errCh <- fmt.Errorf("parser diff: %w", err)
				return
			}
			resultCh <- results
		}()
	}

	if e.cfg.TimingAnalysis {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := e.runTimingAnalysis(runCtx, target)
			if err != nil {
				errCh <- fmt.Errorf("timing analysis: %w", err)
				return
			}
			resultCh <- results
		}()
	}

	wg.Wait()
	close(errCh)
	close(resultCh)

	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}

	var all []ZeroDayResult
	for results := range resultCh {
		all = append(all, results...)
	}

	e.mu.Lock()
	e.results = all
	e.mu.Unlock()

	return all, nil
}

func (e *ZeroDayEngine) runBehavioralFuzz(ctx context.Context, target string) ([]ZeroDayResult, error) {
	basePayloads := []string{
		"<script>alert(1)</script>",
		"' OR '1'='1",
		"${7*7}",
		"{{7*7}}",
		"../../etc/passwd",
		"//example.com@",
	}

	fuzzResults := e.fuzzer.Run(ctx, target, basePayloads)
	var results []ZeroDayResult
	for _, fr := range fuzzResults {
		if !fr.Success {
			continue
		}
		sev := "medium"
		conf := 0.5
		if fr.DetectedWAF {
			sev = "high"
			conf = 0.7
		}
		desc := fmt.Sprintf("Behavioral anomaly: payload %q returned status %d", fr.Payload, fr.StatusCode)
		if fr.DetectedWAF {
			desc = fmt.Sprintf("WAF-evasion behavioral anomaly: payload %q bypassed WAF detection", fr.Payload)
		}
		results = append(results, ZeroDayResult{
			Type:        "behavioral_fuzz",
			Target:      fr.URL,
			Payload:     fr.Payload,
			Description: desc,
			Severity:    sev,
			Confidence:  conf,
			Evidence:    fmt.Sprintf("Status: %d, Mutations tried: %d", fr.StatusCode, len(fr.Mutations)),
		})
	}
	return results, nil
}

func (e *ZeroDayEngine) runParserDifferentials(ctx context.Context, target string) ([]ZeroDayResult, error) {
	testCases := []struct {
		name  string
		pathA string
		pathB string
	}{
		{"JSON whitespace diff", "", ""},
		{"URL parameter duplication", "/api/users?id=1", "/api/users?id=1&id=2"},
		{"Unicode normalization", "/search?q=%E2%82%AC", "/search?q=€"},
		{"Null byte injection", "/api/file.txt%00.html", "/api/file.txt"},
		{"Case sensitivity", "/API/Users/1", "/api/users/1"},
		{"Path traversal", "/api/users/../users/1", "/api/users/1"},
	}

	client := &http.Client{Timeout: e.cfg.RequestTimeout}
	var results []ZeroDayResult
	for _, tc := range testCases {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if !e.canMakeRequest() {
			return results, fmt.Errorf("request budget exhausted")
		}

		reqA, err := http.NewRequestWithContext(ctx, http.MethodGet, target+tc.pathA, nil)
		if err != nil {
			continue
		}
		reqB, err := http.NewRequestWithContext(ctx, http.MethodGet, target+tc.pathB, nil)
		if err != nil {
			continue
		}

		respA, err := client.Do(reqA)
		if err != nil {
			continue
		}
		bodyA, _ := io.ReadAll(io.LimitReader(respA.Body, 1<<20))
		respA.Body.Close()

		respB, err := client.Do(reqB)
		if err != nil {
			continue
		}
		bodyB, _ := io.ReadAll(io.LimitReader(respB.Body, 1<<20))
		respB.Body.Close()

		similarity, _ := e.diffEng.CompareResponse(string(bodyA), string(bodyB))
		statusMatch := respA.StatusCode == respB.StatusCode

		if !statusMatch || similarity < 0.9 {
			results = append(results, ZeroDayResult{
				Type:        "parser_differential",
				Target:      target,
				Description: fmt.Sprintf("Parser differential: %s (status %d vs %d, similarity %.0f%%)", tc.name, respA.StatusCode, respB.StatusCode, similarity*100),
				Severity:    "medium",
				Confidence:  0.6,
				Evidence:    fmt.Sprintf("Path A: %s, Path B: %s, Status A: %d, Status B: %d, Similarity: %.4f", tc.pathA, tc.pathB, respA.StatusCode, respB.StatusCode, similarity),
			})
		}
	}
	return results, nil
}

func (e *ZeroDayEngine) runTimingAnalysis(ctx context.Context, target string) ([]ZeroDayResult, error) {
	timingPayloads := []struct {
		name    string
		payload string
		window  time.Duration
	}{
		{"Sleep-based timing", "/api?delay=5000", 2 * time.Second},
		{"Regex DoS", "/search?q=" + strings.Repeat("a", 100) + "!", 3 * time.Second},
		{"Hash collision", "/api/login?password=" + strings.Repeat("A", 256), 2 * time.Second},
	}

	var results []ZeroDayResult
	baselineDuration, err := e.measureRequestLatency(ctx, target, 3, e.cfg.RequestTimeout)
	if err != nil {
		return nil, fmt.Errorf("timing baseline: %w", err)
	}

	for _, tp := range timingPayloads {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		duration, err := e.measureRequestLatency(ctx, target+tp.payload, 3, e.cfg.RequestTimeout)
		if err != nil {
			continue
		}

		ratio := duration.Seconds() / baselineDuration.Seconds()
		if ratio > 1.5 && duration > tp.window {
			sev := "medium"
			conf := 0.5
			if ratio > 3.0 {
				sev = "high"
				conf = 0.75
			}
			results = append(results, ZeroDayResult{
				Type:        "timing_side_channel",
				Target:      target + tp.payload,
				Description: fmt.Sprintf("Timing anomaly: %s (%.1fx baseline, took %v)", tp.name, ratio, duration),
				Severity:    sev,
				Confidence:  conf,
				Evidence:    fmt.Sprintf("Baseline: %v, Actual: %v, Ratio: %.2f", baselineDuration, duration, ratio),
			})
		}
	}
	return results, nil
}

func (e *ZeroDayEngine) measureRequestLatency(ctx context.Context, url string, samples int, timeout time.Duration) (time.Duration, error) {
	if samples <= 0 || samples > 5 {
		samples = 3
	}
	client := &http.Client{Timeout: timeout}
	var total time.Duration
	var count int

	for i := 0; i < samples; i++ {
		if !e.canMakeRequest() {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		total += time.Since(start)
		count++
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if count == 0 {
		return 0, fmt.Errorf("no successful requests")
	}
	return total / time.Duration(count), nil
}

func (e *ZeroDayEngine) Results() []ZeroDayResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	cpy := make([]ZeroDayResult, len(e.results))
	copy(cpy, e.results)
	return cpy
}

func FormatZeroDayResults(results []ZeroDayResult) string {
	if len(results) == 0 {
		return "No zero-day anomalies detected during this phase."
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== Zero-Day Discovery Results (%d anomalies) ===\n", len(results)))
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sorted := make([]ZeroDayResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return severityOrder[sorted[i].Severity] < severityOrder[sorted[j].Severity]
	})
	for _, r := range sorted {
		b.WriteString(fmt.Sprintf("[%s] [%.0f%% conf] %s\n", strings.ToUpper(r.Severity), r.Confidence*100, r.Description))
		b.WriteString(fmt.Sprintf("  Target: %s\n", r.Target))
		if r.Evidence != "" {
			b.WriteString(fmt.Sprintf("  Evidence: %s\n", r.Evidence))
		}
	}
	return b.String()
}
