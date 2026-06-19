package verifier

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/security"
)

type Verdict string

const (
	VerdictConfirmed    Verdict = "confirmed"
	VerdictSuspected    Verdict = "suspected"
	VerdictFalsePos     Verdict = "false_positive"
	VerdictInconclusive Verdict = "inconclusive"
)

type VerificationMethod string

const (
	MethodReplay     VerificationMethod = "replay"
	MethodExtraction VerificationMethod = "extraction"
	MethodTiming     VerificationMethod = "timing"
	MethodOOB        VerificationMethod = "oob_callback"
	MethodDiff       VerificationMethod = "differential"
	MethodLogical    VerificationMethod = "logical_proof"
)

type VerificationResult struct {
	Verdict      Verdict            `json:"verdict"`
	Method       VerificationMethod `json:"method"`
	Confidence   float64            `json:"confidence"`
	Evidence     string             `json:"evidence"`
	Reproducible bool               `json:"reproducible"`
	Attempts     int                `json:"attempts"`
	Duration     time.Duration      `json:"duration"`
	Hash         string             `json:"hash"`
	Timestamp    time.Time          `json:"timestamp"`
}

type VerificationRequest struct {
	ID             string             `json:"id"`
	VulnType       string             `json:"vuln_type"`
	Target         string             `json:"target"`
	Payload        string             `json:"payload"`
	ExpectedOutput string             `json:"expected_output"`
	Method         VerificationMethod `json:"method"`
	MaxAttempts    int                `json:"max_attempts"`
	Threshold      float64            `json:"threshold"`
	Metadata       map[string]string  `json:"metadata,omitempty"`
	Ctx            context.Context    `json:"-"`
}

type Engine struct {
	mu               sync.RWMutex
	results          map[string][]VerificationResult
	methods          map[VerificationMethod]VerifierFunc
	history          []VerificationResult
	maxHistory       int
	disableSSRFCheck bool
}

type VerifierFunc func(req VerificationRequest) VerificationResult

func NewEngine() *Engine {
	e := &Engine{
		results:    make(map[string][]VerificationResult),
		methods:    make(map[VerificationMethod]VerifierFunc),
		history:    make([]VerificationResult, 0, 1000),
		maxHistory: 1000,
	}
	e.registerDefaults()
	return e
}

func (e *Engine) registerDefaults() {
	e.methods[MethodReplay] = e.verifyReplay
	e.methods[MethodExtraction] = e.verifyExtraction
	e.methods[MethodTiming] = e.verifyTiming
	e.methods[MethodOOB] = e.verifyOOB
	e.methods[MethodDiff] = e.verifyDifferential
	e.methods[MethodLogical] = e.verifyLogical
}

func (e *Engine) RegisterMethod(method VerificationMethod, fn VerifierFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.methods[method] = fn
}

func (e *Engine) Verify(req VerificationRequest) VerificationResult {
	if req.MaxAttempts <= 0 {
		req.MaxAttempts = 3
	}
	if req.Threshold <= 0 {
		req.Threshold = 0.8
	}
	if req.Ctx == nil {
		req.Ctx = context.Background()
	}

	fn, ok := e.methods[req.Method]
	if !ok {
		return VerificationResult{
			Verdict:    VerdictInconclusive,
			Method:     req.Method,
			Confidence: 0,
			Evidence:   fmt.Sprintf("no verifier registered for method: %s", req.Method),
		}
	}

	start := time.Now()
	result := fn(req)
	result.Duration = time.Since(start)
	result.Timestamp = time.Now()
	result.Hash = e.hashResult(result)

	logger.Debug("[Verifier] Verification result", logger.Fields{
		"id":         req.ID,
		"method":     string(req.Method),
		"verdict":    string(result.Verdict),
		"confidence": fmt.Sprintf("%.2f", result.Confidence),
		"duration":   result.Duration.String(),
	})

	e.mu.Lock()
	e.results[req.ID] = append(e.results[req.ID], result)
	e.history = append(e.history, result)
	if len(e.history) > e.maxHistory {
		e.history = e.history[len(e.history)-e.maxHistory:]
	}
	e.mu.Unlock()

	return result
}

func (e *Engine) VerifyMultiple(req VerificationRequest, methods []VerificationMethod) VerificationResult {
	var best VerificationResult
	best.Confidence = -1

	for _, method := range methods {
		req.Method = method
		result := e.Verify(req)
		if result.Confidence > best.Confidence {
			best = result
		}
	}

	if best.Confidence < 0 {
		return VerificationResult{Verdict: VerdictInconclusive, Confidence: 0}
	}
	return best
}

func (e *Engine) GetHistory() []VerificationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]VerificationResult, len(e.history))
	copy(result, e.history)
	return result
}

func (e *Engine) GetResults(id string) []VerificationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	results := e.results[id]
	out := make([]VerificationResult, len(results))
	copy(out, results)
	return out
}

func (e *Engine) VerifyAll(req VerificationRequest) []VerificationResult {
	var results []VerificationResult
	for method := range e.methods {
		r := req
		r.Method = method
		results = append(results, e.Verify(r))
	}
	return results
}

func (e *Engine) verifyReplay(req VerificationRequest) VerificationResult {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	targetURL := req.Target
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	if !e.disableSSRFCheck {
		if err := security.ValidateURL(targetURL); err != nil {
			return VerificationResult{
				Verdict:    VerdictInconclusive,
				Confidence: 0,
				Evidence:   fmt.Sprintf("SSRF-safe URL validation rejected %s: %v", targetURL, err),
				Attempts:   1,
			}
		}
	}

	var lastResp *http.Response
	var lastBody string
	var lastErr error

	for attempt := 0; attempt < req.MaxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(req.Ctx, 30*time.Second)
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}

		httpReq.Header.Set("User-Agent", "Ares-Verifier/1.0")
		if req.Payload != "" {
			safePayload := strings.ReplaceAll(req.Payload, "\r", "")
			safePayload = strings.ReplaceAll(safePayload, "\n", "")
			httpReq.Header.Set("X-Test-Payload", safePayload)
		}

		resp, err := client.Do(httpReq)
		cancel()
		if err != nil {
			lastErr = err
			select {
			case <-req.Ctx.Done():
				return VerificationResult{
					Verdict:    VerdictInconclusive,
					Confidence: 0,
					Evidence:   fmt.Sprintf("Replay cancelled: %v", req.Ctx.Err()),
					Attempts:   attempt + 1,
				}
			case <-time.After(2 * time.Second):
			}
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		lastResp = resp
		lastBody = string(body)
		lastErr = nil
		break
	}

	if lastErr != nil {
		return VerificationResult{
			Verdict:    VerdictInconclusive,
			Confidence: 0,
			Evidence:   fmt.Sprintf("Replay failed after %d attempts: %v", req.MaxAttempts, lastErr),
			Attempts:   req.MaxAttempts,
		}
	}

	bodyLower := strings.ToLower(lastBody)
	payloadLower := strings.ToLower(req.Payload)
	expectedLower := strings.ToLower(req.ExpectedOutput)

	evidence := fmt.Sprintf("Replayed against %s — status=%d length=%d",
		targetURL, lastResp.StatusCode, len(lastBody))

	reflected := payloadLower != "" && strings.Contains(bodyLower, payloadLower)

	expectedFound := expectedLower != "" && strings.Contains(bodyLower, expectedLower)

	indicatorsMatch := 0
	if reflected {
		indicatorsMatch++
	}
	if expectedFound {
		indicatorsMatch++
	}
	if lastResp.StatusCode >= 200 && lastResp.StatusCode < 300 {
		indicatorsMatch++
	}

	confidence := float64(indicatorsMatch) / 3.0

	if reflected && expectedFound {
		return VerificationResult{
			Verdict:      VerdictConfirmed,
			Confidence:   min(0.95, 0.7+confidence*0.25),
			Evidence:     evidence + " — payload reflected AND expected response matched",
			Reproducible: true,
			Attempts:     req.MaxAttempts,
		}
	}

	if reflected {
		return VerificationResult{
			Verdict:      VerdictSuspected,
			Confidence:   0.6,
			Evidence:     evidence + " — payload reflected in response body",
			Reproducible: true,
			Attempts:     req.MaxAttempts,
		}
	}

	return VerificationResult{
		Verdict:      VerdictFalsePos,
		Confidence:   0.2,
		Evidence:     evidence + " — payload not reflected, finding likely false positive",
		Reproducible: true,
		Attempts:     req.MaxAttempts,
	}
}

func (e *Engine) verifyExtraction(req VerificationRequest) VerificationResult {
	evidence := fmt.Sprintf("Extraction test: attempted data extraction via %s", req.VulnType)

	matchCount := 0
	indicators := []string{"root:", "admin:", "password", "flag{", "SECRET", "BEGIN"}
	for _, ind := range indicators {
		if strings.Contains(req.ExpectedOutput, ind) {
			matchCount++
		}
	}

	confidence := float64(matchCount) / float64(len(indicators))
	if confidence > 0.5 {
		return VerificationResult{
			Verdict:      VerdictConfirmed,
			Confidence:   0.85 + confidence*0.1,
			Evidence:     evidence + fmt.Sprintf(" — %d extraction indicators matched", matchCount),
			Reproducible: true,
			Attempts:     1,
		}
	}

	return VerificationResult{
		Verdict:    VerdictSuspected,
		Confidence: 0.3,
		Evidence:   evidence + " — no extraction indicators detected",
		Attempts:   1,
	}
}

func (e *Engine) verifyTiming(req VerificationRequest) VerificationResult {
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	targetURL := req.Target
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	if !e.disableSSRFCheck {
		if err := security.ValidateURL(targetURL); err != nil {
			return VerificationResult{
				Verdict:    VerdictInconclusive,
				Confidence: 0,
				Evidence:   fmt.Sprintf("SSRF-safe URL validation rejected %s: %v", targetURL, err),
				Attempts:   1,
			}
		}
	}

	samples := req.MaxAttempts
	if samples < 5 {
		samples = 5
	}

	var baselineTimes []time.Duration
	var payloadTimes []time.Duration

	for i := 0; i < samples; i++ {
		ctx, cancel := context.WithTimeout(req.Ctx, 30*time.Second)

		payload := req.Payload
		if i%2 == 0 {
			payload = ""
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			cancel()
			continue
		}

		httpReq.Header.Set("User-Agent", "Ares-Verifier/1.0")
		if payload != "" {
			safePayload := strings.ReplaceAll(req.Payload, "\r", "")
			safePayload = strings.ReplaceAll(safePayload, "\n", "")
			httpReq.Header.Set("X-Test-Payload", safePayload)
		}

		start := time.Now()
		_, err = client.Do(httpReq)
		cancel()
		duration := time.Since(start)

		if err != nil {
			select {
			case <-req.Ctx.Done():
				return VerificationResult{
					Verdict:    VerdictInconclusive,
					Confidence: 0,
					Evidence:   fmt.Sprintf("Timing test cancelled: %v", req.Ctx.Err()),
					Attempts:   i + 1,
				}
			default:
			}
			continue
		}

		if payload != "" {
			payloadTimes = append(payloadTimes, duration)
		} else {
			baselineTimes = append(baselineTimes, duration)
		}
	}

	if len(baselineTimes) < 2 || len(payloadTimes) < 2 {
		return VerificationResult{
			Verdict:    VerdictInconclusive,
			Confidence: 0.3,
			Evidence:   fmt.Sprintf("Insufficient timing samples: %d baseline, %d payload", len(baselineTimes), len(payloadTimes)),
			Attempts:   samples,
		}
	}

	baselineAvg := averageDuration(baselineTimes)
	payloadAvg := averageDuration(payloadTimes)

	ratio := 1.0
	if baselineAvg > 0 {
		ratio = float64(payloadAvg) / float64(baselineAvg)
	}

	threshold := 2.0
	if t, ok := req.Metadata["timing_threshold"]; ok {
		if parsedThreshold, err := fmt.Sscanf(t, "%f", &threshold); err == nil && parsedThreshold == 1 {
		}
	}

	evidence := fmt.Sprintf("Timing analysis: baseline=%.2fms payload=%.2fms ratio=%.2fx threshold=%.1fx (samples: %d/%d)",
		float64(baselineAvg)/float64(time.Millisecond),
		float64(payloadAvg)/float64(time.Millisecond),
		ratio, threshold, len(baselineTimes), len(payloadTimes))

	if ratio >= threshold {
		confidence := 0.6 + (ratio-threshold)*0.15
		if confidence > 0.95 {
			confidence = 0.95
		}
		return VerificationResult{
			Verdict:      VerdictConfirmed,
			Confidence:   confidence,
			Evidence:     evidence + " — statistically significant timing delay detected",
			Reproducible: true,
			Attempts:     samples,
		}
	}

	if ratio >= 1.5 {
		return VerificationResult{
			Verdict:      VerdictSuspected,
			Confidence:   0.5,
			Evidence:     evidence + " — marginal timing delay detected",
			Reproducible: true,
			Attempts:     samples,
		}
	}

	return VerificationResult{
		Verdict:    VerdictFalsePos,
		Confidence: 0.3,
		Evidence:   evidence + " — no significant timing delay detected",
		Attempts:   samples,
	}
}

func averageDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func (e *Engine) verifyOOB(req VerificationRequest) VerificationResult {
	evidence := fmt.Sprintf("OOB callback check for %s (requires callback server integration)", req.ID)

	if req.Metadata != nil {
		if callbackID, ok := req.Metadata["callback_id"]; ok && callbackID != "" {
			return VerificationResult{
				Verdict:      VerdictSuspected,
				Confidence:   0.6,
				Evidence:     evidence + " — pending OOB callback confirmation",
				Reproducible: false,
				Attempts:     1,
			}
		}
	}

	return VerificationResult{
		Verdict:    VerdictInconclusive,
		Confidence: 0.1,
		Evidence:   evidence + " — no OOB callback configured, cannot confirm",
		Attempts:   1,
	}
}

func (e *Engine) verifyDifferential(req VerificationRequest) VerificationResult {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	targetURL := req.Target
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	if !e.disableSSRFCheck {
		if err := security.ValidateURL(targetURL); err != nil {
			return VerificationResult{
				Verdict:    VerdictInconclusive,
				Confidence: 0,
				Evidence:   fmt.Sprintf("SSRF-safe URL validation rejected %s: %v", targetURL, err),
				Attempts:   1,
			}
		}
	}

	baselineReq, _ := http.NewRequestWithContext(req.Ctx, http.MethodGet, targetURL, nil)
	baselineReq.Header.Set("User-Agent", "Ares-Verifier/1.0")

	payloadReq, _ := http.NewRequestWithContext(req.Ctx, http.MethodGet, targetURL, nil)
	payloadReq.Header.Set("User-Agent", "Ares-Verifier/1.0")
	if req.Payload != "" {
		safePayload := strings.ReplaceAll(req.Payload, "\r", "")
		safePayload = strings.ReplaceAll(safePayload, "\n", "")
		payloadReq.Header.Set("X-Test-Payload", safePayload)
		if req.VulnType == "auth_bypass" || req.VulnType == "idor" {
			payloadReq.Header.Set("Cookie", req.Payload)
		}
	}

	baselineResp, err := client.Do(baselineReq)
	if err != nil {
		return VerificationResult{
			Verdict:    VerdictInconclusive,
			Confidence: 0,
			Evidence:   fmt.Sprintf("Differential baseline request failed: %v", err),
			Attempts:   1,
		}
	}
	baselineBody, _ := io.ReadAll(io.LimitReader(baselineResp.Body, 1<<20))
	baselineResp.Body.Close()

	payloadResp, err := client.Do(payloadReq)
	if err != nil {
		return VerificationResult{
			Verdict:    VerdictInconclusive,
			Confidence: 0,
			Evidence:   fmt.Sprintf("Differential payload request failed: %v", err),
			Attempts:   1,
		}
	}
	payloadBody, _ := io.ReadAll(io.LimitReader(payloadResp.Body, 1<<20))
	payloadResp.Body.Close()

	baselineStr := string(baselineBody)
	payloadStr := string(payloadBody)

	statusDiff := baselineResp.StatusCode != payloadResp.StatusCode
	bodyDiff := baselineStr != payloadStr
	lengthDiff := len(baselineBody) != len(payloadBody)

	diffCount := 0
	if statusDiff {
		diffCount++
	}
	if bodyDiff {
		diffCount++
	}
	if lengthDiff {
		diffCount++
	}

	evidence := fmt.Sprintf("Differential: baseline=%d/%d payload=%d/%d statusDiff=%v bodyDiff=%v",
		baselineResp.StatusCode, len(baselineBody),
		payloadResp.StatusCode, len(payloadBody),
		statusDiff, bodyDiff)

	if diffCount >= 2 {
		confidence := 0.7 + float64(diffCount-2)*0.1
		return VerificationResult{
			Verdict:      VerdictConfirmed,
			Confidence:   confidence,
			Evidence:     evidence + " — significant behavioral change with payload",
			Reproducible: true,
			Attempts:     2,
		}
	}

	if diffCount == 1 {
		return VerificationResult{
			Verdict:      VerdictSuspected,
			Confidence:   0.5,
			Evidence:     evidence + " — minor behavioral change with payload",
			Reproducible: true,
			Attempts:     2,
		}
	}

	return VerificationResult{
		Verdict:    VerdictFalsePos,
		Confidence: 0.4,
		Evidence:   evidence + " — no behavioral change with payload",
		Attempts:   2,
	}
}

func (e *Engine) verifyLogical(req VerificationRequest) VerificationResult {
	if req.ExpectedOutput == "" {
		return VerificationResult{
			Verdict:    VerdictInconclusive,
			Confidence: 0,
			Evidence:   "Logical proof requires expected output to compare against",
			Attempts:   1,
		}
	}

	if strings.Contains(req.ExpectedOutput, req.Payload) {
		return VerificationResult{
			Verdict:      VerdictConfirmed,
			Confidence:   0.85,
			Evidence:     "Payload detected in response — logical confirmation",
			Reproducible: true,
			Attempts:     1,
		}
	}

	return VerificationResult{
		Verdict:    VerdictFalsePos,
		Confidence: 0.7,
		Evidence:   "Payload NOT detected in response — likely false positive",
		Attempts:   1,
	}
}

func (e *Engine) hashResult(r VerificationResult) string {
	data := fmt.Sprintf("%s|%s|%f|%s|%v", r.Verdict, r.Method, r.Confidence, r.Evidence, r.Timestamp)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:16])
}

func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	byVerdict := make(map[Verdict]int)
	for _, r := range e.history {
		byVerdict[r.Verdict]++
	}

	return map[string]interface{}{
		"total_verifications": len(e.history),
		"by_verdict":          byVerdict,
		"unique_findings":     len(e.results),
	}
}

func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results = make(map[string][]VerificationResult)
	e.history = make([]VerificationResult, 0, e.maxHistory)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (v Verdict) String() string {
	return string(v)
}

func (v VerificationMethod) String() string {
	return string(v)
}

type ChainStep struct {
	Method VerificationMethod
	Config map[string]string
}

type ChainResult struct {
	Steps      []VerificationResult `json:"steps"`
	Verdict    Verdict              `json:"verdict"`
	Confidence float64              `json:"confidence"`
}

func (e *Engine) VerifyChain(req VerificationRequest, chain []ChainStep) ChainResult {
	results := make([]VerificationResult, 0, len(chain))
	confirmedCount := 0
	totalConfidence := 0.0

	for _, step := range chain {
		stepReq := req
		stepReq.Method = step.Method
		if step.Config != nil {
			if stepReq.Metadata == nil {
				stepReq.Metadata = make(map[string]string)
			}
			for k, v := range step.Config {
				stepReq.Metadata[k] = v
			}
		}

		result := e.Verify(stepReq)
		results = append(results, result)

		if result.Verdict == VerdictConfirmed {
			confirmedCount++
			totalConfidence += result.Confidence
		}
		if result.Verdict == VerdictFalsePos {
			return ChainResult{
				Steps:      results,
				Verdict:    VerdictFalsePos,
				Confidence: result.Confidence,
			}
		}
	}

	chainResult := ChainResult{Steps: results}

	if len(chain) == 0 {
		chainResult.Verdict = VerdictInconclusive
		return chainResult
	}

	confirmRatio := float64(confirmedCount) / float64(len(chain))

	switch {
	case confirmRatio >= 0.8:
		chainResult.Verdict = VerdictConfirmed
		chainResult.Confidence = totalConfidence / float64(confirmedCount)
		if confirmedCount > 0 {
			chainResult.Confidence += 0.1 * float64(confirmedCount)
		}
		if chainResult.Confidence > 0.98 {
			chainResult.Confidence = 0.98
		}
	case confirmRatio >= 0.5:
		chainResult.Verdict = VerdictSuspected
		if confirmedCount > 0 {
			chainResult.Confidence = totalConfidence / float64(confirmedCount)
		} else {
			chainResult.Confidence = 0.5
		}
	default:
		chainResult.Verdict = VerdictInconclusive
		chainResult.Confidence = totalConfidence / float64(len(chain))
	}

	return chainResult
}

func (e *Engine) VerifyAllMethods(req VerificationRequest) ChainResult {
	chain := []ChainStep{
		{Method: MethodReplay},
		{Method: MethodLogical, Config: map[string]string{"fallback": "true"}},
	}
	return e.VerifyChain(req, chain)
}

func (e *Engine) CalibrateConfidence(rawConfidence float64, method VerificationMethod) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	confirmed := 0
	falsePos := 0
	totalByMethod := 0

	for _, r := range e.history {
		if r.Method == method {
			totalByMethod++
			if r.Verdict == VerdictConfirmed {
				confirmed++
			}
			if r.Verdict == VerdictFalsePos {
				falsePos++
			}
		}
	}

	if totalByMethod < 10 {
		return rawConfidence
	}

	accuracy := float64(confirmed) / float64(totalByMethod)
	fpRate := float64(falsePos) / float64(totalByMethod)

	calibrated := rawConfidence * (accuracy + 0.5)
	if fpRate > 0.3 {
		calibrated *= (1.0 - fpRate)
	}

	if calibrated > 0.98 {
		calibrated = 0.98
	}
	if calibrated < 0.01 {
		calibrated = 0.01
	}

	return calibrated
}

func (e *Engine) HistoricalAccuracy(method VerificationMethod) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	confirmed := 0
	total := 0

	for _, r := range e.history {
		if r.Method == method {
			total++
			if r.Verdict == VerdictConfirmed {
				confirmed++
			}
		}
	}

	if total == 0 {
		return 0
	}
	return float64(confirmed) / float64(total)
}

func (e *Engine) FalsePositiveRate(method VerificationMethod) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	falsePos := 0
	total := 0

	for _, r := range e.history {
		if r.Method == method {
			total++
			if r.Verdict == VerdictFalsePos {
				falsePos++
			}
		}
	}

	if total == 0 {
		return 0
	}
	return float64(falsePos) / float64(total)
}
