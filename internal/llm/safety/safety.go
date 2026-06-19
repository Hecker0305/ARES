package safety

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ares/engine/internal/logger"
)

var (
	ErrBudgetExceeded = errors.New("LLM budget exceeded")
	ErrRetryExceeded  = errors.New("LLM retry limit exceeded")
	ErrOutputBlocked  = errors.New("LLM output blocked by safety filter")
)

// SafetyConfig configures the LLM safety layer
type SafetyConfig struct {
	// Per-stage token budgets
	MaxPromptTokens     int
	MaxCompletionTokens int

	// Per-scan budgets
	MaxScanTokens   int
	MaxScanRequests int

	// Retry limits
	MaxRetriesPerRequest int
	MaxRetriesPerStep    int

	// Output filtering
	BlockPatterns   []string
	MaxOutputLength int

	// Timing limits
	RequestTimeout time.Duration
	TotalTimeout   time.Duration
}

// DefaultSafetyConfig returns a reasonable safety configuration
func DefaultSafetyConfig() SafetyConfig {
	return SafetyConfig{
		MaxPromptTokens:      100000,
		MaxCompletionTokens:  10000,
		MaxScanTokens:        1000000,
		MaxScanRequests:      1000,
		MaxRetriesPerRequest: 3,
		MaxRetriesPerStep:    3,
		BlockPatterns:        defaultBlockPatterns(),
		MaxOutputLength:      100000,
		RequestTimeout:       60 * time.Second,
		TotalTimeout:         30 * time.Minute,
	}
}

func defaultBlockPatterns() []string {
	return []string{
		// Code injection patterns — explicit function calls with arguments
		`(?i)(\beval\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|\bpassthru\s*\()`,
		`(?i)(\bdelete\s+from\s+\w+|insert\s+into\s+\w+.*\bvalues\b)`,

		// Prompt injection patterns
		`(?i)(ignore\s+(all|previous)\s+(instructions|commands))`,
		`(?i)(\byou are now\b.*\b(assistant|helpful|harmless)\b)`,
		`(?i)(system\s+prompt\s*:\s*|developer\s+mode\s*:\s*)`,
		`(?i)(jailbreak|dan\s+mode|unfiltered\s+mode)`,

		// Credential/secret patterns — only block explicit assignment, not usage
		`(?i)(?:^|\n).*(password|secret|api[_-]?key)\s*[=:]\s*['"][^'"]+['"]`,

		// Script embedding — only block HTML script tag injection, not legitimate JS analysis
		`(?s)(?:^|\n).*<script[^>]*>.*?</script>`,

		// Self-referential safety override attempts
		`(?i)disable\s+(your|the)\s+safety`,
		`(?i)ignore\s+(your|the)\s+(guidelines|rules|restrictions)`,
	}
}

// SafetyStatus represents the safety state of a request
type SafetyStatus int

const (
	StatusSafe SafetyStatus = iota
	StatusFlagged
	StatusBlocked
)

// SafetyCheckResult represents the result of a safety check
type SafetyCheckResult struct {
	Status  SafetyStatus
	Score   float64
	Flags   []string
	Blocked bool
	Reason  string
}

// TokenBudget tracks token usage for a scan or stage
type TokenBudget struct {
	mu         sync.RWMutex
	maxTokens  int64
	usedTokens int64
}

// NewTokenBudget creates a new token budget with the given max
func NewTokenBudget(maxTokens int64) *TokenBudget {
	return &TokenBudget{
		maxTokens: maxTokens,
	}
}

// Consume attempts to consume tokens from the budget
// Returns true if successful, false if budget would be exceeded
func (b *TokenBudget) Consume(tokens int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.usedTokens+tokens > b.maxTokens {
		return false
	}

	b.usedTokens += tokens
	return true
}

// Remaining returns the number of tokens remaining in the budget
func (b *TokenBudget) Remaining() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.maxTokens - b.usedTokens
}

// Used returns the number of tokens used
func (b *TokenBudget) Used() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.usedTokens
}

// Reset resets the budget
func (b *TokenBudget) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.usedTokens = 0
}

// RetryTracker tracks retry attempts for a request or step
type RetryTracker struct {
	mu          sync.RWMutex
	maxRetries  int
	attempts    int
	lastAttempt time.Time
}

// NewRetryTracker creates a new retry tracker with the given max retries
func NewRetryTracker(maxRetries int) *RetryTracker {
	return &RetryTracker{
		maxRetries: maxRetries,
	}
}

// CanRetry checks if another retry is allowed
func (r *RetryTracker) CanRetry() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts < r.maxRetries
}

// RecordAttempt records a retry attempt and returns the attempt number
func (r *RetryTracker) RecordAttempt() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	r.lastAttempt = time.Now()
	return r.attempts
}

// Attempts returns the number of recorded attempts
func (r *RetryTracker) Attempts() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.attempts
}

// OutputFilter provides output sanitization for LLM responses
type OutputFilter struct {
	patterns  []*regexp.Regexp
	maxLength int
	mu        sync.RWMutex
}

// NewOutputFilter creates a new output filter with the given patterns
func NewOutputFilter(patterns []string, maxLength int) *OutputFilter {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return &OutputFilter{
		patterns:  compiled,
		maxLength: maxLength,
	}
}

// Filter scans output for potentially dangerous content
func (f *OutputFilter) Filter(output string) (*SafetyCheckResult, string) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if output == "" {
		return &SafetyCheckResult{Status: StatusSafe}, ""
	}

	if len(output) > 100000 {
		output = output[:100000]
	}

	// Check length
	if f.maxLength > 0 && len(output) > f.maxLength {
		return &SafetyCheckResult{
			Status:  StatusFlagged,
			Score:   0.9,
			Flags:   []string{"output_exceeds_max_length"},
			Blocked: false,
			Reason:  fmt.Sprintf("output length %d exceeds max %d", len(output), f.maxLength),
		}, output[:f.maxLength] + "... [TRUNCATED]"
	}

	flags := []string{}

	for _, pattern := range f.patterns {
		if pattern.MatchString(output) {
			flags = append(flags, pattern.String())
		}
	}

	if len(flags) > 0 {
		score := float64(len(flags)) / float64(len(f.patterns))
		if score >= 0.5 {
			return &SafetyCheckResult{
				Status:  StatusBlocked,
				Score:   score,
				Flags:   flags,
				Blocked: true,
				Reason:  "output contains too many dangerous patterns",
			}, ""
		}
		return &SafetyCheckResult{
			Status:  StatusFlagged,
			Score:   score,
			Flags:   flags,
			Blocked: false,
			Reason:  "output contains suspicious patterns",
		}, output
	}

	return &SafetyCheckResult{
		Status:  StatusSafe,
		Score:   0,
		Flags:   nil,
		Blocked: false,
	}, output
}

// RequestLimiter provides rate limiting for LLM requests
type RequestLimiter struct {
	mu          sync.RWMutex
	maxRequests int
	requests    int
	windowStart time.Time
	window      time.Duration
}

// NewRequestLimiter creates a new request limiter
func NewRequestLimiter(maxRequests int, window time.Duration) *RequestLimiter {
	return &RequestLimiter{
		maxRequests: maxRequests,
		window:      window,
		windowStart: time.Now(),
	}
}

// Allow checks if a request is allowed within the rate limit
func (l *RequestLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.windowStart) > l.window {
		l.windowStart = now
		l.requests = 0
	}

	if l.requests >= l.maxRequests {
		return false
	}

	l.requests++
	return true
}

// Remaining returns the number of remaining requests in the current window
func (l *RequestLimiter) Remaining() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	remaining := l.maxRequests - l.requests
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// RequestSafetyCheck performs all safety checks for an LLM request
var (
	patternCache     map[string][]*regexp.Regexp
	patternCacheMu   sync.RWMutex
	patternCacheInit sync.Once
)

func initPatternCache() {
	patternCacheInit.Do(func() {
		patternCache = make(map[string][]*regexp.Regexp)
	})
}

func getCompiledPatterns(cfg SafetyConfig) []*regexp.Regexp {
	initPatternCache()
	key := fmt.Sprintf("%v", cfg.BlockPatterns)
	patternCacheMu.RLock()
	cached, ok := patternCache[key]
	patternCacheMu.RUnlock()
	if ok {
		return cached
	}

	compiled := make([]*regexp.Regexp, 0, len(cfg.BlockPatterns))
	for _, p := range cfg.BlockPatterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}

	patternCacheMu.Lock()
	patternCache[key] = compiled
	patternCacheMu.Unlock()
	return compiled
}

const perRegexTimeout = 2 * time.Second

func RequestSafetyCheck(ctx context.Context, prompt string, cfg SafetyConfig) (*SafetyCheckResult, error) {
	patterns := getCompiledPatterns(cfg)
	if len(patterns) == 0 {
		return &SafetyCheckResult{Status: StatusSafe}, nil
	}

	if len(prompt) > 100000 {
		prompt = prompt[:100000]
	}

	flags := make([]string, 0, len(patterns))
	guard := make(chan struct{}, 8)
	var mu sync.Mutex
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	for _, pattern := range patterns {
		pattern := pattern
		select {
		case guard <- struct{}{}:
		case <-ctx.Done():
			logger.Info(fmt.Sprintf("[safety] Timeout before starting pattern: %s", pattern.String()))
			continue
		}

		wg.Add(1)
		go func(re *regexp.Regexp) {
			defer wg.Done()
			defer func() { <-guard }()

			matchCh := make(chan bool, 1)
			innerCtx, innerCancel := context.WithTimeout(ctx, perRegexTimeout)
			defer innerCancel()

			go func() {
				select {
				case matchCh <- re.MatchString(prompt):
				case <-innerCtx.Done():
				}
			}()

			select {
			case match := <-matchCh:
				if match {
					mu.Lock()
					flags = append(flags, re.String())
					mu.Unlock()
				}
			case <-innerCtx.Done():
				logger.Info(fmt.Sprintf("[safety] Regex timed out: %s", re.String()))
			}
		}(pattern)
	}

	wg.Wait()

	blocked := len(flags) > len(patterns)/2
	if blocked {
		return &SafetyCheckResult{
			Status:  StatusBlocked,
			Score:   float64(len(flags)) / float64(len(patterns)),
			Flags:   flags,
			Blocked: true,
			Reason:  "output contains too many dangerous patterns",
		}, ErrOutputBlocked
	}
	return &SafetyCheckResult{
		Status:  StatusSafe,
		Score:   0,
		Flags:   flags,
		Blocked: false,
	}, nil
}

// ScanSafetyGuard provides comprehensive safety for an entire scan
type ScanSafetyGuard struct {
	mu             sync.RWMutex
	cfg            SafetyConfig
	scanTokens     *TokenBudget
	stageTokens    *TokenBudget
	requestTracker *RequestLimiter
	retryTracker   *RetryTracker
	startTime      time.Time
	requestCount   int64
}

// NewScanSafetyGuard creates a new safety guard for a scan
func NewScanSafetyGuard(cfg SafetyConfig) *ScanSafetyGuard {
	return &ScanSafetyGuard{
		cfg:            cfg,
		scanTokens:     NewTokenBudget(int64(cfg.MaxScanTokens)),
		stageTokens:    NewTokenBudget(int64(cfg.MaxPromptTokens)),
		requestTracker: NewRequestLimiter(cfg.MaxScanRequests, cfg.TotalTimeout),
		retryTracker:   NewRetryTracker(cfg.MaxRetriesPerRequest),
		startTime:      time.Now(),
	}
}

// CanMakeRequest checks if a request is allowed within all safety constraints
func (g *ScanSafetyGuard) CanMakeRequest() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if time.Since(g.startTime) > g.cfg.TotalTimeout {
		return fmt.Errorf("%w: total timeout exceeded", ErrBudgetExceeded)
	}
	if g.scanTokens.Remaining() <= 0 {
		return fmt.Errorf("%w: scan token budget exhausted", ErrBudgetExceeded)
	}
	if !g.retryTracker.CanRetry() {
		return fmt.Errorf("%w: retry limit exceeded", ErrRetryExceeded)
	}
	if !g.requestTracker.Allow() {
		return fmt.Errorf("%w: request rate limit exceeded", ErrBudgetExceeded)
	}
	return nil
}

// RecordRequest records a completed request and consumes tokens
func (g *ScanSafetyGuard) RecordRequest(tokensUsed int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.scanTokens.Consume(tokensUsed)
	atomic.AddInt64(&g.requestCount, 1)
}

// RecordRetry records a retry attempt
func (g *ScanSafetyGuard) RecordRetry() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.retryTracker.RecordAttempt()
}

// ResetStageBudget resets the per-stage token budget
func (g *ScanSafetyGuard) ResetStageBudget() {
	g.stageTokens.Reset()
}

// RetryTracker returns the retry tracker for external use
func (g *ScanSafetyGuard) RetryTracker() *RetryTracker {
	return g.retryTracker
}

// GetConfig returns the current safety configuration
func (g *ScanSafetyGuard) GetConfig() SafetyConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cfg
}

// Stats returns the current safety statistics
func (g *ScanSafetyGuard) Stats() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return map[string]interface{}{
		"scan_tokens_used":      g.scanTokens.Used(),
		"scan_tokens_remaining": g.scanTokens.Remaining(),
		"request_count":         g.requestCount,
		"max_retries":           g.cfg.MaxRetriesPerRequest,
		"timed_out":             time.Since(g.startTime) > g.cfg.TotalTimeout,
		"uptime":                time.Since(g.startTime).String(),
	}
}
