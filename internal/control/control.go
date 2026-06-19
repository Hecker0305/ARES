package control

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/safety"
	"github.com/ares/engine/internal/security"
)

// =============================================================================
// ARES ENGINE - UNIFIED CONTROL PACKAGE
// =============================================================================

var (
	ErrDenied           = errors.New("action denied by policy")
	ErrRateLimited      = errors.New("rate limit exceeded")
	ErrBudgetExceeded   = errors.New("resource budget exceeded")
	ErrSafetyBlocked    = errors.New("safety policy violation")
	ErrKillSwitch       = errors.New("emergency stop active")
	ErrApprovalRequired = errors.New("human approval required")
	ErrChainBroken      = errors.New("integrity chain broken")
)

// RiskLevel represents severity
type RiskLevel int

const (
	RiskNone RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskLevel) String() string {
	switch r {
	case RiskNone:
		return "none"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// RateMetrics tracks usage
type RateMetrics struct {
	Allowed uint64
	Denied  uint64
	Current float64
}

// RateLimiter is a token-bucket rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	refill   float64
	last     time.Time
	metrics  RateMetrics
}

// NewRateLimiter creates a rate limiter
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	if rate <= 0 {
		rate = 1
	}
	if burst <= 0 {
		burst = 10
	}
	return &RateLimiter{
		tokens:   float64(burst),
		capacity: float64(burst),
		refill:   rate,
		last:     time.Now(),
	}
}

// Allow returns true if permitted
func (l *RateLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillTokens()
	if l.tokens >= 1.0 {
		l.tokens--
		l.metrics.Allowed++
		l.metrics.Current = l.tokens
		return true
	}
	l.metrics.Denied++
	return false
}

// Budget returns remaining capacity
func (l *RateLimiter) Budget() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillTokens()
	return l.tokens
}

// Metrics returns usage stats
func (l *RateLimiter) Metrics() RateMetrics {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillTokens()
	return l.metrics
}

func (l *RateLimiter) refillTokens() {
	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	l.tokens += elapsed * l.refill
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	l.last = now
}

// TokenBudget tracks usage against a maximum
type TokenBudget struct {
	mu   sync.RWMutex
	max  int64
	used int64
}

// NewTokenBudget creates a new token budget
func NewTokenBudget(max int64) *TokenBudget {
	return &TokenBudget{max: max}
}

// Consume attempts to consume tokens
func (b *TokenBudget) Consume(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.max {
		return false
	}
	b.used += n
	return true
}

// Remaining returns available tokens
func (b *TokenBudget) Remaining() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.max - b.used
}

// Used returns consumed tokens
func (b *TokenBudget) Used() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.used
}

// Status returns usage percentage (0-100)
func (b *TokenBudget) Status() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.max == 0 {
		return 0
	}
	return int((b.used * 100) / b.max)
}

// BudgetStatus is a budget snapshot
type BudgetStatus struct {
	Name   string `json:"name"`
	Used   int64  `json:"used"`
	Max    int64  `json:"max"`
	Status int    `json:"status"`
}

// UsageSummary is all budget usage
type UsageSummary struct {
	Budgets map[string]BudgetStatus `json:"budgets"`
	Rates   map[string]RateMetrics  `json:"rates"`
}

// Governor manages all budgets
type Governor struct {
	mu      sync.RWMutex
	budgets map[string]*TokenBudget
	rates   map[string]*RateLimiter
}

// GovernorConfig configures the governor
type GovernorConfig struct {
	MaxTokens     int64
	MaxMemoryMB   int64
	MaxGoroutines int32
	MaxExecutions int64
	MaxDepth      int
	MaxAgents     int
}

// NewGovernor creates a new governor
func NewGovernor(cfg GovernorConfig) *Governor {
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 100
	}
	if cfg.MaxAgents == 0 {
		cfg.MaxAgents = 10
	}
	if cfg.MaxExecutions == 0 {
		cfg.MaxExecutions = 1000
	}
	g := &Governor{
		budgets: make(map[string]*TokenBudget),
		rates:   make(map[string]*RateLimiter),
	}
	g.budgets["tokens"] = NewTokenBudget(cfg.MaxTokens)
	g.budgets["exec"] = NewTokenBudget(cfg.MaxExecutions)
	g.budgets["memory"] = NewTokenBudget(cfg.MaxMemoryMB)
	return g
}

// CanExecute checks resource constraints
func (g *Governor) CanExecute(tokens int64) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if tokens > 0 {
		if budget, exists := g.budgets["tokens"]; !exists || !budget.Consume(tokens) {
			return false, ErrBudgetExceeded
		}
	}
	return true, nil
}

// RateLimiter gets or creates a named rate limiter
func (g *Governor) RateLimiter(name string, rate float64, burst int) *RateLimiter {
	g.mu.Lock()
	defer g.mu.Unlock()
	if l, exists := g.rates[name]; exists {
		return l
	}
	l := NewRateLimiter(rate, burst)
	g.rates[name] = l
	return l
}

// Budget returns a named budget
func (g *Governor) Budget(name string) *TokenBudget {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.budgets[name]
}

// Usage returns current usage
func (g *Governor) Usage() UsageSummary {
	g.mu.RLock()
	defer g.mu.RUnlock()
	budgets := make(map[string]BudgetStatus)
	for name, b := range g.budgets {
		budgets[name] = BudgetStatus{Name: name, Used: b.Used(), Max: b.max, Status: b.Status()}
	}
	rates := make(map[string]RateMetrics)
	for name, r := range g.rates {
		rates[name] = r.Metrics()
	}
	return UsageSummary{Budgets: budgets, Rates: rates}
}

// EnforcementPoint identifies where a check originates
type EnforcementPoint int

const (
	EnforcementToolCall EnforcementPoint = iota
	EnforcementGateway
	EnforcementTerminal
	EnforcementBrowser
	EnforcementAPIRequest
)

func (e EnforcementPoint) String() string {
	switch e {
	case EnforcementToolCall:
		return "tool_call"
	case EnforcementGateway:
		return "gateway"
	case EnforcementTerminal:
		return "terminal"
	case EnforcementBrowser:
		return "browser"
	case EnforcementAPIRequest:
		return "api_request"
	default:
		return "unknown"
	}
}

// UnifiedRequest describes any policy evaluation request
type UnifiedRequest struct {
	ID          string
	Source      EnforcementPoint
	Action      string
	Target      string
	Actor       string
	RiskLevel   RiskLevel
	IsNetworkOp bool
	IsExploit   bool
	TokenCost   int64
	Params      map[string]interface{}
	TraceID     string
	Command     string
	Binary      string
	Args        []string
	URL         string
	Path        string
	Script      string
	Write       bool
	ToolParams  map[string]string
}

// UnifiedResponse is the unified policy response
type UnifiedResponse struct {
	Allowed    bool
	DecisionID string
	Reason     string
	RiskLevel  RiskLevel
	TraceID    string
	Duration   time.Duration
	NextAction string
}

func (r UnifiedResponse) Error() string { return r.Reason }

// PolicyEngine is the unified policy decision engine
type PolicyEngine struct {
	mu               sync.RWMutex
	safety           *safety.PolicyEngine
	governor         *Governor
	tokenBudget      *TokenBudget
	rateLimiters     map[string]*RateLimiter
	rateLimiterOrder []string
	kernel           security.Kernel
	auditLog         []UnifiedRequest
	decisionCounter  int64
}

// NewPolicyEngine creates the unified policy engine
func NewPolicyEngine(cfg GovernorConfig) *PolicyEngine {
	return &PolicyEngine{
		safety:           safety.NewPolicyEngine(),
		governor:         NewGovernor(cfg),
		tokenBudget:      NewTokenBudget(cfg.MaxTokens),
		rateLimiters:     make(map[string]*RateLimiter),
		rateLimiterOrder: make([]string, 0, 10000),
		kernel:           security.GetK(),
		auditLog:         make([]UnifiedRequest, 0, 10000),
	}
}

// Evaluate performs a comprehensive policy evaluation
func (e *PolicyEngine) Evaluate(req UnifiedRequest) UnifiedResponse {
	start := time.Now()

	// 1. Kill switch check
	if e.safety.IsKillSwitchActive() {
		return e.respond(req, false, "kill_switch_active", ErrKillSwitch, RiskCritical, start)
	}

	// 2. Safety mode check
	if allowed, err := e.safety.CheckAction(req.Action); !allowed {
		return e.respond(req, false, err.Error(), ErrSafetyBlocked, RiskCritical, start)
	}

	// 3. Kernel validation
	if allowed, reason := e.checkKernel(req); !allowed {
		return e.respond(req, false, reason, ErrDenied, RiskHigh, start)
	}

	// 4. Classify risk
	risk := e.classifyAction(req)
	req.RiskLevel = risk

	// 5. Approval requirement
	if e.requiresApproval(risk, req) {
		return e.respond(req, false, "requires_approval", ErrApprovalRequired, risk, start)
	}

	// 6. Rate limiting
	if !e.checkRateLimit(req) {
		return e.respond(req, false, "rate_limit_exceeded", ErrRateLimited, RiskLow, start)
	}

	// 7. Resource budget
	if !e.checkBudget(req) {
		return e.respond(req, false, "budget_exceeded", ErrBudgetExceeded, RiskMedium, start)
	}

	// All checks passed
	return e.respond(req, true, "all_checks_passed", nil, risk, start)
}

func (e *PolicyEngine) checkKernel(req UnifiedRequest) (bool, string) {
	if e.kernel == nil {
		return false, "kernel not initialized"
	}

	actionType := security.ActionToolCall
	switch req.Source {
	case EnforcementTerminal:
		actionType = security.ActionShellExec
	case EnforcementBrowser:
		actionType = security.ActionBrowserNavigate
	case EnforcementAPIRequest:
		actionType = security.ActionHTTPRequest
	}

	actionReq := security.ActionRequest{
		Type:     actionType,
		ToolName: req.Action,
		Source:   req.Source.String(),
		Command:  req.Command,
		Binary:   req.Binary,
		Args:     req.Args,
		URL:      req.URL,
		Path:     req.Path,
		Script:   req.Script,
		Write:    req.Write,
	}
	if len(req.Args) > 0 {
		actionReq.Args = make([]string, len(req.Args))
		copy(actionReq.Args, req.Args)
	}
	if req.ToolParams != nil {
		actionReq.ToolParams = make(map[string]string, len(req.ToolParams))
		for k, v := range req.ToolParams {
			actionReq.ToolParams[k] = v
		}
	}

	verdict := e.kernel.ValidateAction(context.Background(), actionReq)
	return verdict.Decision == security.DecisionAllow, verdict.Reason
}

func (e *PolicyEngine) classifyAction(req UnifiedRequest) RiskLevel {
	risk := req.RiskLevel
	if req.IsNetworkOp && risk < RiskMedium {
		risk = RiskMedium
	}
	if req.IsExploit && risk < RiskHigh {
		risk = RiskHigh
	}
	return risk
}

func (e *PolicyEngine) requiresApproval(risk RiskLevel, req UnifiedRequest) bool {
	if risk >= RiskCritical {
		return true
	}
	if risk >= RiskHigh && req.IsNetworkOp {
		return true
	}
	if req.TokenCost > 50000 {
		return true
	}
	return false
}

func (e *PolicyEngine) checkRateLimit(req UnifiedRequest) bool {
	e.mu.Lock()
	key := req.Actor
	if key == "" {
		key = "default"
	}
	limiter, exists := e.rateLimiters[key]
	if !exists {
		if len(e.rateLimiters) >= 10000 {
			oldest := e.rateLimiterOrder[0]
			delete(e.rateLimiters, oldest)
			e.rateLimiterOrder = e.rateLimiterOrder[1:]
		}
		limiter = NewRateLimiter(10, 20)
		e.rateLimiters[key] = limiter
		e.rateLimiterOrder = append(e.rateLimiterOrder, key)
	}
	e.mu.Unlock()
	return limiter.Allow()
}

func (e *PolicyEngine) checkBudget(req UnifiedRequest) bool {
	if req.TokenCost > 0 {
		return e.tokenBudget.Consume(req.TokenCost)
	}
	return true
}

func (e *PolicyEngine) respond(req UnifiedRequest, allowed bool, reason string, err error, risk RiskLevel, start time.Time) UnifiedResponse {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.decisionCounter++
	nextAction := ""
	if !allowed && err != nil {
		nextAction = determineNextAction(risk, err.Error())
	}

	resp := UnifiedResponse{
		Allowed:    allowed,
		DecisionID: fmt.Sprintf("dec-%012d", e.decisionCounter),
		Reason:     reason,
		RiskLevel:  risk,
		TraceID:    req.TraceID,
		Duration:   time.Since(start),
		NextAction: nextAction,
	}

	e.auditLog = append(e.auditLog, req)
	if len(e.auditLog) > 10000 {
		e.auditLog = e.auditLog[1:]
	}

	logger.Info("policy decision", logger.Fields{
		"decision_id": resp.DecisionID,
		"action":      req.Action,
		"allowed":     allowed,
		"reason":      reason,
		"risk":        risk.String(),
		"duration":    resp.Duration.String(),
	})

	return resp
}

func determineNextAction(risk RiskLevel, reason string) string {
	switch risk {
	case RiskCritical:
		return "escalate_to_admin"
	case RiskHigh:
		if reason == "requires_approval" {
			return "request_approval"
		}
		return "review_and_retry"
	case RiskMedium:
		return "retry_with_limits"
	default:
		return "retry"
	}
}

// GetDecisionLog returns recent decisions
func (e *PolicyEngine) GetDecisionLog(limit int) []UnifiedRequest {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.auditLog) {
		limit = len(e.auditLog)
	}
	result := make([]UnifiedRequest, limit)
	copy(result, e.auditLog[len(e.auditLog)-limit:])
	return result
}

// GetStats returns stats
func (e *PolicyEngine) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"decisions":   e.decisionCounter,
		"audit_size":  len(e.auditLog),
		"safety_mode": e.safety.Mode(),
		"kill_switch": e.safety.IsKillSwitchActive(),
	}
}

// SetMode changes safety mode
func (e *PolicyEngine) SetMode(mode safety.OperationMode, actor string) error {
	return e.safety.SetMode(mode, actor)
}

// ActivateKillSwitch activates emergency stop and returns deactivation token
func (e *PolicyEngine) ActivateKillSwitch(actor, reason string) string {
	return e.safety.ActivateKillSwitch(actor, reason)
}

// DeactivateKillSwitch deactivates emergency stop with authorization token
func (e *PolicyEngine) DeactivateKillSwitch(actor, token string) error {
	return e.safety.DeactivateKillSwitch(actor, token)
}
