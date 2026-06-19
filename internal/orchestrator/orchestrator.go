package orchestrator

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ares/engine/internal/chainer"
	"github.com/ares/engine/internal/uuid"
	"github.com/ares/engine/internal/explain"
	"github.com/ares/engine/internal/gateway"
	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/guardrails"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/planner"
	"github.com/ares/engine/internal/policy"
	"github.com/ares/engine/internal/sandbox"
	"github.com/ares/engine/internal/verifier"
)

// --- Event System ---

type PhaseEventType int

const (
	PhaseStarted PhaseEventType = iota
	PhaseCompleted
	PhaseFailed
	PhaseSkipped
	PhaseDegraded
)

func (t PhaseEventType) String() string {
	switch t {
	case PhaseStarted:
		return "started"
	case PhaseCompleted:
		return "completed"
	case PhaseFailed:
		return "failed"
	case PhaseSkipped:
		return "skipped"
	case PhaseDegraded:
		return "degraded"
	default:
		return "unknown"
	}
}

type PhaseEvent struct {
	Phase     string
	Type      PhaseEventType
	Timestamp time.Time
	Duration  time.Duration
	Error     string
	Metadata  map[string]interface{}
}

// --- Tool Output Summary ---

type ToolOutputSummary struct {
	Tool    string `json:"tool"`
	Count   int    `json:"count"`
	Summary string `json:"summary,omitempty"`
}

// --- Circuit Breaker ---

type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota
	CircuitOpen
	CircuitHalfOpen
)

func (s CircuitBreakerState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

type CircuitBreakerConfig struct {
	Threshold   int           `json:"threshold"`
	Cooldown    time.Duration `json:"cooldown"`
	HalfOpenMax int           `json:"half_open_max"`
}

type PhaseCircuitBreaker struct {
	mu            sync.Mutex
	config        CircuitBreakerConfig
	failures      int
	lastFailure   time.Time
	state         CircuitBreakerState
	halfOpenCount int
}

func NewPhaseCircuitBreaker(config CircuitBreakerConfig) *PhaseCircuitBreaker {
	if config.Threshold <= 0 {
		config.Threshold = 3
	}
	if config.Cooldown <= 0 {
		config.Cooldown = 30 * time.Second
	}
	if config.HalfOpenMax <= 0 {
		config.HalfOpenMax = 1
	}
	return &PhaseCircuitBreaker{config: config, state: CircuitClosed}
}

func (cb *PhaseCircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailure) > cb.config.Cooldown {
			cb.state = CircuitHalfOpen
			cb.halfOpenCount = 0
			return true
		}
		return false
	case CircuitHalfOpen:
		if cb.halfOpenCount < cb.config.HalfOpenMax {
			cb.halfOpenCount++
			return true
		}
		return false
	default:
		return true
	}
}

func (cb *PhaseCircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.halfOpenCount = 0
	cb.state = CircuitClosed
}

func (cb *PhaseCircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.config.Threshold {
		cb.state = CircuitOpen
	}
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitOpen
	}
}

func (cb *PhaseCircuitBreaker) State() CircuitBreakerState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *PhaseCircuitBreaker) Failures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures
}

func (cb *PhaseCircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.halfOpenCount = 0
	cb.state = CircuitClosed
}

// --- Phase Configuration ---

type PhaseConfig struct {
	Name           string        `json:"name"`
	Timeout        time.Duration `json:"timeout"`
	RetryCount     int           `json:"retry_count"`
	RetryBaseDelay time.Duration `json:"retry_base_delay"`
	Dependencies   []string      `json:"dependencies,omitempty"`
}

func DefaultPhaseConfig(name string) PhaseConfig {
	return PhaseConfig{
		Name:           name,
		Timeout:        30 * time.Minute,
		RetryCount:     0,
		RetryBaseDelay: time.Second,
		Dependencies:   nil,
	}
}

// --- Enhanced PhaseResult (backward-compatible) ---

type PhaseResult struct {
	Phase         string              `json:"phase"`
	Success       bool                `json:"success"`
	Duration      time.Duration       `json:"duration"`
	Error         string              `json:"error,omitempty"`
	FindingsCount int                 `json:"findings_count,omitempty"`
	ToolOutputs   []ToolOutputSummary `json:"tool_outputs,omitempty"`
	Attempts      int                 `json:"attempts,omitempty"`
	Skipped       bool                `json:"skipped,omitempty"`
	Degraded      bool                `json:"degraded,omitempty"`
}

// --- Pipeline (unchanged) ---

type Pipeline struct {
	Planner    *planner.Planner
	Policy     *policy.PolicyEngine
	Gateway    *gateway.Gateway
	Verifier   *verifier.Engine
	Guardrails *guardrails.Engine
	Chainer    *chainer.Chainer
	Explainer  *explain.Generator
	Graph      *graph.AttackGraph
	LLM        *llm.Client
	Sandbox    *sandbox.Manager
}

// --- Orchestrator ---

type phaseDef struct {
	name string
	run  func(context.Context) error
}

type Orchestrator struct {
	mu          sync.RWMutex
	pipeline    Pipeline
	results     []PhaseResult
	active      bool
	target      string
	startTime   time.Time
	phaseCfgs   map[string]PhaseConfig
	circuitDefs map[string]*PhaseCircuitBreaker
	eventCh     chan PhaseEvent
	eventInit   sync.Once
	totalPhases int32
	donePhases  int32
	maxParallel int
}

func New(p Pipeline) *Orchestrator {
	o := &Orchestrator{
		pipeline:    p,
		results:     make([]PhaseResult, 0),
		phaseCfgs:   make(map[string]PhaseConfig),
		circuitDefs: make(map[string]*PhaseCircuitBreaker),
		eventCh:     make(chan PhaseEvent, 256),
		maxParallel: 4,
	}
	return o
}

func (o *Orchestrator) SetMaxParallel(n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if n > 0 && n <= 16 {
		o.maxParallel = n
	} else if n > 16 {
		o.maxParallel = 16
	}
}

func (o *Orchestrator) SetPhaseConfig(name string, cfg PhaseConfig) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if cfg.RetryBaseDelay == 0 {
		cfg.RetryBaseDelay = time.Second
	}
	o.phaseCfgs[name] = cfg
}

func (o *Orchestrator) SetCircuitBreaker(name string, config CircuitBreakerConfig) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.circuitDefs[name] = NewPhaseCircuitBreaker(config)
}

func (o *Orchestrator) emitEvent(phase string, typ PhaseEventType, duration time.Duration, err string, metadata map[string]interface{}) {
	o.eventInit.Do(func() {
		o.eventCh = make(chan PhaseEvent, 256)
	})
	evt := PhaseEvent{
		Phase:     phase,
		Type:      typ,
		Timestamp: time.Now(),
		Duration:  duration,
		Error:     err,
		Metadata:  metadata,
	}
	select {
	case o.eventCh <- evt:
	default:
	}
}

func (o *Orchestrator) getPhaseConfig(name string) PhaseConfig {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cfg, ok := o.phaseCfgs[name]; ok {
		return cfg
	}
	return DefaultPhaseConfig(name)
}

func (o *Orchestrator) getCircuitBreaker(name string) *PhaseCircuitBreaker {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cb, ok := o.circuitDefs[name]; ok {
		return cb
	}
	return nil
}

func (o *Orchestrator) recordResult(r PhaseResult) {
	o.mu.Lock()
	o.results = append(o.results, r)
	o.mu.Unlock()
	atomic.AddInt32(&o.donePhases, 1)
}

func (o *Orchestrator) executePhase(ctx context.Context, name string, fn func(context.Context) error) {
	cfg := o.getPhaseConfig(name)
	cb := o.getCircuitBreaker(name)

	if cb != nil && !cb.Allow() {
		r := PhaseResult{
			Phase:    name,
			Success:  false,
			Error:    "circuit breaker open",
			Skipped:  true,
			Degraded: true,
		}
		o.recordResult(r)
		o.emitEvent(name, PhaseSkipped, 0, "circuit breaker open", map[string]interface{}{"degraded": true})
		return
	}

	o.emitEvent(name, PhaseStarted, 0, "", nil)

	var lastErr error
	start := time.Now()
	attempts := 0
	maxRetries := cfg.RetryCount

	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			duration := time.Since(start)
			lastErr = ctx.Err()
			r := PhaseResult{
				Phase:    name,
				Success:  false,
				Duration: duration,
				Error:    lastErr.Error(),
				Attempts: attempts,
			}
			o.recordResult(r)
			o.emitEvent(name, PhaseFailed, duration, lastErr.Error(), map[string]interface{}{"attempts": attempts})
			return
		default:
		}

		phaseCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		err := fn(phaseCtx)
		cancel()
		attempts++

		if err == nil {
			duration := time.Since(start)
			if cb != nil {
				cb.RecordSuccess()
			}
			r := PhaseResult{
				Phase:         name,
				Success:       true,
				Duration:      duration,
				Attempts:      attempts,
				FindingsCount: o.countFindingsForPhase(name),
				ToolOutputs:   o.collectToolOutputs(name),
			}
			o.recordResult(r)
			o.emitEvent(name, PhaseCompleted, duration, "", map[string]interface{}{
				"attempts":       attempts,
				"findings_count": r.FindingsCount,
			})
			return
		}

		lastErr = err
		if attempt < maxRetries {
			delay := time.Duration(float64(cfg.RetryBaseDelay) * math.Pow(2, float64(attempt)))
			logger.Warn("Phase retry", logger.Fields{
				"component": "Orchestrator",
				"phase":     name,
				"attempt":   attempt + 1,
				"max":       maxRetries,
				"backoff":   delay.String(),
				"error":     err.Error(),
			})
			o.emitEvent(name, PhaseFailed, time.Since(start), err.Error(), map[string]interface{}{
				"attempt": attempt + 1,
				"retry":   true,
			})

			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				duration := time.Since(start)
				r := PhaseResult{
					Phase:    name,
					Success:  false,
					Duration: duration,
					Error:    ctx.Err().Error(),
					Attempts: attempts,
				}
				o.recordResult(r)
				o.emitEvent(name, PhaseFailed, duration, ctx.Err().Error(), map[string]interface{}{"attempts": attempts})
				return
			case <-timer.C:
			}
		}
	}

	duration := time.Since(start)
	degraded := false
	if cb != nil {
		cb.RecordFailure()
		degraded = cb.State() == CircuitOpen
	}

	r := PhaseResult{
		Phase:    name,
		Success:  false,
		Duration: duration,
		Error:    lastErr.Error(),
		Attempts: attempts,
		Degraded: degraded,
	}
	o.recordResult(r)

	meta := map[string]interface{}{"attempts": attempts, "degraded": degraded}
	o.emitEvent(name, PhaseFailed, duration, lastErr.Error(), meta)
	if degraded {
		o.emitEvent(name, PhaseDegraded, duration, lastErr.Error(), meta)
	}
}

func (o *Orchestrator) countFindingsForPhase(phase string) int {
	if o.pipeline.Graph == nil {
		return 0
	}
	nodes := o.pipeline.Graph.AllNodes()
	switch phase {
	case "recon", "discovery":
		count := 0
		for _, n := range nodes {
			if n.Type == graph.NodeService || n.Type == graph.NodeAsset {
				count++
			}
		}
		return count
	case "exploit", "verify":
		count := 0
		for _, n := range nodes {
			if n.Type == graph.NodeVuln {
				if confirmed, ok := n.Properties["confirmed"].(bool); ok && confirmed {
					count++
				}
			}
		}
		return count
	case "chain":
		count := 0
		for _, n := range nodes {
			if n.Type == graph.NodeTechnique {
				count++
			}
		}
		return count
	default:
		return 0
	}
}

func (o *Orchestrator) collectToolOutputs(phase string) []ToolOutputSummary {
	return nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Execute runs phases sequentially with retry, timeout, circuit breaker,
// and graceful degradation on failure.
func (o *Orchestrator) Execute(ctx context.Context, target string) error {
	o.mu.Lock()
	o.active = true
	o.target = target
	o.startTime = time.Now()
	o.results = make([]PhaseResult, 0)
	atomic.StoreInt32(&o.totalPhases, 6)
	atomic.StoreInt32(&o.donePhases, 0)
	o.mu.Unlock()

	defer func() {
		o.mu.Lock()
		o.active = false
		o.mu.Unlock()
	}()

	logger.Info("Starting pipeline for target", logger.Fields{"component": "Orchestrator", "target": target})

	objectives := o.pipeline.Planner.DecomposeTarget(target)
	plan := o.pipeline.Planner.GeneratePlan(target, objectives)
	logger.Info("Generated plan", logger.Fields{"component": "Orchestrator", "summary": plan.Chain.Summary})

	phases := []phaseDef{
		{name: "recon", run: func(ctx context.Context) error { return o.runRecon(ctx, target) }},
		{name: "discovery", run: func(ctx context.Context) error { return o.runDiscovery(ctx, target) }},
		{name: "exploit", run: func(ctx context.Context) error { return o.runExploit(ctx, target) }},
		{name: "verify", run: func(ctx context.Context) error { return o.runVerification(ctx, target) }},
		{name: "chain", run: func(ctx context.Context) error { return o.runChaining(ctx, target) }},
		{name: "report", run: func(ctx context.Context) error { return o.runReporting(ctx, target) }},
	}

	for _, phase := range phases {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		o.executePhase(ctx, phase.name, phase.run)
	}

	return nil
}

// ExecuteParallel runs independent phases (recon + discovery) concurrently
// using a phase dependency DAG. All exported behavior is the same as Execute.
func (o *Orchestrator) ExecuteParallel(ctx context.Context, target string) error {
	o.mu.Lock()
	o.active = true
	o.target = target
	o.startTime = time.Now()
	o.results = make([]PhaseResult, 0)
	o.mu.Unlock()

	defer func() {
		o.mu.Lock()
		o.active = false
		o.mu.Unlock()
	}()

	logger.Info("Starting parallel pipeline for target", logger.Fields{"component": "Orchestrator", "target": target})

	objectives := o.pipeline.Planner.DecomposeTarget(target)
	plan := o.pipeline.Planner.GeneratePlan(target, objectives)
	logger.Info("Generated plan", logger.Fields{"component": "Orchestrator", "summary": plan.Chain.Summary})

	phases := map[string]phaseDef{
		"recon":     {name: "recon", run: func(ctx context.Context) error { return o.runRecon(ctx, target) }},
		"discovery": {name: "discovery", run: func(ctx context.Context) error { return o.runDiscovery(ctx, target) }},
		"exploit":   {name: "exploit", run: func(ctx context.Context) error { return o.runExploit(ctx, target) }},
		"verify":    {name: "verify", run: func(ctx context.Context) error { return o.runVerification(ctx, target) }},
		"chain":     {name: "chain", run: func(ctx context.Context) error { return o.runChaining(ctx, target) }},
		"report":    {name: "report", run: func(ctx context.Context) error { return o.runReporting(ctx, target) }},
	}

	deps := map[string][]string{
		"exploit": {"recon", "discovery"},
		"verify":  {"exploit"},
		"chain":   {"verify"},
		"report":  {"chain"},
	}

	atomic.StoreInt32(&o.totalPhases, int32(len(phases)))
	atomic.StoreInt32(&o.donePhases, 0)

	completed := make(map[string]bool)
	submitted := make(map[string]bool)
	var completedMu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	doneCh := make(chan string, len(phases))

	o.mu.RLock()
	sem := make(chan struct{}, o.maxParallel)
	o.mu.RUnlock()

	submitPhase := func(name string) {
		submitted[name] = true
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o.executePhase(ctx, n, phases[n].run)
			completedMu.Lock()
			completed[n] = true
			completedMu.Unlock()
			doneCh <- n
		}(name)
	}

	for name := range phases {
		if len(deps[name]) == 0 {
			submitPhase(name)
		}
	}

	finished := 0
	total := len(phases)
	for finished < total {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doneCh:
			finished++
			for name := range phases {
				completedMu.Lock()
				alreadyDone := completed[name] || submitted[name]
				completedMu.Unlock()
				if alreadyDone {
					continue
				}
				completedMu.Lock()
				allMet := true
				for _, dep := range deps[name] {
					if !completed[dep] {
						allMet = false
						break
					}
				}
				completedMu.Unlock()
				if allMet {
					submitPhase(name)
				}
			}
		}
	}

	wg.Wait()
	return nil
}

func (o *Orchestrator) runRecon(ctx context.Context, target string) error {
	logger.Info("Gathering target intelligence", logger.Fields{"component": "Recon", "target": target})
	if err := sleepContext(ctx, 500*time.Millisecond); err != nil {
		return err
	}

	o.pipeline.Graph.AddNode(target, graph.NodeAsset, target)
	o.pipeline.Graph.SetNodeProperty(target, "type", "target")
	o.pipeline.Graph.SetNodeProperty(target, "status", "discovered")

	for _, obj := range o.pipeline.Planner.GetActiveObjectives(target) {
		o.pipeline.Graph.AddNode(obj.ID, graph.NodeTechnique, obj.Goal)
		o.pipeline.Graph.AddEdge(target, obj.ID, graph.EdgeLeadsTo)
	}

	return nil
}

func (o *Orchestrator) runDiscovery(ctx context.Context, target string) error {
	logger.Info("Discovering attack surface", logger.Fields{"component": "Discovery", "target": target})

	services := []string{"http", "https", "api", "dns"}
	for _, svc := range services {
		if err := sleepContext(ctx, 100*time.Millisecond); err != nil {
			return err
		}
		nodeID := fmt.Sprintf("svc-%s-%s", svc, target)
		o.pipeline.Graph.AddNode(nodeID, graph.NodeService, svc+" on "+target)
		o.pipeline.Graph.AddEdge(target, nodeID, graph.EdgeDiscovers)
	}

	return nil
}

func (o *Orchestrator) runExploit(ctx context.Context, target string) error {
	logger.Info("Testing exploit paths", logger.Fields{"component": "Exploit", "target": target})

	vulnTypes := []string{"sqli", "xss", "ssrf", "lfi", "idor"}
	for _, vt := range vulnTypes {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		req := gateway.CallRequest{
			Tool:   "exploit",
			Target: target,
			Params: map[string]string{
				"type":   vt,
				"target": target,
			},
			TraceID: fmt.Sprintf("trace-%s", target),
		}

		result := o.pipeline.Gateway.Call(ctx, req)
		if result.Blocked {
			logger.Warn("Blocked by policy", logger.Fields{"component": "Exploit", "vuln_type": vt, "reason": result.Reason})
			continue
		}

		vulnID := fmt.Sprintf("vuln-%s-%s", vt, target)
		o.pipeline.Graph.AddNode(vulnID, graph.NodeVuln, vt+" on "+target)
		o.pipeline.Graph.AddEdge(target, vulnID, graph.EdgeExploits)

		if !result.Success {
			continue
		}

		verReq := verifier.VerificationRequest{
			ID:       fmt.Sprintf("ver-%s-%s", vt, target),
			VulnType: vt,
			Target:   target,
			Payload:  vt + "_payload",
		}
		verResult := o.pipeline.Verifier.Verify(verReq)
		if verResult.Verdict == verifier.VerdictConfirmed {
			o.pipeline.Graph.SetNodeProperty(vulnID, "confirmed", true)
			o.pipeline.Graph.SetNodeProperty(vulnID, "confidence", verResult.Confidence)
			o.pipeline.Graph.UpdateNodeScore(vulnID, verResult.Confidence)
			logger.Info("Confirmed vulnerability", logger.Fields{"component": "Exploit", "vuln_type": vt, "confidence": verResult.Confidence})
		}
	}

	return nil
}

func (o *Orchestrator) runVerification(ctx context.Context, target string) error {
	logger.Info("Running verification pipeline", logger.Fields{"component": "Verify", "target": target})

	nodes := o.pipeline.Graph.AllNodes()
	for _, node := range nodes {
		if node.Type != graph.NodeVuln {
			continue
		}
		if props, ok := node.Properties["confirmed"].(bool); ok && props {
			logger.Debug("Node already confirmed", logger.Fields{"component": "Verify", "node": node.Label})
			continue
		}
	}

	return nil
}

func (o *Orchestrator) runChaining(ctx context.Context, target string) error {
	logger.Info("Building exploit chains", logger.Fields{"component": "Chainer", "target": target})

	var findings []string
	nodes := o.pipeline.Graph.AllNodes()
	for _, node := range nodes {
		if node.Type == graph.NodeVuln {
			if confirmed, ok := node.Properties["confirmed"].(bool); ok && confirmed {
				findings = append(findings, node.Label)
			}
		}
	}

	if len(findings) == 0 {
		logger.Info("No confirmed findings to chain", logger.Fields{"component": "Chainer"})
		return nil
	}

	chains := o.pipeline.Chainer.Analyze(findings)
	for _, chain := range chains {
		logger.Info("Found chain", logger.Fields{"component": "Chainer", "summary": chain.Summary, "score": chain.Score, "impact": chain.Impact})
		chainNodeID := uuid.New()
		o.pipeline.Graph.AddNode(chainNodeID, graph.NodeTechnique, chain.Summary)
		o.pipeline.Graph.SetNodeProperty(chainNodeID, "impact", chain.Impact)
		o.pipeline.Graph.SetNodeProperty(chainNodeID, "score", chain.Score)
	}

	return nil
}

func (o *Orchestrator) runReporting(ctx context.Context, target string) error {
	logger.Info("Generating exploit narratives", logger.Fields{"component": "Report", "target": target})

	nodes := o.pipeline.Graph.AllNodes()
	for _, node := range nodes {
		if node.Type != graph.NodeVuln {
			continue
		}
		confirmed, _ := node.Properties["confirmed"].(bool)
		confidence, _ := node.Properties["confidence"].(float64)
		if confidence == 0 {
			confidence = 0.5
		}

		narrative := o.pipeline.Explainer.GenerateNarrative(
			node.Label,
			target,
			"",
			fmt.Sprintf("Node: %s, Score: %.2f", node.ID, node.Score),
			confidence,
		)
		narrative.Reproducible = confirmed

		logger.Info("Narrative generated", logger.Fields{"component": "Report", "title": narrative.Title, "severity": narrative.Severity, "confidence": narrative.Confidence})
	}

	return nil
}

// Results returns a copy of all phase results including enriched metadata
// (findings count, tool outputs, attempts, degradation status).
func (o *Orchestrator) Results() []PhaseResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make([]PhaseResult, len(o.results))
	copy(result, o.results)
	return result
}

// Progress returns a 0.0–1.0 float64 representing pipeline completion.
func (o *Orchestrator) Progress() float64 {
	total := atomic.LoadInt32(&o.totalPhases)
	if total == 0 {
		return 0
	}
	done := atomic.LoadInt32(&o.donePhases)
	return float64(done) / float64(total)
}

// Events returns a read-only channel of PhaseEvent for subscribers.
func (o *Orchestrator) Events() <-chan PhaseEvent {
	o.eventInit.Do(func() {
		o.eventCh = make(chan PhaseEvent, 256)
	})
	return o.eventCh
}

func (o *Orchestrator) Status() map[string]interface{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	allDegraded := true
	anySuccess := false
	for _, r := range o.results {
		if r.Success {
			anySuccess = true
			allDegraded = false
		}
		if !r.Degraded {
			allDegraded = false
		}
	}
	return map[string]interface{}{
		"active":       o.active,
		"target":       o.target,
		"phases":       len(o.results),
		"uptime":       time.Since(o.startTime).String(),
		"progress":     float64(int(o.Progress()*100)) / 100,
		"partial":      anySuccess && o.active,
		"all_degraded": allDegraded && len(o.results) > 0,
	}
}

func (o *Orchestrator) BuildPipeline(
	llmClient *llm.Client,
	pe *policy.PolicyEngine,
	g *graph.AttackGraph,
	sb *sandbox.Manager,
	gr *guardrails.Engine,
	vf *verifier.Engine,
	ch *chainer.Chainer,
) Pipeline {
	gw := gateway.New(pe, gr, sb)
	pl := planner.New(llmClient, pe, g)
	ex := explain.New(g, ch, vf)

	return Pipeline{
		Planner:    pl,
		Policy:     pe,
		Gateway:    gw,
		Verifier:   vf,
		Guardrails: gr,
		Chainer:    ch,
		Explainer:  ex,
		Graph:      g,
		LLM:        llmClient,
		Sandbox:    sb,
	}
}
