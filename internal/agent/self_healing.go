package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ares/engine/internal/uuid"
)

type SelfHealingConfig struct {
	MaxRetries      int
	RecoveryTimeout time.Duration
	StuckThreshold  int
	RollbackOnPanic bool
	CheckpointEvery int
	CheckpointBase  string
}

type RecoverStrategy int

const (
	RecoverRetry RecoverStrategy = iota
	RecoverRestartPhase
	RecoverReinitialize
	RecoverCheckpoint
	RecoverFallback
)

type Checkpoint struct {
	ID        string
	Timestamp time.Time
	Phase     Phase
	Iteration int
	Targets   []string
	Findings  []FindingData
}

type Msg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type SelfHealingLoop struct {
	cfg              SelfHealingConfig
	executor         *Tier4Executor
	checkpts         map[string]*Checkpoint
	history          []Checkpoint
	mu               sync.RWMutex
	retries          map[string]int
	archivedFindings []FindingData
}

func NewSelfHealingLoop(executor *Tier4Executor, cfg SelfHealingConfig) *SelfHealingLoop {
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RecoveryTimeout == 0 {
		cfg.RecoveryTimeout = 30 * time.Second
	}
	if cfg.StuckThreshold == 0 {
		cfg.StuckThreshold = 20
	}
	if cfg.CheckpointEvery == 0 {
		cfg.CheckpointEvery = 5
	}

	return &SelfHealingLoop{
		cfg:      cfg,
		executor: executor,
		checkpts: make(map[string]*Checkpoint),
		retries:  make(map[string]int),
	}
}

func (l *SelfHealingLoop) Run(ctx context.Context, prompt string) error {
	scanID := uuid.New()
	l.mu.Lock()
	l.retries[scanID] = 0
	l.mu.Unlock()

	for attempt := 0; attempt <= l.cfg.MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if l.isStuck(scanID) {
			if err := l.recover(ctx, scanID); err != nil {
				return fmt.Errorf("recovery failed after %d attempts: %w", attempt+1, err)
			}
		}

		if attempt > 0 && l.cfg.CheckpointEvery > 0 && attempt%l.cfg.CheckpointEvery == 0 {
			l.saveCheckpoint(scanID)
		}

		if err := l.executor.Run(ctx, prompt); err != nil {
			if l.cfg.RollbackOnPanic {
				l.doRollback(scanID)
			}
			l.cleanupCheckpoint(scanID)
			return fmt.Errorf("executor failed after attempt %d/%d: %w", attempt+1, l.cfg.MaxRetries+1, err)
		}

		if l.isComplete(scanID) {
			l.cleanupCheckpoint(scanID)
			return nil
		}
	}

	l.cleanupCheckpoint(scanID)
	return fmt.Errorf("exceeded max retries (%d) without completion", l.cfg.MaxRetries+1)
}

func (l *SelfHealingLoop) isStuck(scanID string) bool {
	state := l.executor.GetState()
	if state == nil {
		return false
	}

	if state.Iteration >= l.cfg.StuckThreshold {
		return true
	}

	l.mu.RLock()
	defer l.mu.RUnlock()
	if retryCount, ok := l.retries[scanID]; ok && retryCount >= l.cfg.MaxRetries {
		return true
	}

	return false
}

func (l *SelfHealingLoop) recover(ctx context.Context, scanID string) error {
	l.mu.Lock()
	currentPhase := PhaseRecon
	if l.executor.GetState() != nil {
		currentPhase = l.executor.GetState().Phase
	}
	l.mu.Unlock()

	strategy := l.selectRecoveryStrategy(scanID)

	switch strategy {
	case RecoverRetry:
		return l.retryCurrentState(ctx, scanID)
	case RecoverRestartPhase:
		return l.restartPhase(ctx, scanID, currentPhase)
	case RecoverReinitialize:
		return l.reinitializeAgent(ctx, scanID)
	case RecoverCheckpoint:
		return l.restoreCheckpoint(ctx, scanID)
	default:
		return l.fallbackRecovery(ctx, scanID)
	}
}

func (l *SelfHealingLoop) selectRecoveryStrategy(scanID string) RecoverStrategy {
	l.mu.RLock()
	defer l.mu.RUnlock()

	retryCount := l.retries[scanID]

	if retryCount < 2 {
		return RecoverRetry
	}

	if checkpoint, exists := l.checkpts[scanID]; exists && checkpoint != nil {
		return RecoverCheckpoint
	}

	if retryCount < 4 {
		return RecoverRestartPhase
	}

	if retryCount < 6 {
		return RecoverReinitialize
	}

	return RecoverFallback
}

func (l *SelfHealingLoop) retryCurrentState(ctx context.Context, scanID string) error {
	l.mu.RLock()
	executor := l.executor
	l.mu.RUnlock()

	if executor == nil {
		return fmt.Errorf("executor is nil, cannot retry state for scan %s", scanID)
	}

	l.mu.RLock()
	cnt := 0
	if c, ok := l.retries[scanID]; ok {
		cnt = c
	}
	l.mu.RUnlock()

	delay := time.Duration(1<<min(cnt, 6)) * time.Second
	time.Sleep(delay)

	return nil
}

func (l *SelfHealingLoop) restartPhase(ctx context.Context, scanID string, phase Phase) error {
	l.mu.Lock()
	if l.executor.GetState() != nil {
		l.executor.SetPhase(phase)
	}
	if state := l.executor.GetState(); state != nil {
		state.Iteration = 0
	}
	l.mu.Unlock()

	time.Sleep(time.Second)
	return nil
}

func (l *SelfHealingLoop) reinitializeAgent(ctx context.Context, scanID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	state := l.executor.GetState()
	if state != nil {
		state.Iteration = 0
		state.Findings = nil
		state.PrevCmd = ""
		state.CommandSeq = 0
	}

	for k := range l.retries {
		l.retries[k] = 0
	}

	return nil
}

func (l *SelfHealingLoop) saveCheckpoint(scanID string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	state := l.executor.GetState()
	if state == nil {
		return
	}

	cp := &Checkpoint{
		ID:        scanID,
		Timestamp: time.Now(),
		Phase:     state.Phase,
		Iteration: state.Iteration,
		Targets:   state.Targets,
		Findings:  state.Findings,
	}

	l.checkpts[scanID] = cp
	l.history = append(l.history, *cp)

	if len(l.history) > 10 {
		l.history = l.history[1:]
	}
}

func (l *SelfHealingLoop) restoreCheckpoint(ctx context.Context, scanID string) error {
	l.mu.RLock()
	cp, exists := l.checkpts[scanID]
	l.mu.RUnlock()

	if !exists || cp == nil {
		return fmt.Errorf("no checkpoint found for %s", scanID)
	}

	l.mu.Lock()
	if l.executor.GetState() != nil {
		l.executor.SetPhase(cp.Phase)
		l.executor.state.Iteration = 0
		l.executor.state.Findings = cp.Findings
	}
	l.mu.Unlock()

	l.mu.Lock()
	l.retries[scanID] = 0
	l.mu.Unlock()

	return nil
}

func (l *SelfHealingLoop) doRollback(scanID string) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if state := l.executor.GetState(); state != nil {
		state.Iteration = 0
		state.Findings = nil
	}
}

func (l *SelfHealingLoop) fallbackRecovery(ctx context.Context, scanID string) error {
	l.mu.Lock()
	state := l.executor.GetState()
	if state == nil {
		l.mu.Unlock()
		return fmt.Errorf("no state available")
	}

	// Archive findings, never delete them
	if len(state.Findings) > 0 {
		l.archivedFindings = append(l.archivedFindings, state.Findings...)
	}

	state.Iteration = 0
	state.Phase = PhaseRecon
	state.PrevCmd = ""
	state.CommandSeq = 0
	state.Targets = nil
	l.mu.Unlock()

	return nil
}

func (l *SelfHealingLoop) cleanupCheckpoint(scanID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.checkpts, scanID)
}

func (l *SelfHealingLoop) isComplete(scanID string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	state := l.executor.GetState()
	if state == nil {
		return false
	}

	return state.Phase == PhaseReport || state.Iteration >= l.cfg.StuckThreshold
}

func (l *SelfHealingLoop) GetRecoveryStats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var totalRetries int
	for _, r := range l.retries {
		totalRetries += r
	}

	strategyName := "unknown"
	switch l.selectRecoveryStrategy("current") {
	case RecoverRetry:
		strategyName = "retry"
	case RecoverRestartPhase:
		strategyName = "restart_phase"
	case RecoverReinitialize:
		strategyName = "reinitialize"
	case RecoverCheckpoint:
		strategyName = "restore_checkpoint"
	default:
		strategyName = "fallback"
	}

	return map[string]interface{}{
		"total_scans":      len(l.retries),
		"total_retries":    totalRetries,
		"checkpoints":      len(l.checkpts),
		"history_depth":    len(l.history),
		"current_strategy": strategyName,
	}
}

type AgentHealth struct {
	ID           string    `json:"id"`
	Iteration    int       `json:"iteration"`
	Phase        Phase     `json:"phase"`
	LastActivity time.Time `json:"last_activity"`
	Retries      int       `json:"retries"`
	Healthy      bool      `json:"healthy"`
	Issues       []string  `json:"issues"`
}

func (l *SelfHealingLoop) HealthCheck() *AgentHealth {
	l.mu.RLock()
	defer l.mu.RUnlock()

	state := l.executor.GetState()
	health := &AgentHealth{
		ID:           "agent_1",
		LastActivity: time.Now(),
		Issues:       []string{},
		Healthy:      true,
	}

	if state != nil {
		health.Iteration = state.Iteration
		health.Phase = state.Phase
		health.Retries = l.retries["scan_current"]
	}

	if health.Iteration >= l.cfg.StuckThreshold {
		health.Healthy = false
		health.Issues = append(health.Issues, "stuck")
	}

	if health.Retries > l.cfg.MaxRetries {
		health.Healthy = false
		health.Issues = append(health.Issues, "max_retries_exceeded")
	}

	return health
}
