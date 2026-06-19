package safety

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNoSafeFallback     = errors.New("no safe fallback path available")
	ErrShutdownInProgress = errors.New("controlled shutdown in progress")
)

// FailureMode represents how the system handles failures
type FailureMode int

const (
	ImmediateFail FailureMode = iota
	RetryOnce
	RetryWithBackoff
	CircuitBreaker
	DegradedMode
	SafeAbort
	ControlledShutdown
)

func (m FailureMode) String() string {
	switch m {
	case ImmediateFail:
		return "immediate-fail"
	case RetryOnce:
		return "retry-once"
	case RetryWithBackoff:
		return "retry-backoff"
	case CircuitBreaker:
		return "circuit-breaker"
	case DegradedMode:
		return "degraded"
	case SafeAbort:
		return "safe-abort"
	case ControlledShutdown:
		return "controlled-shutdown"
	default:
		return "unknown"
	}
}

// FailureHandler handles failures according to the configured mode
type FailureHandler struct {
	mu         sync.RWMutex
	mode       FailureMode
	maxRetries int
	backoff    time.Duration
	observers  []FailureObserver
}

// FailureObserver is notified of failures and recovery
type FailureObserver interface {
	OnFailure(component string, err error, mode FailureMode)
	OnRecovery(component string, success bool)
	OnShutdown(component string)
}

// NewFailureHandler creates a new failure handler
func NewFailureHandler(mode FailureMode) *FailureHandler {
	return &FailureHandler{
		mode:       mode,
		maxRetries: 3,
		backoff:    time.Second,
		observers:  make([]FailureObserver, 0),
	}
}

// HandleFailure handles a failure according to the configured mode
func (h *FailureHandler) HandleFailure(component string, operation func() error) error {
	h.mu.RLock()
	mode := h.mode
	obsCopy := make([]FailureObserver, len(h.observers))
	copy(obsCopy, h.observers)
	h.mu.RUnlock()

	var lastErr error

	switch mode {
	case ImmediateFail:
		lastErr = operation()
		if lastErr != nil {
			h.notifyFailure(component, lastErr, mode)
			return lastErr
		}
		return nil

	case RetryOnce:
		lastErr = operation()
		if lastErr != nil {
			h.notifyFailure(component, lastErr, mode)
			lastErr = operation()
			if lastErr != nil {
				return lastErr
			}
		}
		return nil

	case RetryWithBackoff:
		for attempt := 0; attempt <= h.maxRetries; attempt++ {
			lastErr = operation()
			if lastErr == nil {
				h.notifyRecovery(component, true)
				return nil
			}
			h.notifyFailure(component, lastErr, mode)
			if attempt < h.maxRetries {
				wait := h.backoff * time.Duration(1<<uint(attempt))
				time.Sleep(wait)
			}
		}
		return fmt.Errorf("failed after %d attempts: %w", h.maxRetries+1, lastErr)

	case CircuitBreaker:
		lastErr = operation()
		if lastErr != nil {
			h.notifyFailure(component, lastErr, mode)
		}
		return lastErr

	case DegradedMode:
		lastErr = operation()
		if lastErr != nil {
			h.notifyFailure(component, lastErr, mode)
			return nil
		}
		return nil

	case SafeAbort:
		lastErr = operation()
		if lastErr != nil {
			h.notifyFailure(component, lastErr, mode)
			return lastErr
		}
		return nil

	case ControlledShutdown:
		lastErr = operation()
		if lastErr != nil {
			h.notifyFailure(component, lastErr, mode)
			h.notifyShutdown(component)
		}
		return lastErr

	default:
		return operation()
	}
}

// Subscribe adds a failure observer
func (h *FailureHandler) Subscribe(observer FailureObserver) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observers = append(h.observers, observer)
}

func (h *FailureHandler) notifyFailure(component string, err error, mode FailureMode) {
	h.mu.RLock()
	obsCopy := make([]FailureObserver, len(h.observers))
	copy(obsCopy, h.observers)
	h.mu.RUnlock()
	for _, obs := range obsCopy {
		obs.OnFailure(component, err, mode)
	}
}

func (h *FailureHandler) notifyRecovery(component string, success bool) {
	h.mu.RLock()
	obsCopy := make([]FailureObserver, len(h.observers))
	copy(obsCopy, h.observers)
	h.mu.RUnlock()
	for _, obs := range obsCopy {
		obs.OnRecovery(component, success)
	}
}

func (h *FailureHandler) notifyShutdown(component string) {
	h.mu.RLock()
	obsCopy := make([]FailureObserver, len(h.observers))
	copy(obsCopy, h.observers)
	h.mu.RUnlock()
	for _, obs := range obsCopy {
		obs.OnShutdown(component)
	}
}

// SafeContext wraps a context with safe cancellation
type SafeContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewSafeContext creates a new safe context
func NewSafeContext(parent context.Context) *SafeContext {
	ctx, cancel := context.WithCancel(parent)
	return &SafeContext{ctx: ctx, cancel: cancel}
}

// Context returns the underlying context
func (s *SafeContext) Context() context.Context {
	return s.ctx
}

// Cancel safely cancels the context
func (s *SafeContext) Cancel() {
	s.cancel()
}

// RecoveryManager manages recovery points for safe failure handling
type RecoveryManager struct {
	mu          sync.RWMutex
	checkpoints map[string]interface{}
	maxPoints   int
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(maxPoints int) *RecoveryManager {
	if maxPoints == 0 {
		maxPoints = 100
	}
	return &RecoveryManager{
		checkpoints: make(map[string]interface{}),
		maxPoints:   maxPoints,
	}
}

// SaveState saves a recovery point
func (rm *RecoveryManager) SaveState(id string, state interface{}) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.checkpoints) >= rm.maxPoints {
		for k := range rm.checkpoints {
			delete(rm.checkpoints, k)
			break
		}
	}

	rm.checkpoints[id] = state
	return nil
}

// LoadState loads a recovery point
func (rm *RecoveryManager) LoadState(id string) (interface{}, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	point, exists := rm.checkpoints[id]
	if !exists {
		return nil, fmt.Errorf("recovery point %s not found", id)
	}
	return point, nil
}

// DeleteState removes a recovery point
func (rm *RecoveryManager) DeleteState(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.checkpoints, id)
	return nil
}

// ListStates returns all recovery point IDs
func (rm *RecoveryManager) ListStates() []string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	ids := make([]string, 0, len(rm.checkpoints))
	for id := range rm.checkpoints {
		ids = append(ids, id)
	}
	return ids
}

// RetryConfig configures retry behavior
type RetryConfig struct {
	MaxAttempts int
	MinDelay    time.Duration
	MaxDelay    time.Duration
	Multiplier  float64
}

// DefaultRetryConfig returns reasonable default retry settings
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		MinDelay:    100 * time.Millisecond,
		MaxDelay:    10 * time.Second,
		Multiplier:  2.0,
	}
}

// RetryWithConfig retries an operation with configurable backoff
func RetryWithConfig(config RetryConfig, operation func() error) error {
	delay := config.MinDelay

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		if err := operation(); err == nil {
			return nil
		} else if attempt == config.MaxAttempts-1 {
			return err
		}
		time.Sleep(delay)
		delay = time.Duration(float64(delay) * config.Multiplier)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}

	return ErrNoSafeFallback
}
