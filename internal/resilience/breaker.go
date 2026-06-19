package resilience

import (
	"errors"
	"math/rand"
	"sync"
	"time"
)

var ErrCircuitOpen = errors.New("circuit breaker is open")

type State int

const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

type Config struct {
	Name string

	MaxConsecutiveFailures int

	ResetTimeout time.Duration

	HalfOpenMaxCalls int

	SuccessThreshold int

	MaxResetTimeout time.Duration

	UseExponentialBackoff bool
}

func DefaultConfig(name string) Config {
	return Config{
		Name:                   name,
		MaxConsecutiveFailures: 5,
		ResetTimeout:           30 * time.Second,
		HalfOpenMaxCalls:       1,
		SuccessThreshold:       1,
		MaxResetTimeout:        5 * time.Minute,
		UseExponentialBackoff:  true,
	}
}

type CircuitBreaker struct {
	mu              sync.RWMutex
	cfg             Config
	state           State
	failures        int
	successes       int
	openedAt        time.Time
	consecutiveOpen int
	metrics         Metrics
}

type Metrics struct {
	TotalRequests  uint64
	TotalFailures  uint64
	TotalSuccesses uint64
	TotalTimeouts  uint64
}

func NewCircuitBreaker(cfg Config) *CircuitBreaker {
	if cfg.MaxConsecutiveFailures == 0 {
		cfg.MaxConsecutiveFailures = 5
	}
	if cfg.ResetTimeout == 0 {
		cfg.ResetTimeout = 30 * time.Second
	}
	if cfg.SuccessThreshold == 0 {
		cfg.SuccessThreshold = 1
	}
	if cfg.MaxResetTimeout == 0 {
		cfg.MaxResetTimeout = 5 * time.Minute
	}
	return &CircuitBreaker{
		cfg:   cfg,
		state: StateClosed,
	}
}

func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *CircuitBreaker) Metrics() Metrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.metrics
}

func (cb *CircuitBreaker) currentResetTimeout() time.Duration {
	if !cb.cfg.UseExponentialBackoff {
		return cb.cfg.ResetTimeout
	}

	baseTimeout := cb.cfg.ResetTimeout
	maxTimeout := cb.cfg.MaxResetTimeout
	if maxTimeout == 0 {
		maxTimeout = 5 * time.Minute
	}

	timeout := baseTimeout
	for i := 0; i < cb.consecutiveOpen; i++ {
		timeout *= 2
		if timeout > maxTimeout {
			timeout = maxTimeout
			break
		}
	}

	jitter := time.Duration(rand.Float64() * float64(timeout) * 0.3)
	timeout += jitter

	if timeout > maxTimeout {
		timeout = maxTimeout
	}

	return timeout
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.metrics.TotalRequests++

	switch cb.state {
	case StateClosed:
		return true

	case StateOpen:
		resetTimeout := cb.currentResetTimeout()
		if time.Since(cb.openedAt) >= resetTimeout {
			cb.state = StateHalfOpen
			cb.successes = 0
			return true
		}
		cb.metrics.TotalTimeouts++
		return false

	case StateHalfOpen:
		if cb.successes < cb.cfg.HalfOpenMaxCalls {
			return true
		}
		cb.metrics.TotalTimeouts++
		return false

	default:
		return false
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.metrics.TotalSuccesses++

	switch cb.state {
	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.cfg.SuccessThreshold {
			cb.state = StateClosed
			cb.failures = 0
			cb.consecutiveOpen = 0
		}

	case StateClosed:
		cb.failures = 0
	}
}

func (cb *CircuitBreaker) RecordFailure(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.metrics.TotalFailures++

	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.cfg.MaxConsecutiveFailures {
			cb.state = StateOpen
			cb.openedAt = time.Now()
			cb.consecutiveOpen++
		}

	case StateHalfOpen:
		cb.state = StateOpen
		cb.openedAt = time.Now()
		cb.successes = 0
		cb.consecutiveOpen++
	}
}

func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
	cb.consecutiveOpen = 0
}

func (cb *CircuitBreaker) WaitForClose(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cb.State() == StateClosed {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

type SubsystemBreaker struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
}

func NewSubsystemBreaker() *SubsystemBreaker {
	return &SubsystemBreaker{
		breakers: make(map[string]*CircuitBreaker),
	}
}

func (sb *SubsystemBreaker) GetOrCreate(subsystem string, cfg Config) *CircuitBreaker {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	cfg.Name = subsystem
	if cb, exists := sb.breakers[subsystem]; exists {
		return cb
	}

	cb := NewCircuitBreaker(cfg)
	sb.breakers[subsystem] = cb
	return cb
}

func (sb *SubsystemBreaker) Get(subsystem string) (*CircuitBreaker, bool) {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	cb, exists := sb.breakers[subsystem]
	return cb, exists
}

func (sb *SubsystemBreaker) ResetAll() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for _, cb := range sb.breakers {
		cb.Reset()
	}
}

func (sb *SubsystemBreaker) StateSummary() map[string]State {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	summary := make(map[string]State, len(sb.breakers))
	for name, cb := range sb.breakers {
		summary[name] = cb.State()
	}
	return summary
}

type BackpressureController struct {
	breaker *SubsystemBreaker
}

func NewBackpressureController(breaker *SubsystemBreaker) *BackpressureController {
	return &BackpressureController{
		breaker: breaker,
	}
}

func (bp *BackpressureController) AllowOperation(subsystem string) bool {
	cb, exists := bp.breaker.Get(subsystem)
	if !exists {
		return true
	}

	state := cb.State()
	if state == StateOpen {
		return false
	}

	return cb.Allow()
}

func (bp *BackpressureController) ReportOperationResult(subsystem string, success bool, err error) {
	cb, exists := bp.breaker.Get(subsystem)
	if !exists {
		return
	}

	if success {
		cb.RecordSuccess()
	} else {
		cb.RecordFailure(err)
	}
}
