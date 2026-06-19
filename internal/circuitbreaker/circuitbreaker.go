package circuitbreaker

import (
	"sync"
	"time"
)

type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case Open:
		return "open"
	case HalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

type Config struct {
	Threshold   int           `json:"threshold"`
	Cooldown    time.Duration `json:"cooldown"`
	HalfOpenMax int           `json:"half_open_max"`
}

type CircuitBreaker struct {
	mu            sync.Mutex
	config        Config
	failures      int
	lastFailure   time.Time
	state         State
	halfOpenCount int
}

func New(config Config) *CircuitBreaker {
	if config.Threshold <= 0 {
		config.Threshold = 3
	}
	if config.Cooldown <= 0 {
		config.Cooldown = 30 * time.Second
	}
	if config.HalfOpenMax <= 0 {
		config.HalfOpenMax = 1
	}
	return &CircuitBreaker{config: config, state: Closed}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case Closed:
		return true
	case Open:
		if time.Since(cb.lastFailure) > cb.config.Cooldown {
			cb.state = HalfOpen
			cb.halfOpenCount = 0
			return true
		}
		return false
	case HalfOpen:
		if cb.halfOpenCount < cb.config.HalfOpenMax {
			cb.halfOpenCount++
			return true
		}
		return false
	default:
		return true
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.halfOpenCount = 0
	cb.state = Closed
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.config.Threshold {
		cb.state = Open
	}
	if cb.state == HalfOpen {
		cb.state = Open
	}
}

func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *CircuitBreaker) Failures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures
}

func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.halfOpenCount = 0
	cb.state = Closed
}

type Manager struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
	config   Config
}

func NewManager(config Config) *Manager {
	return &Manager{
		breakers: make(map[string]*CircuitBreaker),
		config:   config,
	}
}

func (m *Manager) Get(tool string) *CircuitBreaker {
	m.mu.RLock()
	cb, ok := m.breakers[tool]
	m.mu.RUnlock()
	if ok {
		return cb
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if cb, ok := m.breakers[tool]; ok {
		return cb
	}
	cb = New(m.config)
	m.breakers[tool] = cb
	return cb
}

func (m *Manager) RecordSuccess(tool string) {
	m.Get(tool).RecordSuccess()
}

func (m *Manager) RecordFailure(tool string) {
	m.Get(tool).RecordFailure()
}

func (m *Manager) Allow(tool string) bool {
	return m.Get(tool).Allow()
}

func (m *Manager) Reset(tool string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cb, ok := m.breakers[tool]; ok {
		cb.Reset()
	}
}

func (m *Manager) ResetAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cb := range m.breakers {
		cb.Reset()
	}
}

func (m *Manager) States() map[string]State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	states := make(map[string]State, len(m.breakers))
	for tool, cb := range m.breakers {
		states[tool] = cb.state
	}
	return states
}
