package safety

import (
	"fmt"
	"sync"
	"time"
)

// InvariantPriority defines how critical an invariant is
type InvariantPriority int

const (
	InvariantCritical InvariantPriority = iota // Must never be violated
	InvariantHigh                              // Very important, violations trigger alerts
	InvariantMedium                            // Important, violations logged
	InvariantLow                               // Best practice, violations noted
)

// Invariant represents a system rule that must never be broken
type Invariant struct {
	ID          string
	Name        string
	Description string
	Priority    InvariantPriority
	Check       func() bool
	Violation   string // What to do when violated
}

// InvariantsEngine enforces system-wide invariants
type InvariantsEngine struct {
	mu         sync.RWMutex
	invariants map[string]Invariant
	violations []InvariantViolation
}

// InvariantViolation records when an invariant is broken
type InvariantViolation struct {
	InvariantID string
	Name        string
	Timestamp   int64
	Details     string
	Priority    InvariantPriority
}

// NewInvariantsEngine creates a new invariants engine
func NewInvariantsEngine() *InvariantsEngine {
	return &InvariantsEngine{
		invariants: make(map[string]Invariant),
		violations: make([]InvariantViolation, 0),
	}
}

// Register registers a new invariant
func (e *InvariantsEngine) Register(invariant Invariant) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invariants[invariant.ID] = invariant
}

// CheckAll verifies all invariants
func (e *InvariantsEngine) CheckAll() []InvariantViolation {
	e.mu.RLock()
	var violations []InvariantViolation
	for id, inv := range e.invariants {
		if inv.Check != nil && !inv.Check() {
			violations = append(violations, InvariantViolation{
				InvariantID: id,
				Name:        inv.Name,
				Timestamp:   time.Now().Unix(),
				Priority:    inv.Priority,
			})
		}
	}
	e.mu.RUnlock()

	if len(violations) > 0 {
		e.mu.Lock()
		e.violations = append(e.violations, violations...)
		e.mu.Unlock()
	}

	return violations
}

// CheckInvariant checks a single invariant by ID
func (e *InvariantsEngine) CheckInvariant(id string) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	invariant, exists := e.invariants[id]
	if !exists {
		return false, fmt.Errorf("invariant %s not found", id)
	}

	if invariant.Check != nil {
		return invariant.Check(), nil
	}
	return true, nil
}

// GetViolations returns all recorded violations
func (e *InvariantsEngine) GetViolations() []InvariantViolation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]InvariantViolation(nil), e.violations...)
}

// ClearViolations clears the violation log
func (e *InvariantsEngine) ClearViolations() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.violations = nil
}

// InvariantCount returns the number of registered invariants
func (e *InvariantsEngine) InvariantCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.invariants)
}

// ViolationCount returns the number of recorded violations
func (e *InvariantsEngine) ViolationCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.violations)
}

// DefaultInvariants returns the standard set of system invariants
func DefaultInvariants() []Invariant {
	return []Invariant{
		{
			ID:          "sandbox-isolation",
			Name:        "All executions must be isolated",
			Description: "No execution path should have unrestricted system access",
			Priority:    InvariantMedium,
			Check: func() bool {
				return true
			},
			Violation: "Enable sandboxing for execution path",
		},
	}
}
