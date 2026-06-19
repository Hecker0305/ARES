package safety

import (
	"github.com/ares/engine/internal/uuid"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrBlockedByPolicy    = errors.New("blocked by autonomy policy")
	ErrRequiresEscalation = errors.New("requires escalation to higher autonomy level")
	ErrAutonomyDenied     = errors.New("autonomy level denied for this action")
)

// AutonomyLevel represents the level of autonomous operation
type AutonomyLevel int

const (
	// NoAutonomy: all actions require human approval
	NoAutonomy AutonomyLevel = iota
	// MinimalAutonomy: only low-risk, verified actions auto-execute
	MinimalAutonomy
	// StandardAutonomy: standard autonomous operation with guardrails
	StandardAutonomy
	// ElevatedAutonomy: expanded authority with periodic checks
	ElevatedAutonomy
	// FullAutonomy: complete autonomous operation
	FullAutonomy
)

// AutonomyConfig configures the autonomy escalation model
type AutonomyConfig struct {
	// DefaultLevel is the initial autonomy level
	DefaultLevel AutonomyLevel

	// EscalationTimeout is how long before pending escalations expire
	EscalationTimeout time.Duration

	// AutoDemote enables automatic demotion on violations
	AutoDemote bool

	// MaxEscalationsPerHour limits escalation abuse
	MaxEscalationsPerHour int

	// RequireMFAForHighRisk requires MFA for high-risk actions
	RequireMFAForHighRisk bool
}

// DefaultAutonomyConfig returns reasonable defaults
func DefaultAutonomyConfig() AutonomyConfig {
	return AutonomyConfig{
		DefaultLevel:          MinimalAutonomy,
		EscalationTimeout:     5 * time.Minute,
		AutoDemote:            true,
		MaxEscalationsPerHour: 10,
		RequireMFAForHighRisk: false,
	}
}

// AutonomyPolicy defines what each level can do
type AutonomyPolicy struct {
	MaxRiskLevel          RiskLevel
	AllowUnattended       bool
	AllowExploits         bool
	AllowDataExfiltration bool
	AllowTargetExpansion  bool
	RequireVerification   bool
	MaxConcurrentActions  int
	ApprovalWindow        time.Duration
}

// AutonomyManager handles graduated autonomy escalation
type AutonomyManager struct {
	mu              sync.RWMutex
	current         AutonomyLevel
	config          AutonomyConfig
	approvals       map[string]*EscalationRequest
	history         []AutonomyEvent
	violations      int
	lastViolationAt time.Time
	policies        map[AutonomyLevel]AutonomyPolicy
	subscribers     []AutonomySubscriber
}

// AutonomyEvent records autonomy level changes
type AutonomyEvent struct {
	Timestamp time.Time
	OldLevel  AutonomyLevel
	NewLevel  AutonomyLevel
	Actor     string
	Reason    string
	Trigger   EventTrigger
}

// EventTrigger describes what triggered the level change
type EventTrigger int

const (
	TriggerManual EventTrigger = iota
	TriggerAutoEscalation
	TriggerAutoDemotion
	TriggerPolicyViolation
	TriggerTimeout
)

// EscalationRequest represents a request to increase autonomy
type EscalationRequest struct {
	ID           string
	Actor        string
	FromLevel    AutonomyLevel
	ToLevel      AutonomyLevel
	Reason       string
	Actions      []string
	RiskLevel    RiskLevel
	RequestedAt  time.Time
	ApprovedAt   time.Time
	Denied       bool
	DeniedReason string
}

// AutonomySubscriber receives notifications about autonomy changes
type AutonomySubscriber interface {
	OnLevelChanged(oldLevel, newLevel AutonomyLevel, actor string)
	OnEscalationRequested(req *EscalationRequest)
	OnEscalationApproved(req *EscalationRequest)
	OnEscalationDenied(req *EscalationRequest)
	OnAutoDemotion(level AutonomyLevel, reason string)
}

// NewAutonomyManager creates a new autonomy manager
func NewAutonomyManager(cfg AutonomyConfig) *AutonomyManager {
	return &AutonomyManager{
		current:     cfg.DefaultLevel,
		config:      cfg,
		approvals:   make(map[string]*EscalationRequest),
		history:     make([]AutonomyEvent, 0),
		policies:    defaultAutonomyPolicies(),
		subscribers: make([]AutonomySubscriber, 0),
	}
}

func defaultAutonomyPolicies() map[AutonomyLevel]AutonomyPolicy {
	return map[AutonomyLevel]AutonomyPolicy{
		NoAutonomy: {
			MaxRiskLevel:          RiskNone,
			AllowUnattended:       false,
			AllowExploits:         false,
			AllowDataExfiltration: false,
			AllowTargetExpansion:  false,
			RequireVerification:   true,
			MaxConcurrentActions:  0,
			ApprovalWindow:        0,
		},
		MinimalAutonomy: {
			MaxRiskLevel:          RiskLow,
			AllowUnattended:       false,
			AllowExploits:         false,
			AllowDataExfiltration: false,
			AllowTargetExpansion:  false,
			RequireVerification:   true,
			MaxConcurrentActions:  2,
			ApprovalWindow:        1 * time.Minute,
		},
		StandardAutonomy: {
			MaxRiskLevel:          RiskMedium,
			AllowUnattended:       true,
			AllowExploits:         true,
			AllowDataExfiltration: false,
			AllowTargetExpansion:  true,
			RequireVerification:   false,
			MaxConcurrentActions:  5,
			ApprovalWindow:        5 * time.Minute,
		},
		ElevatedAutonomy: {
			MaxRiskLevel:          RiskHigh,
			AllowUnattended:       true,
			AllowExploits:         true,
			AllowDataExfiltration: true,
			AllowTargetExpansion:  true,
			RequireVerification:   false,
			MaxConcurrentActions:  10,
			ApprovalWindow:        10 * time.Minute,
		},
		FullAutonomy: {
			MaxRiskLevel:          RiskCritical,
			AllowUnattended:       true,
			AllowExploits:         true,
			AllowDataExfiltration: true,
			AllowTargetExpansion:  true,
			RequireVerification:   false,
			MaxConcurrentActions:  50,
			ApprovalWindow:        30 * time.Minute,
		},
	}
}

// CurrentLevel returns the current autonomy level
func (m *AutonomyManager) CurrentLevel() AutonomyLevel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// LevelString returns the current level as a string
func (m *AutonomyManager) LevelString() string {
	return m.current.String()
}

// SetLevel changes the autonomy level
func (m *AutonomyManager) SetLevel(level AutonomyLevel, actor, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.config.AutoDemote && level > m.current {
		// Check if we've had too many violations recently
		if m.violations > 3 {
			return ErrAutonomyDenied
		}
	}

	oldLevel := m.current
	m.current = level

	event := AutonomyEvent{
		Timestamp: time.Now(),
		OldLevel:  oldLevel,
		NewLevel:  level,
		Actor:     actor,
		Reason:    reason,
		Trigger:   TriggerManual,
	}
	m.history = append(m.history, event)

	// Notify subscribers
	for _, sub := range m.subscribers {
		sub.OnLevelChanged(oldLevel, level, actor)
	}

	return nil
}

// CanExecute checks if an action can be executed at the current autonomy level
func (m *AutonomyManager) CanExecute(action string, risk RiskLevel, requiresNetwork bool) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, exists := m.policies[m.current]
	if !exists {
		return false, fmt.Errorf("no policy for autonomy level %d", m.current)
	}

	// Check risk level
	if risk > policy.MaxRiskLevel {
		return false, fmt.Errorf("%w: risk level %d exceeds max %d for level %s",
			ErrBlockedByPolicy, risk, policy.MaxRiskLevel, m.current.String())
	}

	// Check network requirement — use risk gating instead of AllowExploits
	if requiresNetwork && policy.MaxRiskLevel < RiskLow {
		return false, fmt.Errorf("%w: network access not allowed at level %s",
			ErrBlockedByPolicy, m.current.String())
	}

	return true, nil
}

// RequestEscalation creates a request to increase autonomy
func (m *AutonomyManager) RequestEscalation(actor string, toLevel AutonomyLevel, reason string, actions []string, risk RiskLevel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uuid.New()

	req := &EscalationRequest{
		ID:          id,
		Actor:       actor,
		FromLevel:   m.current,
		ToLevel:     toLevel,
		Reason:      reason,
		Actions:     actions,
		RiskLevel:   risk,
		RequestedAt: time.Now(),
	}

	m.approvals[id] = req

	// Notify subscribers
	for _, sub := range m.subscribers {
		sub.OnEscalationRequested(req)
	}

	return nil
}

// ApproveEscalation approves an escalation request
func (m *AutonomyManager) ApproveEscalation(id, approver string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, exists := m.approvals[id]
	if !exists {
		return fmt.Errorf("escalation %s not found", id)
	}

	req.ApprovedAt = time.Now()

	// Update history
	event := AutonomyEvent{
		Timestamp: time.Now(),
		OldLevel:  req.FromLevel,
		NewLevel:  req.ToLevel,
		Actor:     approver,
		Reason:    req.Reason,
		Trigger:   TriggerManual,
	}
	m.history = append(m.history, event)

	m.current = req.ToLevel

	// Notify subscribers
	for _, sub := range m.subscribers {
		sub.OnEscalationApproved(req)
	}

	return nil
}

// DenyEscalation denies an escalation request
func (m *AutonomyManager) DenyEscalation(id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, exists := m.approvals[id]
	if !exists {
		return fmt.Errorf("escalation %s not found", id)
	}

	req.Denied = true
	req.DeniedReason = reason

	delete(m.approvals, id)

	// Notify subscribers
	for _, sub := range m.subscribers {
		sub.OnEscalationDenied(req)
	}

	return nil
}

// RecordViolation records a policy violation and may trigger auto-demotion
func (m *AutonomyManager) RecordViolation() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.decayViolationsLocked()

	m.violations++
	m.lastViolationAt = time.Now()

	// Auto-demote if configured and violations exceed threshold
	if m.config.AutoDemote && m.violations >= 3 {
		if m.current > MinimalAutonomy {
			m.current = m.current - 1
			m.violations = 0

			// Notify subscribers of auto-demotion
			for _, sub := range m.subscribers {
				sub.OnAutoDemotion(m.current, "Auto-demoted due to violations")
			}
		}
	}
}

func (m *AutonomyManager) decayViolationsLocked() {
	if m.lastViolationAt.IsZero() {
		return
	}
	elapsed := time.Since(m.lastViolationAt)
	decayed := int(elapsed.Hours())
	if decayed > m.violations {
		m.violations = 0
	} else if decayed > 0 {
		m.violations -= decayed
	}
}

// Subscribe adds a subscriber for autonomy events
func (m *AutonomyManager) Subscribe(subscriber AutonomySubscriber) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers = append(m.subscribers, subscriber)
}

// GetPendingEscalations returns all pending escalation requests
func (m *AutonomyManager) GetPendingEscalations() []*EscalationRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*EscalationRequest, 0, len(m.approvals))
	for _, req := range m.approvals {
		result = append(result, req)
	}
	return result
}

// GetHistory returns the autonomy change history
func (m *AutonomyManager) GetHistory() []AutonomyEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]AutonomyEvent(nil), m.history...)
}

// Stats provides current autonomy statistics
type Stats struct {
	CurrentLevel    AutonomyLevel `json:"current_level"`
	CurrentLevelStr string        `json:"current_level_string"`
	PendingRequests int           `json:"pending_requests"`
	ViolationCount  int           `json:"violation_count"`
	HistoryCount    int           `json:"history_count"`
}

// GetStats returns current autonomy statistics
func (m *AutonomyManager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return Stats{
		CurrentLevel:    m.current,
		CurrentLevelStr: m.current.String(),
		PendingRequests: len(m.approvals),
		ViolationCount:  m.violations,
		HistoryCount:    len(m.history),
	}
}

// String implements Stringer for AutonomyLevel
func (l AutonomyLevel) String() string {
	switch l {
	case NoAutonomy:
		return "no-autonomy"
	case MinimalAutonomy:
		return "minimal"
	case StandardAutonomy:
		return "standard"
	case ElevatedAutonomy:
		return "elevated"
	case FullAutonomy:
		return "full"
	default:
		return "unknown"
	}
}

// ParseAutonomyLevel parses a string to AutonomyLevel
func ParseAutonomyLevel(s string) (AutonomyLevel, error) {
	switch s {
	case "no-autonomy":
		return NoAutonomy, nil
	case "minimal":
		return MinimalAutonomy, nil
	case "standard":
		return StandardAutonomy, nil
	case "elevated":
		return ElevatedAutonomy, nil
	case "full":
		return FullAutonomy, nil
	default:
		return MinimalAutonomy, fmt.Errorf("unknown autonomy level: %s", s)
	}
}

// LevelColor returns a color code for the autonomy level (for terminal output)
func (l AutonomyLevel) LevelColor() string {
	switch l {
	case NoAutonomy:
		return "\033[31m" // Red
	case MinimalAutonomy:
		return "\033[33m" // Yellow
	case StandardAutonomy:
		return "\033[32m" // Green
	case ElevatedAutonomy:
		return "\033[35m" // Magenta
	case FullAutonomy:
		return "\033[31m" // Red (dangerous)
	default:
		return "\033[0m"
	}
}
