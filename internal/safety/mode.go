package safety

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

// ErrBlockedBySafetyMode is returned when an action is blocked by the current safety mode
var ErrBlockedBySafetyMode = errors.New("blocked by current safety mode")

// ErrRequiresApproval is returned when an action requires human approval
var ErrRequiresApproval = errors.New("requires human approval")

// ErrKillSwitchActive is returned when the emergency stop is active
var ErrKillSwitchActive = errors.New("emergency stop is active")

// OperationMode defines the current operational mode of ARES
type OperationMode int

const (
	// Observe mode: only observe and log, do not execute any actions
	ObserveMode OperationMode = iota
	// Safe mode: only execute low-risk, reversible actions
	SafeMode
	// VerifyOnly mode: execute only actions that can be verified before execution
	VerifyOnlyMode
	// Autonomous mode: full autonomous operation within defined bounds
	AutonomousMode
	// Aggressive mode: expanded scope including higher-risk actions
	AggressiveMode
	// InternalOnly mode: restrict to internal/sandbox targets only
	InternalOnlyMode
)

// String returns a human-readable name for the operation mode
func (m OperationMode) String() string {
	switch m {
	case ObserveMode:
		return "observe"
	case SafeMode:
		return "safe"
	case VerifyOnlyMode:
		return "verify-only"
	case AutonomousMode:
		return "autonomous"
	case AggressiveMode:
		return "aggressive"
	case InternalOnlyMode:
		return "internal-only"
	default:
		return "unknown"
	}
}

// ParseOperationMode parses a string into an OperationMode
func ParseOperationMode(s string) (OperationMode, error) {
	switch s {
	case "observe":
		return ObserveMode, nil
	case "safe":
		return SafeMode, nil
	case "verify-only":
		return VerifyOnlyMode, nil
	case "autonomous":
		return AutonomousMode, nil
	case "aggressive":
		return AggressiveMode, nil
	case "internal-only":
		return InternalOnlyMode, nil
	default:
		return SafeMode, fmt.Errorf("unknown operation mode: %s", s)
	}
}

// RiskLevel represents the risk level of an action
type RiskLevel int

const (
	RiskNone     RiskLevel = iota // No risk
	RiskLow                       // Low risk, reversible
	RiskMedium                    // Medium risk, may require additional verification
	RiskHigh                      // High risk, requires explicit approval
	RiskCritical                  // Critical risk, requires multiple approvals
)

// ActionPolicy defines what actions are allowed in each mode
type ActionPolicy struct {
	// AllowedRiskLevels maps operation modes to their maximum allowed risk level
	AllowedRiskLevels map[OperationMode]RiskLevel

	// RequireApprovalAboveRiskLevel is the risk level above which human approval is required
	RequireApprovalAboveRiskLevel RiskLevel

	// AllowExternalNetwork controls whether external network access is permitted
	AllowExternalNetwork bool

	// AllowExploits controls whether exploit execution is permitted
	AllowExploits bool

	// AllowDataExfiltration controls whether data exfiltration is permitted
	AllowDataExfiltration bool

	// MaxScope defines the maximum scope of targets
	MaxScope string
}

// DefaultPolicies returns the default action policies for each mode
func DefaultPolicies() map[OperationMode]ActionPolicy {
	return map[OperationMode]ActionPolicy{
		ObserveMode: {
			AllowedRiskLevels:             map[OperationMode]RiskLevel{ObserveMode: RiskNone},
			RequireApprovalAboveRiskLevel: RiskLow,
			AllowExternalNetwork:          false,
			AllowExploits:                 false,
			AllowDataExfiltration:         false,
			MaxScope:                      "",
		},
		SafeMode: {
			AllowedRiskLevels:             map[OperationMode]RiskLevel{SafeMode: RiskCritical},
			RequireApprovalAboveRiskLevel: RiskCritical,
			AllowExternalNetwork:          true,
			AllowExploits:                 true,
			AllowDataExfiltration:         false,
			MaxScope:                      "scoped",
		},
		VerifyOnlyMode: {
			AllowedRiskLevels:             map[OperationMode]RiskLevel{VerifyOnlyMode: RiskMedium},
			RequireApprovalAboveRiskLevel: RiskHigh,
			AllowExternalNetwork:          true,
			AllowExploits:                 true,
			AllowDataExfiltration:         false,
			MaxScope:                      "scoped",
		},
		AutonomousMode: {
			AllowedRiskLevels:             map[OperationMode]RiskLevel{AutonomousMode: RiskHigh},
			RequireApprovalAboveRiskLevel: RiskCritical,
			AllowExternalNetwork:          true,
			AllowExploits:                 true,
			AllowDataExfiltration:         true,
			MaxScope:                      "full",
		},
		AggressiveMode: {
			AllowedRiskLevels:             map[OperationMode]RiskLevel{AggressiveMode: RiskCritical},
			RequireApprovalAboveRiskLevel: RiskCritical,
			AllowExternalNetwork:          true,
			AllowExploits:                 true,
			AllowDataExfiltration:         true,
			MaxScope:                      "full",
		},
		InternalOnlyMode: {
			AllowedRiskLevels:             map[OperationMode]RiskLevel{InternalOnlyMode: RiskMedium},
			RequireApprovalAboveRiskLevel: RiskHigh,
			AllowExternalNetwork:          false,
			AllowExploits:                 true,
			AllowDataExfiltration:         false,
			MaxScope:                      "internal",
		},
	}
}

// SafetyModeManager manages operational safety modes
type SafetyModeManager struct {
	mu          sync.RWMutex
	currentMode OperationMode
	policies    map[OperationMode]ActionPolicy
	killSwitch  bool
	approvers   []string
	pending     map[string]*PendingApproval
}

// PendingApproval represents a pending approval request
type PendingApproval struct {
	ID          string
	Action      string
	RiskLevel   RiskLevel
	RequestedAt time.Time
	ApprovedBy  string
	ApprovedAt  time.Time
	Reason      string
}

// NewSafetyModeManager creates a new safety mode manager
func NewSafetyModeManager(initialMode OperationMode) *SafetyModeManager {
	return &SafetyModeManager{
		currentMode: initialMode,
		policies:    DefaultPolicies(),
		approvers:   []string{"admin"},
		pending:     make(map[string]*PendingApproval),
	}
}

// SetMode changes the operation mode
func (m *SafetyModeManager) SetMode(mode OperationMode, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isApproverLocked(actor) {
		return fmt.Errorf("actor %s is not authorized to change safety mode", actor)
	}

	if m.killSwitch {
		return ErrKillSwitchActive
	}

	oldMode := m.currentMode
	m.currentMode = mode

	logger.Info("safety mode changed", logger.Fields{
		"old_mode": oldMode.String(),
		"new_mode": mode.String(),
		"actor":    actor,
	})

	return nil
}

// CurrentMode returns the current operation mode
func (m *SafetyModeManager) CurrentMode() OperationMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMode
}

// IsKillSwitchActive returns whether the emergency stop is active
func (m *SafetyModeManager) IsKillSwitchActive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.killSwitch
}

// ActivateKillSwitch activates the emergency stop
func (m *SafetyModeManager) ActivateKillSwitch(actor, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isApproverLocked(actor) {
		return fmt.Errorf("actor %s is not authorized to activate kill switch", actor)
	}

	m.killSwitch = true

	logger.Error("kill switch activated", logger.Fields{
		"actor":  actor,
		"reason": reason,
	})
	return nil
}

// DeactivateKillSwitch deactivates the emergency stop
func (m *SafetyModeManager) DeactivateKillSwitch(actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isApproverLocked(actor) {
		return fmt.Errorf("actor %s is not authorized to deactivate kill switch", actor)
	}

	m.killSwitch = false

	logger.Info("kill switch deactivated", logger.Fields{
		"actor": actor,
	})
	return nil
}

// CanPerform checks if an action can be performed in the current mode
func (m *SafetyModeManager) CanPerform(action string, risk RiskLevel, isExternal bool) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.killSwitch {
		return false, ErrKillSwitchActive
	}

	policy, exists := m.policies[m.currentMode]
	if !exists {
		return false, fmt.Errorf("no policy defined for mode %s", m.currentMode.String())
	}

	// Check if risk level is allowed
	maxRisk, exists := policy.AllowedRiskLevels[m.currentMode]
	if !exists {
		maxRisk = RiskLow
	}

	if risk > maxRisk {
		return false, fmt.Errorf("%w: risk level %d exceeds allowed %d for mode %s",
			ErrBlockedBySafetyMode, risk, maxRisk, m.currentMode.String())
	}

	// Check external network restriction
	if isExternal && !policy.AllowExternalNetwork {
		return false, fmt.Errorf("%w: external network access not permitted in mode %s",
			ErrBlockedBySafetyMode, m.currentMode.String())
	}

	// Check if approval is required
	if risk > policy.RequireApprovalAboveRiskLevel {
		return false, ErrRequiresApproval
	}

	return true, nil
}

// RequireApproval checks if approval is required for an action
func (m *SafetyModeManager) RequireApproval(risk RiskLevel) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, exists := m.policies[m.currentMode]
	if !exists {
		return true
	}

	return risk > policy.RequireApprovalAboveRiskLevel
}

// RequestApproval creates a pending approval request
func (m *SafetyModeManager) RequestApproval(id, action string, risk RiskLevel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pending[id] = &PendingApproval{
		ID:          id,
		Action:      action,
		RiskLevel:   risk,
		RequestedAt: time.Now(),
	}

	logger.Info("approval requested", logger.Fields{
		"id":         id,
		"action":     action,
		"risk_level": risk,
		"mode":       m.currentMode.String(),
	})

	return nil
}

// Approve approves a pending request
func (m *SafetyModeManager) Approve(id, approver string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	approval, exists := m.pending[id]
	if !exists {
		return fmt.Errorf("approval request %s not found", id)
	}

	approval.ApprovedBy = approver
	approval.ApprovedAt = time.Now()

	logger.Info("approval granted", logger.Fields{
		"id":       id,
		"action":   approval.Action,
		"approver": approver,
	})

	return nil
}

// Deny denies a pending request
func (m *SafetyModeManager) Deny(id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pending[id]; !exists {
		return fmt.Errorf("approval request %s not found", id)
	}

	delete(m.pending, id)

	logger.Info("approval denied", logger.Fields{
		"id":     id,
		"reason": reason,
	})

	return nil
}

// PendingCount returns the number of pending approvals
func (m *SafetyModeManager) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pending)
}

// GetPending returns all pending approvals
func (m *SafetyModeManager) GetPending() []*PendingApproval {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*PendingApproval, 0, len(m.pending))
	for _, p := range m.pending {
		result = append(result, p)
	}
	return result
}

// AddApprover adds an authorized approver
func (m *SafetyModeManager) AddApprover(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvers = append(m.approvers, name)
}

// IsApprover checks if a user is an authorized approver
func (m *SafetyModeManager) IsApprover(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isApproverLocked(name)
}

func (m *SafetyModeManager) isApproverLocked(name string) bool {
	for _, a := range m.approvers {
		if a == name {
			return true
		}
	}
	return false
}

// ModeInfo provides a summary of the current safety mode state
type ModeInfo struct {
	Mode             string `json:"mode"`
	KillSwitch       bool   `json:"kill_switch_active"`
	PendingApprovals int    `json:"pending_approvals"`
	ApproverCount    int    `json:"approver_count"`
	AllowExternal    bool   `json:"allow_external_network"`
	AllowExploits    bool   `json:"allow_exploits"`
	MaxRiskLevel     int    `json:"max_risk_level"`
}

// GetModeInfo returns a summary of the current safety mode state
func (m *SafetyModeManager) GetModeInfo() ModeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy := m.policies[m.currentMode]
	maxRisk := 0
	if r, exists := policy.AllowedRiskLevels[m.currentMode]; exists {
		maxRisk = int(r)
	}

	return ModeInfo{
		Mode:             m.currentMode.String(),
		KillSwitch:       m.killSwitch,
		PendingApprovals: len(m.pending),
		ApproverCount:    len(m.approvers),
		AllowExternal:    policy.AllowExternalNetwork,
		AllowExploits:    policy.AllowExploits,
		MaxRiskLevel:     maxRisk,
	}
}

// ModeCheck is a middleware that enforces safety mode checks
func ModeCheck(manager *SafetyModeManager, action string, risk RiskLevel, isExternal bool) error {
	allowed, err := manager.CanPerform(action, risk, isExternal)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrBlockedBySafetyMode
	}
	return nil
}
