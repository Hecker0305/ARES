package safety

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ares/engine/internal/logger"
)

type ActionClassification struct {
	Action           string
	RiskLevel        RiskLevel
	Description      string
	RequiresApproval bool
	IsExternal       bool
	IsDestructive    bool
}

type ActionClassifier struct {
	mu    sync.RWMutex
	rules map[string]ActionClassification
}

func NewActionClassifier() *ActionClassifier {
	c := &ActionClassifier{
		rules: make(map[string]ActionClassification),
	}
	c.loadDefaultRules()
	return c
}

func (c *ActionClassifier) loadDefaultRules() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules["terminal_execute"] = ActionClassification{
			Action:           "terminal_execute",
			RiskLevel:        RiskHigh,
			Description:      "Command execution on target system",
			RequiresApproval: true,
			IsExternal:       true,
		}

	c.rules["browser_navigate"] = ActionClassification{
		Action:           "browser_navigate",
		RiskLevel:        RiskMedium,
		Description:      "Browser navigation to target",
		RequiresApproval: false,
		IsExternal:       true,
	}
	c.rules["browser_evaluate"] = ActionClassification{
		Action:           "browser_evaluate",
		RiskLevel:        RiskMedium,
		Description:      "JavaScript execution in browser",
		RequiresApproval: false,
		IsExternal:       true,
	}
	c.rules["browser_screenshot"] = ActionClassification{
		Action:           "browser_screenshot",
		RiskLevel:        RiskLow,
		Description:      "Screenshot capture",
		RequiresApproval: false,
		IsExternal:       true,
	}

	c.rules["http_request"] = ActionClassification{
		Action:           "http_request",
		RiskLevel:        RiskMedium,
		Description:      "HTTP request to target",
		RequiresApproval: false,
		IsExternal:       true,
	}

	c.rules["file_read"] = ActionClassification{
		Action:           "file_read",
		RiskLevel:        RiskLow,
		Description:      "File read operation",
		RequiresApproval: false,
		IsExternal:       false,
	}
	c.rules["file_write"] = ActionClassification{
		Action:           "file_write",
		RiskLevel:        RiskHigh,
		Description:      "File write operation",
		RequiresApproval: true,
		IsExternal:       false,
	}
	c.rules["file_delete"] = ActionClassification{
		Action:           "file_delete",
		RiskLevel:        RiskCritical,
		Description:      "File deletion operation",
		RequiresApproval: true,
		IsExternal:       false,
		IsDestructive:    true,
	}

	c.rules["llm_complete"] = ActionClassification{
		Action:           "llm_complete",
		RiskLevel:        RiskLow,
		Description:      "LLM completion request",
		RequiresApproval: false,
		IsExternal:       false,
	}
	c.rules["tool_call"] = ActionClassification{
		Action:           "tool_call",
		RiskLevel:        RiskMedium,
		Description:      "Tool execution via LLM",
		RequiresApproval: false,
		IsExternal:       true,
	}

	c.rules["python_exec"] = ActionClassification{
		Action:           "python_exec",
		RiskLevel:        RiskCritical,
		Description:      "Python code execution",
		RequiresApproval: true,
		IsExternal:       true,
	}
	c.rules["shell_exec"] = ActionClassification{
		Action:           "shell_exec",
		RiskLevel:        RiskCritical,
		Description:      "Shell command execution",
		RequiresApproval: true,
		IsExternal:       true,
	}
	c.rules["ssh_connect"] = ActionClassification{
		Action:           "ssh_connect",
		RiskLevel:        RiskCritical,
		Description:      "SSH connection to target",
		RequiresApproval: true,
		IsExternal:       true,
	}
	c.rules["c2_beacon"] = ActionClassification{
		Action:           "c2_beacon",
		RiskLevel:        RiskCritical,
		Description:      "C2 beacon operation",
		RequiresApproval: true,
		IsExternal:       true,
	}
	c.rules["db_drop"] = ActionClassification{
		Action:           "db_drop",
		RiskLevel:        RiskCritical,
		Description:      "Database drop operation",
		RequiresApproval: true,
		IsExternal:       true,
		IsDestructive:    true,
	}
	c.rules["db_delete"] = ActionClassification{
		Action:           "db_delete",
		RiskLevel:        RiskCritical,
		Description:      "Database delete operation",
		RequiresApproval: true,
		IsExternal:       true,
		IsDestructive:    true,
	}
	c.rules["data_wipe"] = ActionClassification{
		Action:           "data_wipe",
		RiskLevel:        RiskCritical,
		Description:      "Data wipe operation",
		RequiresApproval: true,
		IsExternal:       true,
		IsDestructive:    true,
	}
	c.rules["service_stop"] = ActionClassification{
		Action:           "service_stop",
		RiskLevel:        RiskHigh,
		Description:      "Service stop operation",
		RequiresApproval: true,
		IsExternal:       true,
		IsDestructive:    true,
	}
}

func (c *ActionClassifier) Classify(action string) ActionClassification {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if classification, exists := c.rules[action]; exists {
		return classification
	}

	upperAction := strings.ToUpper(action)
	destructivePatterns := []string{"DELETE", "DROP", "DESTROY", "WIPE", "ERASE", "REMOVE", "KILL", "TERMINATE"}
	for _, pattern := range destructivePatterns {
		if strings.Contains(upperAction, pattern) {
			return ActionClassification{
				Action:           action,
				RiskLevel:        RiskCritical,
				Description:      "Destructive action (auto-classified)",
				RequiresApproval: true,
				IsExternal:       true,
				IsDestructive:    true,
			}
		}
	}

	return ActionClassification{
		Action:           action,
		RiskLevel:        RiskMedium,
		Description:      "Unclassified action",
		RequiresApproval: false,
		IsExternal:       true,
	}
}

func (c *ActionClassifier) Register(classification ActionClassification) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[classification.Action] = classification
}

func (c *ActionClassifier) RuleCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}

type ModePolicy struct {
	MaxRiskLevel          RiskLevel
	RequireApprovalAbove  RiskLevel
	AllowExternalNetwork  bool
	AllowExploits         bool
	AllowDataExfiltration bool
	AllowDestructive      bool
}

type PolicyEngine struct {
	mu              sync.RWMutex
	currentMode     OperationMode
	classifier      *ActionClassifier
	killSwitch      atomic.Bool
	killSwitchToken string
	approvals       map[string]*ApprovalRequest
	policies        map[OperationMode]ModePolicy
	observers       []ModeObserver
}

type ApprovalRequest struct {
	ID             string
	Action         string
	RiskLevel      RiskLevel
	Description    string
	RequestedAt    time.Time
	ApprovedBy     string
	ApprovedAt     time.Time
	Denied         bool
	Reason         string
	IsDestructive  bool
	ConfirmationID string
}

type ModeObserver interface {
	OnModeChanged(oldMode, newMode OperationMode, actor string)
	OnKillSwitchActivated(actor, reason string)
	OnKillSwitchDeactivated(actor string)
	OnApprovalRequested(req *ApprovalRequest)
	OnApprovalApproved(req *ApprovalRequest)
	OnApprovalDenied(req *ApprovalRequest)
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		currentMode: SafeMode,
		classifier:  NewActionClassifier(),
		approvals:   make(map[string]*ApprovalRequest),
		policies:    defaultPolicies(),
		observers:   make([]ModeObserver, 0),
	}
}

func defaultPolicies() map[OperationMode]ModePolicy {
	return map[OperationMode]ModePolicy{
		ObserveMode: {
			MaxRiskLevel:          RiskNone,
			RequireApprovalAbove:  RiskLow,
			AllowExternalNetwork:  false,
			AllowExploits:         false,
			AllowDataExfiltration: false,
			AllowDestructive:      false,
		},
		SafeMode: {
			MaxRiskLevel:          RiskCritical,
			RequireApprovalAbove:  RiskCritical,
			AllowExternalNetwork:  true,
			AllowExploits:         true,
			AllowDataExfiltration: false,
			AllowDestructive:      false,
		},
		VerifyOnlyMode: {
			MaxRiskLevel:          RiskMedium,
			RequireApprovalAbove:  RiskHigh,
			AllowExternalNetwork:  true,
			AllowExploits:         true,
			AllowDataExfiltration: false,
			AllowDestructive:      false,
		},
		AutonomousMode: {
			MaxRiskLevel:          RiskHigh,
			RequireApprovalAbove:  RiskCritical,
			AllowExternalNetwork:  true,
			AllowExploits:         true,
			AllowDataExfiltration: false,
			AllowDestructive:      false,
		},
		AggressiveMode: {
			MaxRiskLevel:          RiskCritical,
			RequireApprovalAbove:  RiskCritical,
			AllowExternalNetwork:  true,
			AllowExploits:         true,
			AllowDataExfiltration: false,
			AllowDestructive:      false,
		},
		InternalOnlyMode: {
			MaxRiskLevel:          RiskMedium,
			RequireApprovalAbove:  RiskHigh,
			AllowExternalNetwork:  false,
			AllowExploits:         true,
			AllowDataExfiltration: false,
			AllowDestructive:      false,
		},
	}
}

func (e *PolicyEngine) SetMode(mode OperationMode, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.killSwitch.Load() {
		return ErrKillSwitchActive
	}

	oldMode := e.currentMode
	e.currentMode = mode

	logger.Info("safety mode changed", logger.Fields{
		"old_mode": oldMode.String(),
		"new_mode": mode.String(),
		"actor":    actor,
	})

	for _, obs := range e.observers {
		obs.OnModeChanged(oldMode, mode, actor)
	}

	return nil
}

func (e *PolicyEngine) CurrentMode() OperationMode {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentMode
}

func (e *PolicyEngine) ActivateKillSwitch(actor, reason string) string {
	e.killSwitch.Store(true)

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		logger.Error(fmt.Sprintf("[Safety] CRITICAL: Failed to generate kill switch token: %v", err))
		e.killSwitchToken = ""
		return ""
	}
	token := fmt.Sprintf("%x", tokenBytes)

	e.mu.Lock()
	e.killSwitchToken = token
	logger.Error("kill switch activated", logger.Fields{
		"actor":  actor,
		"reason": reason,
	})
	observers := make([]ModeObserver, len(e.observers))
	copy(observers, e.observers)
	e.mu.Unlock()

	for _, obs := range observers {
		obs.OnKillSwitchActivated(actor, reason)
	}
	return token
}

func (e *PolicyEngine) DeactivateKillSwitch(actor, token string) error {
	e.mu.RLock()
	expectedToken := e.killSwitchToken
	e.mu.RUnlock()

	if expectedToken == "" {
		return fmt.Errorf("kill switch deactivation requires authorization token")
	}
	if token == "" || token != expectedToken {
		logger.Warn("kill switch deactivation denied: invalid or missing token", logger.Fields{
			"actor": actor,
		})
		return fmt.Errorf("unauthorized: invalid kill switch deactivation token")
	}

	e.killSwitch.Store(false)

	e.mu.Lock()
	logger.Info("kill switch deactivated", logger.Fields{
		"actor": actor,
	})
	observers := make([]ModeObserver, len(e.observers))
	copy(observers, e.observers)
	e.mu.Unlock()

	for _, obs := range observers {
		obs.OnKillSwitchDeactivated(actor)
	}
	return nil
}

func (e *PolicyEngine) IsKillSwitchActive() bool {
	return e.killSwitch.Load()
}

func (e *PolicyEngine) CheckAction(action string) (bool, error) {
	if e.killSwitch.Load() {
		return false, ErrKillSwitchActive
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	classification := e.classifier.Classify(action)
	policy, exists := e.policies[e.currentMode]
	if !exists {
		return false, fmt.Errorf("no policy for mode %s", e.currentMode.String())
	}

	if classification.IsDestructive && !policy.AllowDestructive {
		return false, fmt.Errorf("%w: destructive action %q requires explicit approval and destructive mode",
			ErrBlockedBySafetyMode, action)
	}

	if classification.RiskLevel > policy.MaxRiskLevel {
		return false, fmt.Errorf("%w: risk level %d exceeds max %d for mode %s",
			ErrBlockedBySafetyMode, classification.RiskLevel, policy.MaxRiskLevel, e.currentMode.String())
	}

	if classification.IsExternal && !policy.AllowExternalNetwork {
		return false, fmt.Errorf("%w: external network not allowed in mode %s",
			ErrBlockedBySafetyMode, e.currentMode.String())
	}

	if classification.RiskLevel >= RiskHigh && !policy.AllowExploits {
		return false, fmt.Errorf("%w: exploits not allowed in mode %s",
			ErrBlockedBySafetyMode, e.currentMode.String())
	}

	if classification.RequiresApproval || classification.RiskLevel > policy.RequireApprovalAbove {
		return false, ErrRequiresApproval
	}

	return true, nil
}

func (e *PolicyEngine) CheckActionWithContext(action string, isExternal bool, target string) (bool, error) {
	if e.killSwitch.Load() {
		return false, ErrKillSwitchActive
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	classification := e.classifier.Classify(action)
	policy, exists := e.policies[e.currentMode]
	if !exists {
		return false, fmt.Errorf("no policy for mode %s", e.currentMode.String())
	}

	if classification.IsExternal {
		isExternal = true
	}

	if classification.IsDestructive && !policy.AllowDestructive {
		return false, fmt.Errorf("%w: destructive action %q requires explicit approval and destructive mode",
			ErrBlockedBySafetyMode, action)
	}

	if classification.RiskLevel > policy.MaxRiskLevel {
		return false, fmt.Errorf("%w: risk level %d exceeds max %d for mode %s",
			ErrBlockedBySafetyMode, classification.RiskLevel, policy.MaxRiskLevel, e.currentMode.String())
	}

	if isExternal && !policy.AllowExternalNetwork {
		return false, fmt.Errorf("%w: external network not allowed in mode %s",
			ErrBlockedBySafetyMode, e.currentMode.String())
	}

	if classification.RiskLevel >= RiskHigh && !policy.AllowExploits {
		return false, fmt.Errorf("%w: exploits not allowed in mode %s",
			ErrBlockedBySafetyMode, e.currentMode.String())
	}

	if classification.RequiresApproval || classification.RiskLevel > policy.RequireApprovalAbove {
		return false, ErrRequiresApproval
	}

	return true, nil
}

func (e *PolicyEngine) RequestApproval(id, action, description string, risk RiskLevel) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	classification := e.classifier.Classify(action)

	e.approvals[id] = &ApprovalRequest{
		ID:            id,
		Action:        action,
		RiskLevel:     risk,
		Description:   description,
		RequestedAt:   time.Now(),
		IsDestructive: classification.IsDestructive,
	}

	logger.Info("approval requested", logger.Fields{
		"id":          id,
		"action":      action,
		"risk_level":  risk,
		"destructive": classification.IsDestructive,
	})

	for _, obs := range e.observers {
		obs.OnApprovalRequested(e.approvals[id])
	}

	return nil
}

func (e *PolicyEngine) Approve(id, approver string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	req, exists := e.approvals[id]
	if !exists {
		return fmt.Errorf("approval %s not found", id)
	}

	req.ApprovedBy = approver
	req.ApprovedAt = time.Now()

	logger.Info("approval granted", logger.Fields{
		"id":       id,
		"action":   req.Action,
		"approver": approver,
	})

	for _, obs := range e.observers {
		obs.OnApprovalApproved(req)
	}

	return nil
}

func (e *PolicyEngine) Deny(id, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	req, exists := e.approvals[id]
	if !exists {
		return fmt.Errorf("approval %s not found", id)
	}

	req.Denied = true
	req.Reason = reason

	delete(e.approvals, id)

	logger.Info("approval denied", logger.Fields{
		"id":     id,
		"reason": reason,
	})

	for _, obs := range e.observers {
		obs.OnApprovalDenied(req)
	}

	return nil
}

func (e *PolicyEngine) GetPendingApprovals() []*ApprovalRequest {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*ApprovalRequest, 0, len(e.approvals))
	for _, req := range e.approvals {
		result = append(result, req)
	}
	return result
}

func (e *PolicyEngine) Subscribe(observer ModeObserver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observers = append(e.observers, observer)
}

type ModeStatus struct {
	Mode             string     `json:"mode"`
	KillSwitchActive bool       `json:"kill_switch_active"`
	PendingApprovals int        `json:"pending_approvals"`
	CurrentPolicy    ModePolicy `json:"current_policy"`
	ClassifierRules  int        `json:"classifier_rules"`
}

func (e *PolicyEngine) GetStatus() ModeStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policy := e.policies[e.currentMode]

	return ModeStatus{
		Mode:             e.currentMode.String(),
		KillSwitchActive: e.killSwitch.Load(),
		PendingApprovals: len(e.approvals),
		CurrentPolicy:    policy,
		ClassifierRules:  e.classifier.RuleCount(),
	}
}

func (e *PolicyEngine) Mode() string {
	return e.CurrentMode().String()
}

func (e *PolicyEngine) AddObserver(observer ModeObserver) {
	e.Subscribe(observer)
}

func (e *PolicyEngine) IsDestructiveAction(action string) bool {
	classification := e.classifier.Classify(action)
	return classification.IsDestructive
}

func RequireDestructiveConfirmation(action string) string {
	return fmt.Sprintf("CONFIRM_DESTRUCTIVE_%s_%d", strings.ToUpper(action), time.Now().UnixNano())
}
