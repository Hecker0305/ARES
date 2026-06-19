package policy

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Action string

const (
	ActionNetworkScan  Action = "network_scan"
	ActionFileRead     Action = "file_read"
	ActionFileWrite    Action = "file_write"
	ActionExecCommand  Action = "exec_command"
	ActionWebRequest   Action = "web_request"
	ActionModifySystem Action = "modify_system"
	ActionAccessSecret Action = "access_secret"
	ActionExfiltrate   Action = "exfiltrate"
	ActionPivot        Action = "pivot"
	ActionInstallTool  Action = "install_tool"
)

type Resource string

const (
	ResourceNetwork    Resource = "network"
	ResourceFilesystem Resource = "filesystem"
	ResourceProcess    Resource = "process"
	ResourceSecret     Resource = "secret"
	ResourceAPI        Resource = "api"
	ResourceBrowser    Resource = "browser"
	ResourceC2         Resource = "c2"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
	EffectWarn  Effect = "warn"
	EffectAudit Effect = "audit"
)

type PermissionLevel int

const (
	LevelNone    PermissionLevel = 0
	LevelRead    PermissionLevel = 1
	LevelWrite   PermissionLevel = 2
	LevelExecute PermissionLevel = 3
	LevelAdmin   PermissionLevel = 4
)

type Rule struct {
	ID          string       `json:"id"`
	Actions     []Action     `json:"actions"`
	Resources   []Resource   `json:"resources"`
	Targets     []string     `json:"targets,omitempty"`
	Effect      Effect       `json:"effect"`
	Priority    int          `json:"priority"`
	Reason      string       `json:"reason"`
	Constraints []Constraint `json:"constraints,omitempty"`
}

type Constraint struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ExecutionPolicy struct {
	Name          string `json:"name"`
	MaxParallel   int    `json:"max_parallel"`
	TimeoutSec    int    `json:"timeout_sec"`
	AllowLoopback bool   `json:"allow_loopback"`
	AllowNetwork  bool   `json:"allow_network"`
	AllowExec     bool   `json:"allow_exec"`
	MaxFileSize   int64  `json:"max_file_size"`
}

type EvaluationResult struct {
	Allowed     bool   `json:"allowed"`
	Effect      Effect `json:"effect"`
	MatchedRule *Rule  `json:"matched_rule,omitempty"`
	Reason      string `json:"reason"`
}

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    Action    `json:"action"`
	Resource  Resource  `json:"resource"`
	Target    string    `json:"target"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason"`
}

type attemptKey struct {
	target string
	action Action
}

type attemptRecord struct {
	count   int
	expires time.Time
}

type PolicyEngine struct {
	mu             sync.RWMutex
	rules          []Rule
	auditLog       []AuditEntry
	defaultEffect  Effect
	allowMustAllow bool
	attempts       map[attemptKey]*attemptRecord
}

func (pe *PolicyEngine) EnableMustAllow(enabled bool) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.allowMustAllow = enabled
}

func New() *PolicyEngine {
	return &PolicyEngine{
		rules:         make([]Rule, 0),
		defaultEffect: EffectDeny,
		attempts:      make(map[attemptKey]*attemptRecord),
	}
}

func NewPermissive() *PolicyEngine {
	return &PolicyEngine{
		rules:         make([]Rule, 0),
		defaultEffect: EffectWarn,
		attempts:      make(map[attemptKey]*attemptRecord),
	}
}

func (pe *PolicyEngine) AddRule(rules ...Rule) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	for i := range rules {
		filteredActions := make([]Action, 0, len(rules[i].Actions))
		for _, a := range rules[i].Actions {
			if a == "*" {
				continue
			}
			filteredActions = append(filteredActions, a)
		}
		if len(filteredActions) == 0 {
			continue
		}
		rules[i].Actions = filteredActions

		filteredResources := make([]Resource, 0, len(rules[i].Resources))
		for _, r := range rules[i].Resources {
			if r == "*" {
				continue
			}
			filteredResources = append(filteredResources, r)
		}
		if len(filteredResources) == 0 {
			continue
		}
		rules[i].Resources = filteredResources

		filteredTargets := make([]string, 0, len(rules[i].Targets))
		for _, t := range rules[i].Targets {
			if t == "*" {
				continue
			}
			filteredTargets = append(filteredTargets, t)
		}
		rules[i].Targets = filteredTargets
	}
	pe.rules = append(pe.rules, rules...)
	sort.SliceStable(pe.rules, func(i, j int) bool {
		return pe.rules[i].Priority > pe.rules[j].Priority
	})
}

func (pe *PolicyEngine) SetDefaultEffect(e Effect) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.defaultEffect = e
}

func (pe *PolicyEngine) Evaluate(action Action, resource Resource, target string) EvaluationResult {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.allowMustAllow {
		for _, rule := range pe.rules {
			if rule.Effect != EffectAllow {
				continue
			}
			if !pe.actionMatches(rule, action) {
				continue
			}
			if !pe.resourceMatches(rule, resource) {
				continue
			}
			if len(rule.Targets) > 0 && !pe.targetMatches(rule, target) {
				continue
			}
			allConstraintsMet := true
			for _, c := range rule.Constraints {
				if !pe.evaluateConstraint(c, action, resource, target) {
					allConstraintsMet = false
					break
				}
			}
			if !allConstraintsMet {
				continue
			}
			return EvaluationResult{
				Allowed:     true,
				Effect:      EffectAllow,
				MatchedRule: &rule,
				Reason:      rule.Reason,
			}
		}
	}

	for _, rule := range pe.rules {
		if !pe.actionMatches(rule, action) {
			continue
		}
		if !pe.resourceMatches(rule, resource) {
			continue
		}
		if len(rule.Targets) > 0 && !pe.targetMatches(rule, target) {
			continue
		}

		allConstraintsMet := true
		for _, c := range rule.Constraints {
			if !pe.evaluateConstraint(c, action, resource, target) {
				allConstraintsMet = false
				break
			}
		}
		if !allConstraintsMet {
			continue
		}

		switch rule.Effect {
		case EffectAllow:
			return EvaluationResult{
				Allowed:     true,
				Effect:      EffectAllow,
				MatchedRule: &rule,
				Reason:      rule.Reason,
			}
		case EffectDeny:
			return EvaluationResult{
				Allowed:     false,
				Effect:      EffectDeny,
				MatchedRule: &rule,
				Reason:      rule.Reason,
			}
		case EffectWarn:
			return EvaluationResult{
				Allowed:     true,
				Effect:      EffectWarn,
				MatchedRule: &rule,
				Reason:      rule.Reason,
			}
		case EffectAudit:
			return EvaluationResult{
				Allowed:     true,
				Effect:      EffectAudit,
				MatchedRule: &rule,
				Reason:      rule.Reason,
			}
		}
	}

	switch pe.defaultEffect {
	case EffectAllow:
		return EvaluationResult{Allowed: true, Effect: EffectAllow, Reason: "default allow"}
	case EffectWarn:
		return EvaluationResult{Allowed: true, Effect: EffectWarn, Reason: "default warn"}
	default:
		return EvaluationResult{Allowed: false, Effect: EffectDeny, Reason: "default deny"}
	}
}

func (pe *PolicyEngine) actionMatches(rule Rule, action Action) bool {
	for _, a := range rule.Actions {
		if a == action {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) resourceMatches(rule Rule, resource Resource) bool {
	for _, r := range rule.Resources {
		if r == resource {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) targetMatches(rule Rule, target string) bool {
	for _, t := range rule.Targets {
		if t == target || strings.HasSuffix(target, "."+t) {
			return true
		}
		parsed := net.ParseIP(target)
		if parsed == nil {
			ips, err := net.LookupIP(target)
			if err == nil && len(ips) > 0 {
				parsed = ips[0]
			}
		}
		if parsed != nil {
			_, cidr, err := net.ParseCIDR(t)
			if err == nil && cidr.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

func (pe *PolicyEngine) RecordAttempt(target string, action Action) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	key := attemptKey{target: target, action: action}
	rec, ok := pe.attempts[key]
	if !ok || time.Now().After(rec.expires) {
		rec = &attemptRecord{count: 0, expires: time.Now().Add(24 * time.Hour)}
		pe.attempts[key] = rec
	}
	rec.count++
}

func (pe *PolicyEngine) AttemptCount(target string, action Action) int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	rec, ok := pe.attempts[attemptKey{target: target, action: action}]
	if !ok || time.Now().After(rec.expires) {
		return 0
	}
	return rec.count
}

func (pe *PolicyEngine) ResetAttempts(target string, action Action) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	delete(pe.attempts, attemptKey{target: target, action: action})
}

func (pe *PolicyEngine) evaluateConstraint(c Constraint, action Action, resource Resource, target string) bool {
	switch c.Type {
	case "max_attempts":
		limit := 10
		if c.Value != "" {
			if parsed, err := strconv.Atoi(c.Value); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		current := pe.AttemptCount(target, action)
		if current >= limit {
			return false
		}
		return true
	case "require_approval":
		return c.Value == "granted"
	case "no_loopback":
		return !strings.Contains(target, "127.0.0.1") && !strings.Contains(target, "localhost") &&
			!strings.HasPrefix(target, "127.") && target != "::1"
	case "no_private":
		ip := net.ParseIP(target)
		if ip == nil {
			if host, _, err := net.SplitHostPort(target); err == nil {
				ip = net.ParseIP(host)
			}
		}
		if ip != nil {
			return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
		}
		return true
	default:
		return true
	}
}

func (pe *PolicyEngine) AddOverrideRule(rule Rule) error {
	if rule.Priority > 100 {
		return fmt.Errorf("cannot add rule with priority > 100 (max security priority)")
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.rules = append(pe.rules, rule)
	return nil
}

func (pe *PolicyEngine) Rules() []Rule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	result := make([]Rule, len(pe.rules))
	copy(result, pe.rules)
	return result
}

func (pe *PolicyEngine) IsActionAllowed(action Action) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	denied := false
	for _, rule := range pe.rules {
		for _, a := range rule.Actions {
			if a == action {
				switch rule.Effect {
				case EffectAllow:
					return true
				case EffectDeny:
					denied = true
				}
			}
		}
	}
	return !denied
}

func (pe *PolicyEngine) ValidateExecutionPolicy(policy ExecutionPolicy) error {
	if policy.MaxParallel <= 0 {
		return fmt.Errorf("max_parallel must be positive")
	}
	if policy.TimeoutSec <= 0 {
		return fmt.Errorf("timeout_sec must be positive")
	}
	return nil
}

var DefaultSafePolicy = ExecutionPolicy{
	Name:          "safe",
	MaxParallel:   3,
	TimeoutSec:    120,
	AllowLoopback: false,
	AllowNetwork:  true,
	AllowExec:     false,
	MaxFileSize:   1 << 20,
}

var DefaultRestrictedPolicy = ExecutionPolicy{
	Name:          "restricted",
	MaxParallel:   1,
	TimeoutSec:    30,
	AllowLoopback: false,
	AllowNetwork:  false,
	AllowExec:     false,
	MaxFileSize:   1 << 10,
}

var DefaultStandardPolicy = ExecutionPolicy{
	Name:          "standard",
	MaxParallel:   5,
	TimeoutSec:    300,
	AllowLoopback: true,
	AllowNetwork:  true,
	AllowExec:     true,
	MaxFileSize:   10 << 20,
}

func SecurityDefaults() *PolicyEngine {
	pe := New()
	pe.AddRule(Rule{
		ID:        "block-metadata-ssrf",
		Actions:   []Action{ActionWebRequest, ActionNetworkScan},
		Resources: []Resource{ResourceNetwork},
		Targets:   []string{"169.254.169.254", "metadata.google.internal", "100.100.100.200", "100.100.100.204"},
		Effect:    EffectDeny,
		Priority:  100,
		Reason:    "cloud metadata endpoints are never accessible",
	})
	pe.AddRule(Rule{
		ID:          "block-private-network",
		Actions:     []Action{ActionWebRequest, ActionNetworkScan},
		Resources:   []Resource{ResourceNetwork},
		Targets:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"},
		Constraints: []Constraint{{Type: "no_private"}},
		Effect:      EffectDeny,
		Priority:    100,
		Reason:      "private IP ranges are not accessible",
	})
	pe.AddRule(Rule{
		ID:        "deny-destructive-filesystem",
		Actions:   []Action{ActionFileWrite},
		Resources: []Resource{ResourceFilesystem},
		Effect:    EffectDeny,
		Priority:  100,
		Reason:    "destructive filesystem operations are denied by default",
	})
	pe.AddRule(Rule{
		ID:        "deny-exfiltration",
		Actions:   []Action{ActionExfiltrate},
		Resources: []Resource{ResourceNetwork, ResourceFilesystem},
		Effect:    EffectDeny,
		Priority:  100,
		Reason:    "data exfiltration is denied by default",
	})
	pe.AddRule(Rule{
		ID:        "deny-system-modification",
		Actions:   []Action{ActionModifySystem},
		Resources: []Resource{ResourceProcess},
		Effect:    EffectDeny,
		Priority:  100,
		Reason:    "system modification is denied by default",
	})
	pe.AddRule(Rule{
		ID:        "audit-network-scans",
		Actions:   []Action{ActionNetworkScan},
		Resources: []Resource{ResourceNetwork},
		Effect:    EffectAudit,
		Priority:  50,
		Reason:    "network scans are audited",
	})
	pe.AddRule(Rule{
		ID:        "warn-web-requests",
		Actions:   []Action{ActionWebRequest},
		Resources: []Resource{ResourceAPI},
		Effect:    EffectWarn,
		Priority:  50,
		Reason:    "outbound web requests must be verified",
	})
	pe.AddRule(Rule{
		ID:        "allow-reads",
		Actions:   []Action{ActionFileRead},
		Resources: []Resource{ResourceFilesystem},
		Effect:    EffectAllow,
		Priority:  10,
		Reason:    "file reads are allowed",
	})
	pe.AddRule(Rule{
		ID:          "allow-in-scope-network",
		Actions:     []Action{ActionNetworkScan, ActionWebRequest},
		Resources:   []Resource{ResourceNetwork, ResourceAPI},
		Constraints: []Constraint{{Type: "no_private"}},
		Effect:      EffectAllow,
		Priority:    10,
		Reason:      "in-scope network access allowed",
	})
	return pe
}
