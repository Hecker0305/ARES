package agent

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ares/engine/internal/llm"
)

type AdaptiveCoordinator struct {
	*Coordinator
	mu           sync.RWMutex
	budget       map[string]float64
	evDecay      map[string]float64
	failureCount map[string]int
	successCount map[string]int
	targetBudget float64
	client       *llm.Client
}

func NewAdaptiveCoordinator(cfg CoordinatorConfig, targetBudget float64, client *llm.Client) *AdaptiveCoordinator {
	coord := NewCoordinator(cfg)
	return &AdaptiveCoordinator{
		Coordinator:  coord,
		budget:       make(map[string]float64),
		evDecay:      make(map[string]float64),
		failureCount: make(map[string]int),
		successCount: make(map[string]int),
		targetBudget: targetBudget,
		client:       client,
	}
}

func (ac *AdaptiveCoordinator) RecordOutcome(target, vulnType string, success bool) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	key := target + ":" + vulnType

	if success {
		ac.successCount[key]++
		if ac.evDecay[key] < 1.0 {
			ac.evDecay[key] += 0.05
		}
	} else {
		ac.failureCount[key]++
		ac.evDecay[key] -= 0.05
		if ac.evDecay[key] < -0.5 {
			ac.evDecay[key] = -0.5
		}
	}

	total := ac.successCount[key] + ac.failureCount[key]
	if total > 5 {
		failRate := float64(ac.failureCount[key]) / float64(total)
		if failRate > 0.7 {
			ac.budget[key] = 0
		} else if failRate > 0.5 {
			ac.budget[key] = ac.targetBudget * 0.3
		} else {
			ac.budget[key] = ac.targetBudget
		}
	}
}

func (ac *AdaptiveCoordinator) ShouldAllocate(target, vulnType string) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	key := target + ":" + vulnType
	allocation := ac.budget[key]
	if allocation <= 0 {
		return false
	}

	if ac.evDecay[key] < -0.3 {
		total := ac.successCount[key] + ac.failureCount[key]
		if total > 3 {
			return false
		}
	}

	return true
}

func (ac *AdaptiveCoordinator) Reallocate(target, currentVulnType string, candidates []string) string {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	key := target + ":" + currentVulnType
	total := ac.successCount[key] + ac.failureCount[key]
	if total > 0 {
		failRate := float64(ac.failureCount[key]) / float64(total)
		if failRate > 0.5 && len(candidates) > 0 {
			for _, c := range candidates {
				cKey := target + ":" + c
				cAllocation := ac.budget[cKey]
				if cAllocation <= 0 {
					ac.budget[cKey] = ac.targetBudget * 0.5
				}
			}
		}
	}

	var best string
	bestScore := -2.0
	for _, c := range candidates {
		cKey := target + ":" + c
		score := ac.evDecay[cKey] + ac.budget[cKey]/ac.targetBudget
		if score > bestScore {
			bestScore = score
			best = c
		}
	}
	return best
}

func (ac *AdaptiveCoordinator) BuildAdaptivePrompt(target string, phase Phase, targets []string) string {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	var activeVulns []string
	var deadVulns []string

	for key, b := range ac.budget {
		if b <= 0 {
			parts := strings.Split(key, ":")
			if len(parts) == 2 {
				deadVulns = append(deadVulns, parts[1])
			}
		} else {
			parts := strings.Split(key, ":")
			if len(parts) == 2 {
				activeVulns = append(activeVulns, parts[1])
			}
		}
	}

	prompt := fmt.Sprintf("[Adaptive Scan] Target: %s | Phase: %s\n", target, phase)
	if len(activeVulns) > 0 {
		prompt += fmt.Sprintf("Active vuln classes (EV>0): %s\n", strings.Join(activeVulns, ", "))
	}
	if len(deadVulns) > 0 {
		prompt += fmt.Sprintf("Avoid (low EV): %s — reallocate to: SSRF, IDOR, path_traversal\n", strings.Join(deadVulns, ", "))
	}
	if len(targets) > 0 {
		prompt += fmt.Sprintf("Scope targets: %s\n", strings.Join(targets, ", "))
	}
	prompt += "Focus on confirming findings with extraction proof. Budget reallocated from dead paths to high-value targets.\n"

	return prompt
}

func (ac *AdaptiveCoordinator) LoadFromMemory(target string, memStore interface{ GetPSuccess(target, vulnType string) float64 }) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	vulnTypes := []string{"sqli", "xss", "lfi", "rce", "ssrf", "ssti", "idor", "path_traversal", "xxe", "open_redirect", "cmd_injection"}
	for _, vt := range vulnTypes {
		key := target + ":" + vt
		p := memStore.GetPSuccess(target, vt)
		ac.budget[key] = p * ac.targetBudget
		ac.evDecay[key] = p - 0.5
	}
}

func (ac *AdaptiveCoordinator) Status() map[string]interface{} {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	var activePaths int
	var deadPaths int
	var totalSuccess, totalFail int

	for key, b := range ac.budget {
		if b <= 0 {
			deadPaths++
		} else {
			activePaths++
		}
		parts := strings.Split(key, ":")
		if len(parts) == 2 {
			totalSuccess += ac.successCount[key]
			totalFail += ac.failureCount[key]
		}
	}

	status := map[string]interface{}{
		"active_paths": activePaths,
		"dead_paths":   deadPaths,
		"total_successes": totalSuccess,
		"total_failures": totalFail,
	}
	return status
}