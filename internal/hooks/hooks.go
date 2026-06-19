package hooks

import (
	"fmt"
	"sync"
	"time"
)

type HookResult struct {
	Blocked bool
	Message string
}

type HookType string

const (
	OnToolCallHook   HookType = "OnToolCall"
	OnToolResultHook HookType = "OnToolResult"
	OnFinishHook     HookType = "OnFinish"
	OnStuckCheckHook HookType = "OnStuckCheck"
)

type HookEvent struct {
	ScanID   string
	ToolName string
	Params   interface{}
	History  []string
	Result   string
	Error    string
	State    ScanState
}

type HookFunc func(HookEvent) HookResult

type Registry struct {
	mu    sync.RWMutex
	hooks map[HookType][]HookFunc
	count map[HookType]int
}

func NewRegistry() *Registry {
	return &Registry{
		hooks: make(map[HookType][]HookFunc),
		count: make(map[HookType]int),
	}
}

func (r *Registry) Register(t HookType, fn HookFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks[t] = append(r.hooks[t], fn)
	r.count[t]++
}

func (r *Registry) Fire(t HookType, e HookEvent) HookResult {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, fn := range r.hooks[t] {
		result := fn(e)
		if result.Blocked {
			return result
		}
	}
	return HookResult{}
}

type ScanState struct {
	UnverifiedCount int
	ConfirmedCount  int
	StartTime       time.Time
	TotalIterations int
	LastCommand     string
	LastTool        string
}

func OnFinishAttempt(s ScanState) HookResult {
	if s.UnverifiedCount > 0 {
		return HookResult{
			Blocked: true,
			Message: fmt.Sprintf(
				"BLOCKED: %d unverified finding(s). Prove each with working exploit, evidence, repeatability, or discard before finish.",
				s.UnverifiedCount,
			),
		}
	}
	if s.ConfirmedCount == 0 && time.Since(s.StartTime) < 10*time.Minute {
		return HookResult{
			Blocked: true,
			Message: "BLOCKED: No confirmed findings yet. Continue testing — try SQLi, XSS, IDOR, auth bypass, SSRF, LFI, command injection.",
		}
	}
	return HookResult{}
}

func OnRepeatCommand(cmd string, history []string) HookResult {
	count := 0
	for _, h := range history {
		if h == cmd {
			count++
		}
	}
	if count >= 3 {
		return HookResult{
			Blocked: true,
			Message: fmt.Sprintf(
				"BLOCKED: Command repeated %d times: %q\nTry a different tool, endpoint, or payload.",
				count, cmd,
			),
		}
	}
	return HookResult{}
}

func CheckStuck(scanID string, sc interface{}) HookResult {
	type stuckable interface{ UnverifiedCount() int }
	if s, ok := sc.(stuckable); ok && s.UnverifiedCount() > 10 {
		return HookResult{
			Blocked: true,
			Message: fmt.Sprintf(
				"DEEP STUCK: %d unverified findings. Switch tactics — try different vuln classes, different endpoints, or skip speculative findings. Focus on confirming one finding at a time.",
				s.UnverifiedCount(),
			),
		}
	}
	return HookResult{}
}

func OnStuckCheck(sc interface{}, iterations int) HookResult {
	if iterations%20 == 0 && iterations > 0 {
		type st interface {
			ConfirmedCount() int
			UnverifiedCount() int
		}
		if s, ok := sc.(st); ok {
			if s.ConfirmedCount() == 0 && s.UnverifiedCount() == 0 {
				return HookResult{
					Blocked: true,
					Message: "STUCK CHECK: No findings after many iterations. Switch to nuclei scan, sqlmap, or dalfox. Run: terminal_execute command=\"nuclei -u https://TARGET -severity critical,high -silent | head -50\"",
				}
			}
		}
	}
	return HookResult{}
}
