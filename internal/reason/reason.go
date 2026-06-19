package reason

import (
	"github.com/ares/engine/internal/uuid"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ReasoningStep represents a single step in the agent's reasoning chain.
type ReasoningStep struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Phase      string            `json:"phase"`
	Action     string            `json:"action"`
	Thought    string            `json:"thought"`
	Decision   string            `json:"decision"`
	Evidence   map[string]string `json:"evidence,omitempty"`
	Confidence float64           `json:"confidence"`
	Duration   time.Duration     `json:"duration_ms"`
	ToolUsed   string            `json:"tool_used,omitempty"`
	ToolOutput string            `json:"tool_output,omitempty"`
	NextAction string            `json:"next_action"`
	RiskLevel  string            `json:"risk_level"`
}

// ReasoningTrace is the full chain of reasoning for a scan.
type ReasoningTrace struct {
	TraceID      string          `json:"trace_id"`
	ScanID       string          `json:"scan_id"`
	Target       string          `json:"target"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  time.Time       `json:"completed_at"`
	Steps        []ReasoningStep `json:"steps"`
	Summary      string          `json:"summary"`
	AttackPath   []string        `json:"attack_path"`
	Findings     int             `json:"findings_count"`
	CriticalPath bool            `json:"critical_path_found"`
}

// Engine manages reasoning traces for exposure via dashboard and API.
type Engine struct {
	mu        sync.RWMutex
	traces    map[string]*ReasoningTrace
	active    map[string]string // scanID -> traceID
	maxTraces int
}

// New creates a new reasoning trace engine.
func New(maxTraces int) *Engine {
	if maxTraces == 0 {
		maxTraces = 1000
	}
	return &Engine{
		traces:    make(map[string]*ReasoningTrace),
		active:    make(map[string]string),
		maxTraces: maxTraces,
	}
}

// StartTrace begins a new reasoning trace for a scan.
func (e *Engine) StartTrace(scanID, target string) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	traceID := uuid.New()
	trace := &ReasoningTrace{
		TraceID:    traceID,
		ScanID:     scanID,
		Target:     target,
		StartedAt:  time.Now(),
		Steps:      make([]ReasoningStep, 0, 64),
		AttackPath: make([]string, 0),
	}
	e.traces[traceID] = trace
	e.active[scanID] = traceID

	// Evict oldest if at capacity
	if len(e.traces) > e.maxTraces {
		oldest := ""
		oldestTime := time.Now()
		for tid, t := range e.traces {
			if !t.CompletedAt.IsZero() && t.CompletedAt.Before(oldestTime) {
				oldest = tid
				oldestTime = t.CompletedAt
			}
		}
		if oldest != "" {
			delete(e.traces, oldest)
		}
	}

	return traceID
}

// AddStep appends a reasoning step to the active trace.
func (e *Engine) AddStep(scanID string, step ReasoningStep) {
	e.mu.Lock()
	defer e.mu.Unlock()

	traceID, ok := e.active[scanID]
	if !ok {
		return
	}
	trace, ok := e.traces[traceID]
	if !ok {
		return
	}

	step.ID = fmt.Sprintf("step-%d", len(trace.Steps)+1)
	step.Timestamp = time.Now()
	trace.Steps = append(trace.Steps, step)

	if step.Evidence != nil && len(step.Evidence) > 0 {
		trace.AttackPath = append(trace.AttackPath, step.Action)
	}
	if step.RiskLevel == "critical" {
		trace.CriticalPath = true
	}
}

// CompleteTrace marks a trace as complete.
func (e *Engine) CompleteTrace(scanID, summary string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	traceID, ok := e.active[scanID]
	if !ok {
		return
	}
	trace, ok := e.traces[traceID]
	if !ok {
		return
	}

	trace.CompletedAt = time.Now()
	trace.Summary = summary
	trace.Findings = 0
	for _, s := range trace.Steps {
		if s.Evidence != nil && len(s.Evidence) > 0 {
			trace.Findings++
		}
	}

	delete(e.active, scanID)
}

// GetTrace returns a reasoning trace by ID.
func (e *Engine) GetTrace(traceID string) *ReasoningTrace {
	e.mu.RLock()
	defer e.mu.RUnlock()
	t := e.traces[traceID]
	if t == nil {
		return nil
	}
	cp := *t
	cp.Steps = make([]ReasoningStep, len(t.Steps))
	copy(cp.Steps, t.Steps)
	return &cp
}

// GetTraceByScanID returns the active or last trace for a scan.
func (e *Engine) GetTraceByScanID(scanID string) *ReasoningTrace {
	e.mu.RLock()
	defer e.mu.RUnlock()

	traceID, ok := e.active[scanID]
	if !ok {
		// Find last completed trace for this scan
		var last *ReasoningTrace
		for _, t := range e.traces {
			if t.ScanID == scanID && !t.CompletedAt.IsZero() {
				if last == nil || t.CompletedAt.After(last.CompletedAt) {
					last = t
				}
			}
		}
		return last
	}
	return e.traces[traceID]
}

// ListTraces returns all traces (optionally filtered by scanID).
func (e *Engine) ListTraces(scanID string) []*ReasoningTrace {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*ReasoningTrace
	for _, t := range e.traces {
		if scanID == "" || t.ScanID == scanID {
			cp := *t
			cp.Steps = make([]ReasoningStep, len(t.Steps))
			copy(cp.Steps, t.Steps)
			result = append(result, &cp)
		}
	}
	return result
}

// ExportJSON exports a trace as JSON bytes.
func (e *Engine) ExportJSON(traceID string) ([]byte, error) {
	t := e.GetTrace(traceID)
	if t == nil {
		return nil, fmt.Errorf("trace %s not found", traceID)
	}
	return json.MarshalIndent(t, "", "  ")
}

// Stats returns reasoning engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	totalSteps := 0
	criticalPaths := 0
	for _, t := range e.traces {
		totalSteps += len(t.Steps)
		if t.CriticalPath {
			criticalPaths++
		}
	}

	return map[string]interface{}{
		"total_traces":        len(e.traces),
		"active_scans":        len(e.active),
		"total_steps":         totalSteps,
		"critical_paths":      criticalPaths,
		"avg_steps_per_trace": float64(totalSteps) / maxFloat64(float64(len(e.traces)), 1),
	}
}

func maxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
