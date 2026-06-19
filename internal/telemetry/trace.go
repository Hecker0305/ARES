package telemetry

import (
	"sync"
	"time"
)

type ToolCallRecord struct {
	Name      string        `json:"name"`
	Params    string        `json:"params"`
	Duration  time.Duration `json:"duration_ms"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

type LLMCallRecord struct {
	PromptTokens     int           `json:"prompt_tokens"`
	CompletionTokens int           `json:"completion_tokens"`
	TotalTokens      int           `json:"total_tokens"`
	Latency          time.Duration `json:"latency_ms"`
	Model            string        `json:"model"`
	Cost             float64       `json:"cost"`
	Timestamp        time.Time     `json:"timestamp"`
}

type IterationRecord struct {
	Number     int       `json:"number"`
	Phase      string    `json:"phase"`
	ToolCalls  int       `json:"tool_calls"`
	LLMCalls   int       `json:"llm_calls"`
	Duration   time.Duration `json:"duration_ms"`
	Decision   string    `json:"decision,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

type ScanTrace struct {
	mu         sync.Mutex
	ScanID     string             `json:"scan_id"`
	Target     string             `json:"target"`
	StartTime  time.Time          `json:"start_time"`
	Iterations []IterationRecord  `json:"iterations"`
	ToolCalls  []ToolCallRecord   `json:"tool_calls"`
	LLMCalls   []LLMCallRecord    `json:"llm_calls"`
	TotalCost  float64            `json:"total_cost"`
	Done       bool               `json:"done"`
}

func New(scanID, target string) *ScanTrace {
	return &ScanTrace{
		ScanID:    scanID,
		Target:    target,
		StartTime: time.Now(),
	}
}

func (t *ScanTrace) AddToolCall(name, params string, duration time.Duration, err string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ToolCalls = append(t.ToolCalls, ToolCallRecord{
		Name: name, Params: params, Duration: duration,
		Error: err, Timestamp: time.Now(),
	})
}

func (t *ScanTrace) AddLLMCall(prompt, completion, total int, latency time.Duration, model string, cost float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.TotalCost += cost
	t.LLMCalls = append(t.LLMCalls, LLMCallRecord{
		PromptTokens: prompt, CompletionTokens: completion, TotalTokens: total,
		Latency: latency, Model: model, Cost: cost, Timestamp: time.Now(),
	})
}

func (t *ScanTrace) EndIteration(num int, phase string, toolCalls, llmCalls int, duration time.Duration, decision string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Iterations = append(t.Iterations, IterationRecord{
		Number: num, Phase: phase, ToolCalls: toolCalls, LLMCalls: llmCalls,
		Duration: duration, Decision: decision, Timestamp: time.Now(),
	})
}

func (t *ScanTrace) MarkDone() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Done = true
}

func (t *ScanTrace) Summary() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	tt := 0
	tc := len(t.ToolCalls)
	lc := len(t.LLMCalls)
	for _, l := range t.LLMCalls {
		tt += l.TotalTokens
	}
	var totalDur time.Duration
	for _, it := range t.Iterations {
		totalDur += it.Duration
	}
	return map[string]interface{}{
		"scan_id":      t.ScanID,
		"target":       t.Target,
		"duration":     totalDur.String(),
		"iterations":   len(t.Iterations),
		"tool_calls":   tc,
		"llm_calls":    lc,
		"total_tokens": tt,
		"total_cost":   t.TotalCost,
		"done":         t.Done,
	}
}
