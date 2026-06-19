package llmrouting

import (
	"fmt"
	"sync"
	"time"
)

type TaskType int

const (
	TaskPlanning     TaskType = 0
	TaskVerification TaskType = 1
	TaskCodeAnalysis TaskType = 2
	TaskReasoning    TaskType = 3
	TaskSummarize    TaskType = 4
	TaskReport       TaskType = 5
)

type ModelConfig struct {
	Name      string     `json:"name"`
	Provider  string     `json:"provider"`
	MaxTokens int        `json:"max_tokens"`
	CostPer1K float64    `json:"cost_per_1k"`
	TaskTypes []TaskType `json:"task_types"`
}

type latencyStats struct {
	total time.Duration
	count int64
}

type accuracyStats struct {
	success int64
	fail    int64
}

type Router struct {
	mu          sync.Mutex
	models      map[string]ModelConfig
	routing     map[TaskType][]string
	costBudget  float64
	costSpent   float64
	costHistory []CostEntry

	latency  map[string]*latencyStats
	accuracy map[string]*accuracyStats
}

type CostEntry struct {
	ModelName string  `json:"model_name"`
	Tokens    int     `json:"tokens"`
	Cost      float64 `json:"cost"`
	TaskType  string  `json:"task_type"`
}

func New() *Router {
	r := &Router{
		models:     make(map[string]ModelConfig),
		routing:    make(map[TaskType][]string),
		costBudget: 10.0,
		costSpent:  0.0,
		latency:    make(map[string]*latencyStats),
		accuracy:   make(map[string]*accuracyStats),
	}
	r.setDefaults()
	return r
}

func (r *Router) SetCostBudget(budget float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.costBudget = budget
}

func (r *Router) TrackCost(modelName string, tokens int, taskType string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg, ok := r.models[modelName]
	if !ok {
		return
	}
	cost := float64(tokens) / 1000.0 * cfg.CostPer1K
	r.costSpent += cost
	r.costHistory = append(r.costHistory, CostEntry{
		ModelName: modelName,
		Tokens:    tokens,
		Cost:      cost,
		TaskType:  taskType,
	})
	if len(r.costHistory) > 1000 {
		r.costHistory = r.costHistory[500:]
	}
}

func (r *Router) GetCostSpent() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.costSpent
}

func (r *Router) GetCostHistory() []CostEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CostEntry, len(r.costHistory))
	copy(out, r.costHistory)
	return out
}

func (r *Router) setDefaults() {
	r.Register(ModelConfig{
		Name: "qwen2.5-coder:14b", Provider: "ollama",
		MaxTokens: 4096, CostPer1K: 0,
		TaskTypes: []TaskType{TaskCodeAnalysis, TaskVerification},
	})
	r.Register(ModelConfig{
		Name: "llama3.1:70b", Provider: "ollama",
		MaxTokens: 8192, CostPer1K: 0,
		TaskTypes: []TaskType{TaskPlanning, TaskReasoning, TaskReport},
	})
	r.Register(ModelConfig{
		Name: "deepseek-coder:6.7b", Provider: "ollama",
		MaxTokens: 4096, CostPer1K: 0,
		TaskTypes: []TaskType{TaskSummarize, TaskCodeAnalysis},
	})
	r.Register(ModelConfig{
		Name: "qwen3:latest", Provider: "ollama",
		MaxTokens: 8192, CostPer1K: 0,
		TaskTypes: []TaskType{TaskPlanning, TaskReasoning, TaskCodeAnalysis, TaskReport},
	})
}

func (r *Router) Register(cfg ModelConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.models[cfg.Name] = cfg
	for _, tt := range cfg.TaskTypes {
		r.routing[tt] = append(r.routing[tt], cfg.Name)
	}
}

func (r *Router) RecordLatency(modelName string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.latency[modelName]
	if !ok {
		s = &latencyStats{}
		r.latency[modelName] = s
	}
	s.total += d
	s.count++
}

func (r *Router) RecordAccuracy(modelName string, success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.accuracy[modelName]
	if !ok {
		s = &accuracyStats{}
		r.accuracy[modelName] = s
	}
	if success {
		s.success++
	} else {
		s.fail++
	}
}

func (r *Router) AvgLatency(modelName string) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.latency[modelName]
	if !ok || s.count == 0 {
		return 0, false
	}
	return s.total / time.Duration(s.count), true
}

func (r *Router) AccuracyRate(modelName string) (float64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.accuracy[modelName]
	if !ok || (s.success+s.fail) == 0 {
		return 0, false
	}
	return float64(s.success) / float64(s.success+s.fail), true
}

func (r *Router) Select(task TaskType) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.costSpent >= r.costBudget {
		return "", fmt.Errorf("cost budget exceeded: spent %.4f of %.4f", r.costSpent, r.costBudget)
	}

	models, ok := r.routing[task]
	if !ok || len(models) == 0 {
		r.fallback(task)
		models = r.routing[task]
	}
	if len(models) == 0 {
		return "", fmt.Errorf("no model available for task type %d", task)
	}

	var best string
	bestScore := -1.0
	for _, name := range models {
		cfg, exists := r.models[name]
		if !exists {
			continue
		}
		if cfg.CostPer1K > 0 && r.costSpent+cfg.CostPer1K > r.costBudget {
			continue
		}
		score := 0.0
		if s, ok := r.accuracy[name]; ok && (s.success+s.fail) > 0 {
			score = float64(s.success) / float64(s.success+s.fail)
		}
		if ls, ok := r.latency[name]; ok && ls.count > 0 {
			avg := ls.total / time.Duration(ls.count)
			latencyScore := 1.0 - (float64(avg) / 1e10)
			if latencyScore < 0 {
				latencyScore = 0
			}
			score = score*0.6 + latencyScore*0.4
		}
		if score > bestScore {
			bestScore = score
			best = name
		}
	}
	if best != "" {
		return best, nil
	}

	for _, name := range models {
		if cfg, exists := r.models[name]; exists {
			if cfg.CostPer1K <= 0 || r.costSpent+cfg.CostPer1K <= r.costBudget {
				return name, nil
			}
		}
	}

	return "", fmt.Errorf("no model within budget for task type %d", task)
}

func (r *Router) fallback(task TaskType) {
	for name, cfg := range r.models {
		for _, tt := range cfg.TaskTypes {
			if tt == task {
				r.routing[task] = append(r.routing[task], name)
				return
			}
		}
	}
}

func (r *Router) ModelsFor(task TaskType) []ModelConfig {
	r.mu.Lock()
	defer r.mu.Unlock()
	modelNames := r.routing[task]
	var cfgs []ModelConfig
	for _, name := range modelNames {
		if cfg, ok := r.models[name]; ok {
			cfgs = append(cfgs, cfg)
		}
	}
	return cfgs
}

func (r *Router) AllModels() []ModelConfig {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ModelConfig
	for _, cfg := range r.models {
		out = append(out, cfg)
	}
	return out
}

func TaskTypeString(t TaskType) string {
	switch t {
	case TaskPlanning:
		return "planning"
	case TaskVerification:
		return "verification"
	case TaskCodeAnalysis:
		return "code_analysis"
	case TaskReasoning:
		return "reasoning"
	case TaskSummarize:
		return "summarization"
	case TaskReport:
		return "reporting"
	default:
		return "unknown"
	}
}
