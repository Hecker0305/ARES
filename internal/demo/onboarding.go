package demo

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type OnboardingStep int

const (
	StepWelcome     OnboardingStep = 1
	StepLLMSetup    OnboardingStep = 2
	StepFirstScan   OnboardingStep = 3
	StepViewResults OnboardingStep = 4
	StepExplore     OnboardingStep = 5
	StepComplete    OnboardingStep = 6
)

type StepInfo struct {
	Number      OnboardingStep `json:"number"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
}

var OnboardingSteps = []StepInfo{
	{StepWelcome, "Welcome to ARES", "Overview of the ARES security scanning engine and what you can accomplish."},
	{StepLLMSetup, "LLM Configuration", "Connect to your LLM provider (Ollama, OpenAI, Anthropic, etc.) to power AI-driven scanning."},
	{StepFirstScan, "Your First Scan", "Run a guided scan against a demo target to see ARES in action."},
	{StepViewResults, "Review Findings", "Explore the vulnerabilities discovered, severity ratings, and remediation guidance."},
	{StepExplore, "Explore Features", "Learn about advanced ARES features: C2 integration, federated intelligence, compliance reporting."},
}

type OnboardingState struct {
	mu          sync.Mutex
	CurrentStep OnboardingStep `json:"current_step"`
	Skipped     bool           `json:"skipped"`
	Completed   bool           `json:"completed"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt time.Time      `json:"completed_at,omitempty"`
}

func NewOnboardingState() *OnboardingState {
	return &OnboardingState{
		CurrentStep: StepWelcome,
		StartedAt:   time.Now(),
	}
}

func (o *OnboardingState) Advance() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.Skipped || o.Completed {
		return
	}
	if o.CurrentStep >= StepComplete {
		o.Completed = true
		o.CompletedAt = time.Now()
		return
	}
	o.CurrentStep++
	if o.CurrentStep >= StepComplete {
		o.Completed = true
		o.CompletedAt = time.Now()
	}
}

func (o *OnboardingState) Skip() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Skipped = true
	o.Completed = true
	o.CompletedAt = time.Now()
}

func (o *OnboardingState) GetState() map[string]interface{} {
	o.mu.Lock()
	defer o.mu.Unlock()

	stepIndex := int(o.CurrentStep) - 1
	if stepIndex < 0 {
		stepIndex = 0
	}
	if stepIndex >= len(OnboardingSteps) {
		stepIndex = len(OnboardingSteps) - 1
	}

	currentStep := OnboardingSteps[stepIndex]

	return map[string]interface{}{
		"current_step":      o.CurrentStep,
		"current_step_info": currentStep,
		"total_steps":       len(OnboardingSteps),
		"skipped":           o.Skipped,
		"completed":         o.Completed,
		"started_at":        o.StartedAt,
		"completed_at":      o.CompletedAt,
	}
}

type OnboardingHandler struct {
	state *OnboardingState
}

func NewOnboardingHandler(state *OnboardingState) *OnboardingHandler {
	if state == nil {
		state = NewOnboardingState()
	}
	return &OnboardingHandler{state: state}
}

func (h *OnboardingHandler) HandleState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.state.GetState())
}

func (h *OnboardingHandler) HandleAdvance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.state.Advance()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.state.GetState())
}

func (h *OnboardingHandler) HandleSkip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.state.Skip()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.state.GetState())
}
