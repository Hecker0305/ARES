package guardrails

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

type ThreatLevel int

const (
	ThreatNone     ThreatLevel = 0
	ThreatLow      ThreatLevel = 1
	ThreatMedium   ThreatLevel = 2
	ThreatHigh     ThreatLevel = 3
	ThreatCritical ThreatLevel = 4
)

type DetectionResult struct {
	Detected    bool        `json:"detected"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	Category    string      `json:"category"`
	MatchedOn   string      `json:"matched_on"`
	Confidence  float64     `json:"confidence"`
	SafeVersion string      `json:"safe_version,omitempty"`
}

type GuardrailConfig struct {
	MaxTokenLen       int
	MaxDepth          int
	BlockRemoteExec   bool
	BlockFileAccess   bool
	RequireApproval   []string
	AllowedHosts      []string
	RateLimit         int
	EnablePromptGuard bool
	EnableOutputGuard bool
	EnableLoopGuard   bool
}

type Engine struct {
	mu          sync.RWMutex
	config      GuardrailConfig
	detectors   []Detector
	loopHistory map[string][]time.Time
}

type Detector interface {
	Name() string
	Detect(input string) DetectionResult
}

type PromptInjectionDetector struct{}

var promptInjectionPatterns = []struct {
	pattern  *regexp.Regexp
	level    ThreatLevel
	category string
}{
	{regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|commands)`), ThreatCritical, "instruction_override"},
	{regexp.MustCompile(`(?i)you are (now |)(an? |)(free |)`), ThreatHigh, "role_play"},
	{regexp.MustCompile(`(?i)system\s*prompt`), ThreatHigh, "system_prompt_leak"},
	{regexp.MustCompile(`(?i)output\s*(only|exclusively)\s*(the|with|)`), ThreatMedium, "output_constraint"},
	{regexp.MustCompile(`(?i)say\s*("|'|` + "`" + `)(.*?)("|'|` + "`" + `)`), ThreatMedium, "forced_output"},
	{regexp.MustCompile(`(?i)repeat\s*(after|back|exactly|verbatim)`), ThreatLow, "repetition"},
	{regexp.MustCompile(`(?i)bypass\s*(restrictions|filters|rules|safety)`), ThreatHigh, "bypass_attempt"},
	{regexp.MustCompile(`(?i)act\s*as\s*(if|though)`), ThreatLow, "role_assumption"},
	{regexp.MustCompile(`(?i)do\s*(not|n't)\s*(follow|obey|comply|listen)\s*(my|our|these|the)\s*(instruction|command|order|direction)s?`), ThreatMedium, "disobedience"},
	{regexp.MustCompile(`(?i)print\s*(the|your|all)\s*(system|internal|secret|hidden)`), ThreatHigh, "secret_disclosure"},
}

func (d PromptInjectionDetector) Name() string { return "prompt_injection" }

func (d PromptInjectionDetector) Detect(input string) DetectionResult {
	for _, p := range promptInjectionPatterns {
		if p.pattern.MatchString(input) {
			return DetectionResult{
				Detected:    true,
				ThreatLevel: p.level,
				Category:    p.category,
				MatchedOn:   p.pattern.String(),
				Confidence:  confidenceFromLevel(p.level),
			}
		}
	}
	return DetectionResult{Detected: false, ThreatLevel: ThreatNone, Confidence: 0}
}

type ToolAbuseDetector struct {
	allowedTools map[string]bool
}

func NewToolAbuseDetector(allowed []string) *ToolAbuseDetector {
	d := &ToolAbuseDetector{allowedTools: make(map[string]bool)}
	for _, t := range allowed {
		d.allowedTools[t] = true
	}
	return d
}

func (d *ToolAbuseDetector) Name() string { return "tool_abuse" }

func (d *ToolAbuseDetector) Detect(input string) DetectionResult {
	lower := strings.ToLower(input)
	abusePatterns := []string{
		"rm -rf", "mkfs", "dd if=",
		":(){:|:&};:", "chmod 777 /", "chown -R /",
		"shutdown", "reboot", "halt", "poweroff",
		"wget -O /", "curl -o /",
	}

	for _, p := range abusePatterns {
		if strings.Contains(lower, p) {
			return DetectionResult{
				Detected:    true,
				ThreatLevel: ThreatCritical,
				Category:    "tool_abuse",
				MatchedOn:   p,
				Confidence:  0.95,
			}
		}
	}
	return DetectionResult{Detected: false}
}

type RecursiveLoopDetector struct {
	mu        sync.Mutex
	patterns  map[string]int
	window    time.Duration
	threshold int
}

func NewRecursiveLoopDetector(window time.Duration, threshold int) *RecursiveLoopDetector {
	return &RecursiveLoopDetector{
		patterns:  make(map[string]int),
		window:    window,
		threshold: threshold,
	}
}

func (d *RecursiveLoopDetector) Name() string { return "recursive_loop" }

func (d *RecursiveLoopDetector) Detect(input string) DetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	h := sha256.Sum256([]byte(input))
	hash := hex.EncodeToString(h[:8])
	d.patterns[hash]++

	count := d.patterns[hash]
	if count >= d.threshold {
		return DetectionResult{
			Detected:    true,
			ThreatLevel: ThreatHigh,
			Category:    "recursive_loop",
			MatchedOn:   fmt.Sprintf("pattern repeated %d times", count),
			Confidence:  0.8,
		}
	}
	return DetectionResult{Detected: false}
}

type OutputSanitizer struct{}

func (s OutputSanitizer) Sanitize(input string) string {
	var result strings.Builder
	for _, r := range input {
		if r == '\x00' {
			continue
		}
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}

func NewDefaultConfig() GuardrailConfig {
	return GuardrailConfig{
		MaxTokenLen:       128000,
		MaxDepth:          50,
		BlockRemoteExec:   true,
		BlockFileAccess:   true,
		RequireApproval:   []string{"exfiltrate", "modify_system", "install_tool"},
		AllowedHosts:      []string{},
		RateLimit:         10,
		EnablePromptGuard: true,
		EnableOutputGuard: true,
		EnableLoopGuard:   true,
	}
}

func NewEngine(cfg GuardrailConfig) *Engine {
	e := &Engine{
		config:      cfg,
		detectors:   make([]Detector, 0),
		loopHistory: make(map[string][]time.Time),
	}
	e.Register(PromptInjectionDetector{})
	e.Register(NewToolAbuseDetector(nil))
	e.Register(NewRecursiveLoopDetector(30*time.Second, 5))
	return e
}

func (e *Engine) Register(d Detector) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.detectors = append(e.detectors, d)
}

func (e *Engine) CheckPrompt(input string) []DetectionResult {
	if !e.config.EnablePromptGuard {
		return nil
	}

	var results []DetectionResult
	for _, d := range e.detectors {
		if d.Name() == "recursive_loop" {
			continue
		}
		result := d.Detect(input)
		if result.Detected {
			results = append(results, result)
		}
	}
	return results
}

func (e *Engine) CheckOutput(output string) []DetectionResult {
	if !e.config.EnableOutputGuard {
		return nil
	}

	var results []DetectionResult
	if len(output) > e.config.MaxTokenLen {
		results = append(results, DetectionResult{
			Detected:    true,
			ThreatLevel: ThreatMedium,
			Category:    "token_overflow",
			MatchedOn:   fmt.Sprintf("output length %d exceeds max %d", len(output), e.config.MaxTokenLen),
			Confidence:  1.0,
		})
	}

	secrets := []string{
		`(?i)AKIA[0-9A-Z]{16}`,
		`(?i)sk-[a-zA-Z0-9]{32,}`,
		`(?i)ghp_[a-zA-Z0-9]{36}`,
		`(?i)-----BEGIN\s+(RSA |EC |)PRIVATE KEY-----`,
		`(?i)sqlite3\s+\S+\.db`,
		`(?i)postgresql://\S+:\S+@`,
		`(?i)mongodb://\S+:\S+@`,
	}
	for _, pattern := range secrets {
		re := regexp.MustCompile(pattern)
		if re.MatchString(output) {
			results = append(results, DetectionResult{
				Detected:    true,
				ThreatLevel: ThreatHigh,
				Category:    "secret_leak",
				MatchedOn:   pattern,
				Confidence:  0.9,
			})
		}
	}
	return results
}

func (e *Engine) CheckLoop(agentID string) DetectionResult {
	if !e.config.EnableLoopGuard {
		return DetectionResult{}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	e.loopHistory[agentID] = append(e.loopHistory[agentID], now)

	var recent []time.Time
	for _, t := range e.loopHistory[agentID] {
		if now.Sub(t) <= 60*time.Second {
			recent = append(recent, t)
		}
	}
	e.loopHistory[agentID] = recent

	if len(recent) > e.config.RateLimit {
		return DetectionResult{
			Detected:    true,
			ThreatLevel: ThreatHigh,
			Category:    "loop_abuse",
			MatchedOn:   fmt.Sprintf("%d iterations in 60s", len(recent)),
			Confidence:  0.85,
		}
	}
	return DetectionResult{}
}

func (e *Engine) SanitizeOutput(output string) string {
	s := OutputSanitizer{}
	return s.Sanitize(output)
}

func (e *Engine) ShouldBlock(results []DetectionResult) bool {
	for _, r := range results {
		if r.ThreatLevel >= ThreatHigh {
			return true
		}
	}
	return false
}

func (e *Engine) Config() GuardrailConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

func (e *Engine) SetConfig(cfg GuardrailConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
}

func confidenceFromLevel(level ThreatLevel) float64 {
	switch level {
	case ThreatNone:
		return 0
	case ThreatLow:
		return 0.3
	case ThreatMedium:
		return 0.6
	case ThreatHigh:
		return 0.85
	case ThreatCritical:
		return 0.98
	default:
		return 0
	}
}
