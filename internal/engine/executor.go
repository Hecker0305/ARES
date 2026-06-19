package engine

import (
	"context"
	"fmt"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/agent"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/sandbox"
	"github.com/ares/engine/internal/scope"
	"github.com/ares/engine/internal/security"
)

var blockedToolArgs = map[string][]string{
	"nmap":     {"-oN", "-oX", "-oG", "-oS", "-oA", "--script", "-iL"},
	"curl":     {"-o", "--output", "-O", "--remote-name", "-F", "--form", "--data", "-d", "--data-binary", "-T", "--upload-file"},
	"sqlmap":   {"--file-write", "--file-dest", "-o", "--os-shell", "--os-cmd", "--sql-shell"},
	"ffuf":     {"-o", "--output", "-of", "--output-format"},
	"gobuster": {"-o", "--output", "-of", "--output-format"},
	"nikto":    {"-o", "--output", "-Format"},
	"dalfox":   {"-o", "--output", "--mass", "--remote-payload"},
}

type Executor struct {
	config     ScanConfig
	mu         sync.RWMutex
	state      *agent.ScanState
	messages   []llm.Message
	tokenCount int
	scope      *scope.Enforcer
}

type ToolResult struct {
	Output string
	Error  string
}

func NewExecutor(cfg ScanConfig) *Executor {
	return &Executor{
		config:     cfg,
		state:      agent.NewScanState(nil),
		messages:   []llm.Message{},
		tokenCount: 0,
	}
}

func (e *Executor) Execute(ctx context.Context, target string, llmClient *llm.Client) (err error) {
	if e == nil || llmClient == nil {
		return fmt.Errorf("executor or LLM client is nil")
	}
	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			logger.Error(fmt.Sprintf("[Executor] PANIC RECOVERED: %v", r))
			if e.mu.TryLock() {
				e.state.Status = "crashed"
				e.state.Error = fmt.Sprintf("panic: %v", r)
				e.mu.Unlock()
			} else {
				logger.Error("[Executor] Could not acquire lock to record crash state")
			}
			err = fmt.Errorf("executor panic: %v", r)
		}
	}()
	e.mu.Lock()
	e.state.Targets = []string{target}
	e.mu.Unlock()
	e.scope = scope.NewEnforcer([]string{target})

	phases := []Phase{
		Phase("recon"),
		Phase("discovery"),
		Phase("vuln_scan"),
		Phase("exploit"),
		Phase("post_exploit"),
		Phase("report"),
	}

	for _, phase := range phases {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		e.mu.Lock()
		e.state.Phase = agent.Phase(phase)
		e.mu.Unlock()

		if err := e.executePhase(ctx, target, llmClient); err != nil {
			logger.Error(fmt.Sprintf("[Executor] Phase %s error: %v", phase, err))
			continue
		}

		if e.isStuck() {
			logger.Info(fmt.Sprintf("[Executor] Stuck at phase %s, advancing", phase))
		}
	}

	return nil
}

func (e *Executor) executePhase(ctx context.Context, target string, llmClient *llm.Client) error {
	e.mu.RLock()
	phase := Phase(e.state.Phase)
	e.mu.RUnlock()

	phasePrompt := e.phasePrompt(phase)
	prompt := fmt.Sprintf("Target: %s\nExecute scan phase: %s", target, phase)
	e.addMessage("user", prompt)

	e.mu.RLock()
	msgs := append([]llm.Message{}, e.messages...)
	e.mu.RUnlock()
	resp, err := llmClient.Complete(ctx, msgs, phasePrompt)
	if err != nil {
		return fmt.Errorf("llm complete: %w", err)
	}

	e.addMessage("assistant", resp)

	e.mu.Lock()
	e.state.IncrementIteration()
	e.state.MarkExecuted(string(phase))
	e.mu.Unlock()

	if e.shouldCompact() {
		e.compactHistory()
	}

	return nil
}

func (e *Executor) phasePrompt(phase Phase) string {
	switch phase {
	case PhaseRecon:
		return "You are in RECON phase. Perform passive reconnaissance to gather information about the target."
	case PhaseDiscovery:
		return "You are in DISCOVERY phase. Discover open ports, services, and endpoints."
	case PhaseVulnScan:
		return "You are in VULN_SCAN phase. Scan for known vulnerabilities and misconfigurations."
	case PhaseExploit:
		return "You are in EXPLOIT phase. Attempt to exploit discovered vulnerabilities."
	case PhasePostExploit:
		return "You are in POST_EXPLOIT phase. Perform post-exploitation activities."
	case PhaseReport:
		return "You are in REPORT phase. Compile findings and generate report."
	default:
		return "Execute scan phase"
	}
}

func (e *Executor) addMessage(role, content string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.messages = append(e.messages, llm.Message{
		Role:    role,
		Content: content,
	})
	e.tokenCount += len(content) / 4
}

func (e *Executor) shouldCompact() bool {
	maxTokens := 128000
	threshold := maxTokens * 80 / 100
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tokenCount > threshold
}

func (e *Executor) compactHistory() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.messages) <= 3 {
		return
	}

	first := e.messages[0]
	summary := fmt.Sprintf("[%d messages summarised]", len(e.messages)-2)
	recent := e.messages[len(e.messages)-2:]

	e.messages = []llm.Message{first, {Role: "user", Content: summary}}
	e.messages = append(e.messages, recent...)

	e.tokenCount = 0
	for _, m := range e.messages {
		e.tokenCount += len(m.Content) / 4
	}
}

func (e *Executor) isStuck() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state.Iteration >= e.config.MaxIterations
}

func (e *Executor) DispatchTool(ctx context.Context, toolName string, args map[string]string) (*ToolResult, error) {
	result, err := e.runTool(ctx, toolName, args)
	if err != nil {
		return &ToolResult{Output: "", Error: err.Error()}, err
	}
	return result, nil
}

func buildCommandSpec(toolName string, args []string) (security.CommandSpec, error) {
	switch toolName {
	case "nmap":
		return security.CommandSpec{Binary: "nmap", Args: args}, nil
	case "curl":
		return security.CommandSpec{Binary: "curl", Args: args}, nil
	case "nikto":
		return security.CommandSpec{Binary: "nikto", Args: args}, nil
	case "nuclei":
		return security.CommandSpec{Binary: "nuclei", Args: args}, nil
	case "sqlmap":
		return security.CommandSpec{Binary: "sqlmap", Args: args}, nil
	case "ffuf":
		return security.CommandSpec{Binary: "ffuf", Args: args}, nil
	case "dalfox":
		return security.CommandSpec{Binary: "dalfox", Args: args}, nil
	case "gobuster":
		return security.CommandSpec{Binary: "gobuster", Args: args}, nil
	case "whatweb":
		return security.CommandSpec{Binary: "whatweb", Args: args}, nil
	case "subfinder":
		return security.CommandSpec{Binary: "subfinder", Args: args}, nil
	default:
		return security.CommandSpec{}, fmt.Errorf("unknown tool: %s", toolName)
	}
}

var argInjectionPatterns = []string{"--", "-o", "-O", "--output", "-w", "--wordlist", "-t", "--threads", "-p", "--proxy"}

func validateTargetArg(target string) error {
	if target == "" {
		return fmt.Errorf("empty target")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target starts with flag prefix: %s", target)
	}
	if strings.Contains(target, "\n") || strings.Contains(target, "\r") {
		return fmt.Errorf("target contains newlines")
	}
	if strings.Contains(target, " ") {
		return fmt.Errorf("target contains spaces: potential argument injection")
	}
	lower := strings.ToLower(target)
	for _, pat := range argInjectionPatterns {
		if strings.Contains(lower, pat) {
			return fmt.Errorf("target contains flag-like substring %q", pat)
		}
	}
	// Reject targets that look like shell metacharacters
	if strings.ContainsAny(target, "|;&$`'\"(){}[]<>!") {
		return fmt.Errorf("target contains shell metacharacters")
	}
	return nil
}

func validateSimpleArg(value, name string) error {
	if value == "" {
		return fmt.Errorf("empty %s", name)
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s starts with flag prefix: %s", name, value)
	}
	if strings.Contains(value, " ") {
		return fmt.Errorf("%s contains spaces: potential argument injection", name)
	}
	if strings.ContainsAny(value, "|;&$`'\"(){}[]<>!\n\r") {
		return fmt.Errorf("%s contains shell metacharacters", name)
	}
	return nil
}

func validateURLArg(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("empty URL")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: %s", parsed.Scheme)
	}
	return nil
}

func (e *Executor) runTool(ctx context.Context, toolName string, args map[string]string) (*ToolResult, error) {
	target, hasTarget := args["target"]
	if !hasTarget || target == "" {
		if len(e.state.Targets) > 0 {
			target = e.state.Targets[0]
		} else {
			return nil, fmt.Errorf("no target specified")
		}
	}

	if err := validateTargetArg(target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	if e.scope == nil {
		e.scope = scope.NewEnforcer([]string{target})
	}
	if !e.scope.IsAllowed(target) {
		return nil, fmt.Errorf("target %q is out of scope", target)
	}

	var cmdArgs []string
	blockedArgs := blockedToolArgs[toolName]
	switch toolName {
	case "nmap":
		cmdArgs = []string{"-sV", "-O", target}
	case "curl":
		rawURL, ok := args["url"]
		if !ok || rawURL == "" {
			return nil, fmt.Errorf("no url provided")
		}
		if err := validateURLArg(rawURL); err != nil {
			return nil, fmt.Errorf("invalid url: %w", err)
		}
		cmdArgs = []string{"-s", rawURL}
	case "nikto":
		cmdArgs = []string{"-h", target}
	case "nuclei":
		templates := args["templates"]
		if templates == "" {
			templates = "cves,exposed-panels"
		}
		if err := validateSimpleArg(templates, "templates"); err != nil {
			return nil, err
		}
		cmdArgs = []string{"-u", target, "-t", templates}
	case "sqlmap":
		cmdArgs = []string{"-u", target, "--batch", "--random-agent", "--timeout=30"}
	case "ffuf":
		wordlist := args["wordlist"]
		if wordlist == "" {
			wordlist = "/usr/share/wordlists/dirb/common.txt"
		}
		if err := validateSimpleArg(wordlist, "wordlist"); err != nil {
			return nil, err
		}
		cmdArgs = []string{"-u", target + "/FUZZ", "-w", wordlist, "-t", "50", "-c"}
	case "dalfox":
		cmdArgs = []string{"url", target, "--silence", "--timeout", "30"}
	case "gobuster":
		wordlist := args["wordlist"]
		if wordlist == "" {
			wordlist = "/usr/share/wordlists/dirb/common.txt"
		}
		if err := validateSimpleArg(wordlist, "wordlist"); err != nil {
			return nil, err
		}
		cmdArgs = []string{"dir", "-u", target, "-w", wordlist, "-t", "50"}
	case "whatweb":
		cmdArgs = []string{target, "--log-verbose=-"}
	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}

	// Check for blocked/dangerous tool arguments
	for i, arg := range cmdArgs {
		for _, blocked := range blockedArgs {
			if arg == blocked && i+1 < len(cmdArgs) {
				return nil, fmt.Errorf("blocked argument %q for tool %s", blocked, toolName)
			}
		}
	}

	spec, err := buildCommandSpec(toolName, cmdArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid tool spec: %w", err)
	}

	validated := security.ValidateCommand(spec)
	if validated.Err != nil {
		return nil, fmt.Errorf("command rejected: %w", validated.Err)
	}

	sandboxCfg := sandbox.Config{
		Level:      sandbox.SandboxRestricted,
		Timeouts:   10 * time.Minute,
		MaxOutput:  10 << 20,
		ReadOnly:   true,
		NetworkOff: false,
	}
	sb := sandbox.NewManager(sandboxCfg)
	result := sb.Execute(ctx, validated.Binary, validated.Args, nil)
	if result.Violation != "" {
		return &ToolResult{Output: result.Stdout, Error: result.Violation}, fmt.Errorf("sandbox violation: %s", result.Violation)
	}
	if result.ExitCode != 0 {
		return &ToolResult{Output: result.Stdout, Error: result.Stderr}, fmt.Errorf("exit code %d: %s", result.ExitCode, result.Stderr)
	}
	return &ToolResult{Output: result.Stdout}, nil
}

func (e *Executor) State() *agent.ScanState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state
}

func (e *Executor) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = agent.NewScanState(nil)
	e.messages = []llm.Message{}
	e.tokenCount = 0
}
