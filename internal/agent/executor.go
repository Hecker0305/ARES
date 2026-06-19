package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ares/engine/internal/huntmemory"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/tools"
)

type Tool struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema ToolSchema `json:"input_schema"`
}

type ToolSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Required   []string               `json:"required"`
}

type ToolCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"arguments"`
}

type ToolResult struct {
	CallID  string `json:"call_id"`
	Content string `json:"content"`
	Error   string `json:"error,omitempty"`
	Success bool   `json:"success"`
}

type ExecutorConfig struct {
	MaxIterations    int
	StuckThreshold   int
	RepeatWindow     int
	TargetReInject   bool
	PhaseEnforcement bool
	ScopeCheck       []string
	Tools            []Tool
	ToolHandlers     map[string]ToolHandler
}

type Tier4Executor struct {
	client     *llm.Client
	state      *ScanState
	config     ExecutorConfig
	toolSchema []Tool
	tools      map[string]ToolHandler
	prevCmds   map[string]int
	sqliteMem  *huntmemory.SQLiteMemory
}

type ToolHandler func(ctx context.Context, args json.RawMessage) (*ToolResult, error)

func NewTier4Executor(client *llm.Client, cfg ExecutorConfig) *Tier4Executor {
	state := NewScanState(nil)

	ex := &Tier4Executor{
		client:     client,
		state:      state,
		config:     cfg,
		toolSchema: cfg.Tools,
		tools:      cfg.ToolHandlers,
		prevCmds:   make(map[string]int),
	}

	if ex.tools == nil {
		ex.tools = make(map[string]ToolHandler)
	}

	if ex.config.StuckThreshold == 0 {
		ex.config.StuckThreshold = 20
	}

	ex.registerBuiltInTools()
	return ex
}

var dangerousArgFlags = map[string][]string{
	"nmap":     {"-oN", "-oX", "-oG", "-oS", "-oA"},
	"curl":     {"-o", "--output", "-O", "--remote-name", "-F", "--form"},
	"ffuf":     {"-o", "--output"},
	"gobuster": {"-o", "--output"},
	"sqlmap":   {"--file-write", "--file-dest", "-o"},
	"nikto":    {"-o", "--output"},
	"wafw00f":  {"-o", "--output"},
}

func validateToolArgs(binary string, args []string) error {
	dangerous, ok := dangerousArgFlags[binary]
	if !ok {
		return nil
	}
	for i, arg := range args {
		for _, flag := range dangerous {
			if arg == flag {
				if i+1 < len(args) {
					nextArg := args[i+1]
					cleanNext := filepath.Clean(nextArg)
					if strings.Contains(cleanNext, "..") {
						return fmt.Errorf("path traversal in argument: %q", nextArg)
					}
					if !strings.HasPrefix(cleanNext, "/tmp/") && !strings.HasPrefix(cleanNext, os.TempDir()) {
						return fmt.Errorf("output path %q not in allowed temp directory", nextArg)
					}
				}
			}
		}
	}
	return nil
}

var allowedNetworkTools = map[string]allowedTool{
	"nmap": {
		allowedFlags: []string{"-sV", "-sC", "-sS", "-sT", "-Pn", "-A", "-T4", "--max-retries", "--host-timeout", "-p", "--open", "-oX", "-oN", "-oG"},
		maxArgs:      20,
	},
	"ping": {
		allowedFlags: []string{"-c", "-W", "-n"},
		maxArgs:      5,
	},
	"dig": {
		allowedFlags: []string{"+short", "+noall", "+answer", "ANY", "A", "AAAA", "MX", "NS", "TXT", "SOA"},
		maxArgs:      10,
	},
	"nslookup": {
		allowedFlags: []string{},
		maxArgs:      10,
	},
	"whois": {
		allowedFlags: []string{"-h"},
		maxArgs:      10,
	},
	"curl": {
		allowedFlags: []string{"-s", "-S", "-v", "-k", "-L", "-I", "-H", "-A", "--connect-timeout", "--max-time", "-X", "-d", "--data", "--data-raw", "--data-binary"},
		maxArgs:      30,
	},
}

type allowedTool struct {
	allowedFlags []string
	maxArgs      int
}

func (e *Tier4Executor) registerBuiltInTools() {
	e.RegisterTool("terminal_execute", Tool{
		Name:        "terminal_execute",
		Description: "Execute a security tool from the allowed list with predefined flags",
		InputSchema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"tool":    map[string]string{"type": "string", "description": "Tool name (nmap, curl, ping, dig, nslookup, whois)"},
				"args":    map[string]string{"type": "string", "description": "Space-separated arguments (only allowed flags permitted)"},
				"target":  map[string]string{"type": "string", "description": "Target host/IP/URL"},
				"workdir": map[string]string{"type": "string"},
				"timeout": map[string]string{"type": "integer"},
			},
			Required: []string{"tool", "target"},
		},
	}, func(ctx context.Context, args json.RawMessage) (*ToolResult, error) {
		var req struct {
			Tool    string `json:"tool"`
			Args    string `json:"args"`
			Target  string `json:"target"`
			Workdir string `json:"workdir"`
			Timeout int    `json:"timeout"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return &ToolResult{Content: "", Error: err.Error(), Success: false}, nil
		}
		toolDef, ok := allowedNetworkTools[req.Tool]
		if !ok {
			return &ToolResult{Content: "", Error: fmt.Sprintf("tool %q not in allowed list", req.Tool), Success: false}, nil
		}
		if req.Timeout == 0 {
			req.Timeout = 120
		}
		parsedArgs := strings.Fields(req.Args)
		if len(parsedArgs) > toolDef.maxArgs {
			return &ToolResult{Content: "", Error: fmt.Sprintf("too many arguments (%d > %d)", len(parsedArgs), toolDef.maxArgs), Success: false}, nil
		}
		for _, arg := range parsedArgs {
			if strings.HasPrefix(arg, "-") {
				flagOnly := arg
				if idx := strings.Index(arg, "="); idx > 0 {
					flagOnly = arg[:idx]
				}
				allowed := false
				for _, f := range toolDef.allowedFlags {
					if flagOnly == f {
						allowed = true
						break
					}
				}
				if !allowed {
					return &ToolResult{Content: "", Error: fmt.Sprintf("flag %q not allowed for tool %q", arg, req.Tool), Success: false}, nil
				}
			}
		}
		if strings.HasPrefix(req.Target, "-") {
			return &ToolResult{Content: "", Error: "target cannot start with '-'", Success: false}, nil
		}
		checkShellMetachar := func(s string) bool {
			return strings.ContainsAny(s, "|;&$`'\"(){}[]<>!\\\n\r")
		}
		if checkShellMetachar(req.Target) {
			return &ToolResult{Content: "", Error: "target contains shell metacharacters", Success: false}, nil
		}
		for _, a := range parsedArgs {
			if checkShellMetachar(a) {
				return &ToolResult{Content: "", Error: "argument contains shell metacharacters", Success: false}, nil
			}
		}
		cmdArgs := make([]string, 0, len(parsedArgs)+1)
		cmdArgs = append(cmdArgs, parsedArgs...)
		cmdArgs = append(cmdArgs, req.Target)
		spec := security.CommandSpec{Binary: req.Tool, Args: cmdArgs}
		if err := validateToolArgs(req.Tool, cmdArgs); err != nil {
			return &ToolResult{Content: "", Error: err.Error(), Success: false}, nil
		}
		cfg := TerminalConfig{
			Workdir: req.Workdir,
			Timeout: time.Duration(req.Timeout) * time.Second,
		}
		out, err := ExecuteCommand(ctx, spec, cfg)
		if err != nil {
			return &ToolResult{Content: out, Error: err.Error(), Success: false}, nil
		}
		return &ToolResult{Content: out, Success: true}, nil
	})

	e.RegisterTool("read_skill", Tool{
		Name:        "read_skill",
		Description: "Read a skill file by name",
		InputSchema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"skill_name": map[string]string{"type": "string"},
			},
			Required: []string{"skill_name"},
		},
	}, func(ctx context.Context, args json.RawMessage) (*ToolResult, error) {
		var req struct {
			SkillName string `json:"skill_name"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return &ToolResult{Error: err.Error(), Success: false}, nil
		}
		content, err := readSkill(req.SkillName)
		if err != nil {
			return &ToolResult{Error: err.Error(), Success: false}, nil
		}
		return &ToolResult{Content: content, Success: true}, nil
	})

	e.RegisterTool("list_skills", Tool{
		Name:        "list_skills",
		Description: "List all available skill files",
		InputSchema: ToolSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
		},
	}, func(ctx context.Context, args json.RawMessage) (*ToolResult, error) {
		skills := listSkills()
		return &ToolResult{Content: strings.Join(skills, "\n"), Success: true}, nil
	})

	e.RegisterTool("memory_recall", Tool{
		Name:        "memory_recall",
		Description: "Recall prior findings, payloads, and FP signals from memory",
		InputSchema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"target":    map[string]string{"type": "string"},
				"vuln_type": map[string]string{"type": "string"},
			},
		},
	}, func(ctx context.Context, args json.RawMessage) (*ToolResult, error) {
		var req struct {
			Target   string `json:"target"`
			VulnType string `json:"vuln_type"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return &ToolResult{Error: err.Error(), Success: false}, nil
		}

		// Query SQLiteMemory when available
		if e.sqliteMem != nil {
			qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			successful, err := e.sqliteMem.GetSuccessfulPayloads(qCtx, req.Target, req.VulnType)
			if err != nil {
				return &ToolResult{Content: fmt.Sprintf("Prior findings for %s (%s): sqlite error", req.Target, req.VulnType), Success: true}, nil
			}

			failed, err := e.sqliteMem.GetFailedPayloads(qCtx, req.Target, req.VulnType)
			if err != nil {
				return &ToolResult{Content: fmt.Sprintf("Prior findings for %s (%s): sqlite error", req.Target, req.VulnType), Success: true}, nil
			}

			successPayloads := strings.Join(successful, ", ")
			if successPayloads == "" {
				successPayloads = "none"
			}
			failedPayloads := strings.Join(failed, ", ")
			if failedPayloads == "" {
				failedPayloads = "none"
			}

			prob := 0.5
			total := len(successful) + len(failed)
			if total > 0 {
				prob = float64(len(successful)) / float64(total)
			}

			content := fmt.Sprintf("Prior findings for %s (%s): success_probability=%.2f, top_payloads=[%s], failed_payloads=[%s]",
				req.Target, req.VulnType, prob, successPayloads, failedPayloads)
			return &ToolResult{Content: content, Success: true}, nil
		}

		// Fallback to old JSON-based memory
		recalled := recallFromMemory(req.Target, req.VulnType)
		return &ToolResult{Content: recalled, Success: true}, nil
	})

	e.RegisterTool("websearch", Tool{
		Name:        "websearch",
		Description: "Search the web using the configured search provider",
		InputSchema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"query": map[string]string{"type": "string"},
			},
			Required: []string{"query"},
		},
	}, func(ctx context.Context, args json.RawMessage) (*ToolResult, error) {
		var req struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return &ToolResult{Error: err.Error(), Success: false}, nil
		}
		result, err := webSearch(req.Query)
		if err != nil {
			return &ToolResult{Error: err.Error(), Success: false}, nil
		}
		return &ToolResult{Content: result, Success: true}, nil
	})

	e.RegisterTool("scope_check", Tool{
		Name:        "scope_check",
		Description: "Check if a target is in scope based on configured scope list",
		InputSchema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"target": map[string]string{"type": "string"},
			},
			Required: []string{"target"},
		},
	}, func(ctx context.Context, args json.RawMessage) (*ToolResult, error) {
		var req struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return &ToolResult{Error: err.Error(), Success: false}, nil
		}
		inScope := isInScopeStr(req.Target, e.config.ScopeCheck)
		if inScope {
			return &ToolResult{Content: "in-scope", Success: true}, nil
		}
		return &ToolResult{Content: "out-of-scope: " + req.Target, Error: "out-of-scope", Success: false}, nil
	})
}

// SetSQLiteMemory wires SQLite-backed persistent hunt memory into the executor
func (e *Tier4Executor) SetSQLiteMemory(sm *huntmemory.SQLiteMemory) {
	e.sqliteMem = sm
}

func (e *Tier4Executor) RegisterTool(name string, schema Tool, handler ToolHandler) {
	e.tools[name] = handler
	e.toolSchema = append(e.toolSchema, schema)
}

func (e *Tier4Executor) Run(ctx context.Context, prompt string) error {
	if e.state.Iteration >= e.config.StuckThreshold {
		return fmt.Errorf("scan stuck at %d iterations", e.state.Iteration)
	}
	e.state.IncrementIteration()

	var messages []llm.Message

	if e.config.PhaseEnforcement {
		phasePrompt := fmt.Sprintf("\n[SYSTEM: Phase=%s, Iteration=%d] Follow strict phase ordering: Recon→Discovery→VulnScan→Exploit→PostExploit→Report\n",
			e.state.Phase, e.state.Iteration)
		prompt = phasePrompt + prompt
	}

	if e.config.TargetReInject && len(e.state.Targets) > 0 {
		prompt = e.state.ReInjectTargets(prompt)
	}

	messages = append(messages, llm.Message{
		Role:    "user",
		Content: prompt,
	})

	_, err := e.client.Complete(ctx, messages, "")
	if err != nil {
		return err
	}

	return nil
}

func (e *Tier4Executor) GetState() *ScanState {
	return e.state
}

func (e *Tier4Executor) SetPhase(phase Phase) {
	e.state.Phase = phase
}

func (e *Tier4Executor) AddTarget(target string) {
	e.state.Targets = append(e.state.Targets, target)
}

func (e *Tier4Executor) GetTools() []Tool {
	return e.toolSchema
}

func (e *Tier4Executor) RecordFinding(f FindingData) {
	e.state.RecordFinding(f)
}

func readSkill(name string) (string, error) {
	req, err := json.Marshal(map[string]string{"skill_name": name})
	if err != nil {
		return "", fmt.Errorf("failed to marshal skill request: %w", err)
	}
	result := tools.ReadSkill(json.RawMessage(req), nil)
	if result.Error != "" {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.Output, nil
}

func listSkills() []string {
	result := tools.ListSkills(json.RawMessage(`{}`), nil)
	if result.Error != "" {
		return []string{"sqli-auth-bypass", "xss-filter-bypass"}
	}
	if result.Output == "" {
		return []string{}
	}
	var lines []string
	for _, l := range strings.Split(result.Output, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "- ") {
			l = l[2:]
			if idx := strings.Index(l, ":"); idx > 0 {
				l = l[:idx]
			}
			l = strings.TrimSpace(l)
			if l != "" {
				lines = append(lines, l)
			}
		}
	}
	if len(lines) == 0 {
		lines = []string{"sqli-auth-bypass", "xss-filter-bypass"}
	}
	return lines
}

func recallFromMemory(target, vulnType string) string {
	req, err := json.Marshal(map[string]string{"query": target, "vuln_type": vulnType})
	if err != nil {
		return fmt.Sprintf("Prior findings for %s (%s): marshal error", target, vulnType)
	}
	result := tools.Recall(json.RawMessage(req), nil)
	if result.Error != "" {
		return fmt.Sprintf("Prior findings for %s (%s): no memory entries", target, vulnType)
	}
	return result.Output
}

func webSearch(query string) (string, error) {
	query = sanitizeSearchQuery(query)
	req, err := json.Marshal(map[string]string{"query": query, "provider": "duckduckgo"})
	if err != nil {
		return "", fmt.Errorf("failed to marshal search request: %w", err)
	}
	result := tools.WebSearchTool(json.RawMessage(req), nil)
	if result.Error != "" {
		return "", fmt.Errorf("%s", result.Error)
	}
	output := result.Output
	output = filterPromptInjection(output)
	return output, nil
}

func sanitizeSearchQuery(query string) string {
	// Remove any potential injection characters from search queries
	query = strings.ReplaceAll(query, "{", "")
	query = strings.ReplaceAll(query, "}", "")
	query = strings.ReplaceAll(query, "<", "")
	query = strings.ReplaceAll(query, ">", "")
	query = strings.ReplaceAll(query, ";", "")
	return strings.TrimSpace(query)
}

func filterPromptInjection(text string) string {
	// Use regex for substring matching, case-insensitive
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(previous|all|above|prior)`),
		regexp.MustCompile(`(?i)system\s*prompt`),
		regexp.MustCompile(`(?i)you\s+are\s+now`),
		regexp.MustCompile(`(?i)forget\s+(all|everything|previous)`),
		regexp.MustCompile(`(?i)new\s+(instruction|rule|directive|command)`),
		regexp.MustCompile(`(?i)override\s+(all|previous|prior)`),
		regexp.MustCompile(`(?i)disregard\s+(all|previous|prior)`),
		regexp.MustCompile(`(?i)role.?play`),
		regexp.MustCompile(`(?i)jail\s*break`),
		regexp.MustCompile(`(?i)act\s+as\s+(if|though)`),
		regexp.MustCompile(`(?i)dante?\s+mode`),
		regexp.MustCompile(`(?i)do\s+(not\s+)?(what|as)\s+(i|we|the)\s+(say|tell|ask|instruct)`),
	}
	lines := strings.Split(text, "\n")
	var filtered []string
	for _, line := range lines {
		matched := false
		for _, p := range patterns {
			if p.MatchString(line) {
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

func isInScopeStr(target string, scopeList []string) bool {
	if len(scopeList) == 0 {
		return true
	}
	for _, s := range scopeList {
		// Exact domain match or subdomain match
		if strings.EqualFold(target, s) ||
			strings.HasSuffix(strings.ToLower(target), "."+strings.ToLower(s)) {
			return true
		}
	}
	return false
}
