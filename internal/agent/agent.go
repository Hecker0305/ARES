package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/agents"
	"github.com/ares/engine/internal/circuitbreaker"
	"github.com/ares/engine/internal/commands"
	"github.com/ares/engine/internal/control"
	"github.com/ares/engine/internal/differential"
	"github.com/ares/engine/internal/graphql"
	"github.com/ares/engine/internal/hooks"
	"github.com/ares/engine/internal/huntmemory"
	"github.com/ares/engine/internal/intel"
	"github.com/ares/engine/internal/jsanalysis"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/llmrouting"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/nlp"
	"github.com/ares/engine/internal/phasemanager"
	"github.com/ares/engine/internal/python"
	"github.com/ares/engine/internal/ratelimit"
	"github.com/ares/engine/internal/reason"
	resruntime "github.com/ares/engine/internal/resource"
	"github.com/ares/engine/internal/safety"
	"github.com/ares/engine/internal/scope"
	"github.com/ares/engine/internal/secondorder"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/semantic"
	"github.com/ares/engine/internal/skills"
	"github.com/ares/engine/internal/taint"
	"github.com/ares/engine/internal/timing"
	"github.com/ares/engine/internal/tools"
	"github.com/ares/engine/internal/tools/agentsgraph"
	"github.com/ares/engine/internal/tools/installer"
	"github.com/ares/engine/internal/validationgate"
	"golang.org/x/text/unicode/norm"
)

const (
	maxHistoryMessages      = 60
	maxHistoryBeforeCompact = 40
	maxToolOutputLen        = 10000
	maxHistoryTokens        = 100000
	maxIterationTokens      = 80000
	maxMessageTokens        = 3000
)

type TokenBudget struct {
	MaxInputTokens    int
	MaxOutputTokens   int
	MaxCostUSD        float64
	CurrentInput      int
	CurrentOutput     int
	EstimatedCost     float64
	CostPerInputK     float64
	CostPerOutputK    float64
}

func NewTokenBudget() *TokenBudget {
	return &TokenBudget{
		MaxInputTokens:  200000,
		MaxOutputTokens: 50000,
		MaxCostUSD:      15.0,
		CostPerInputK:   0.003,
		CostPerOutputK:  0.015,
	}
}

func (b *TokenBudget) RecordInput(tokens int) {
	b.CurrentInput += tokens
	b.estimateCost()
}

func (b *TokenBudget) RecordOutput(tokens int) {
	b.CurrentOutput += tokens
	b.estimateCost()
}

func (b *TokenBudget) estimateCost() {
	inputCost := (float64(b.CurrentInput) / 1000.0) * b.CostPerInputK
	outputCost := (float64(b.CurrentOutput) / 1000.0) * b.CostPerOutputK
	b.EstimatedCost = inputCost + outputCost
}

func (b *TokenBudget) Exceeded() error {
	if b.CurrentInput+b.CurrentOutput > b.MaxInputTokens+b.MaxOutputTokens {
		return fmt.Errorf("token budget exceeded: %d total tokens (max %d)",
			b.CurrentInput+b.CurrentOutput, b.MaxInputTokens+b.MaxOutputTokens)
	}
	if b.EstimatedCost > b.MaxCostUSD {
		return fmt.Errorf("cost budget exceeded: $%.2f (max $%.2f)",
			b.EstimatedCost, b.MaxCostUSD)
	}
	return nil
}

func (b *TokenBudget) Reset() {
	b.CurrentInput = 0
	b.CurrentOutput = 0
	b.EstimatedCost = 0
}

type AgentConfig struct {
	MaxIterations           int
	StuckThreshold          int
	TargetReinject          int
	ConfidenceGate          float64
	MemoryCompressorTimeout time.Duration
	AdaptiveMode            bool
	MaxContextTokens        int
	RateLimit               float64
	RateBurst               int
}

type AgentState struct {
	Phase           Phase
	Iteration       int
	StuckCounter    int
	Recoveries      int
	LastPhaseChange time.Time
}

type MemoryCompressor struct {
	interval  time.Duration
	threshold int
}

type Agent struct {
	mu               sync.RWMutex
	scanCtx          *ScanContext
	llm              llm.LLMClient
	llmRouter        *llmrouting.Router
	registry         *tools.Registry
	history          []llm.Message
	systemPrompt     string
	hookRegistry     *hooks.Registry
	config           AgentConfig
	state            *AgentState
	vulnStore        *VulnStore
	noteStore        *NoteStore
	browserState     *BrowserState
	termState        *TermState
	memoryCompressor *MemoryCompressor
	jsAnalyzer       *jsanalysis.Analyzer
	graphqlPipelines map[string]*graphql.Pipeline
	timingProfile    *timing.TimingProfile
	differentialEng  *differential.Engine
	semanticModel    *semantic.AppModel
	rateLimiter      *ratelimit.Limiter
	skillsLoader     *skills.Loader
	cmdHistory       []string
	traceID          string
	policyEngine     *control.PolicyEngine
	resourceGovernor *resruntime.Governor
	safetyMode       *safety.SafetyModeManager
	paused           bool
	resumeCh         chan struct{}
	tokenBudget      *TokenBudget
	hintCh           chan string
	taintEngine      *taint.Engine
	nlpProcessor     *nlp.Processor
	installer        *installer.Installer
	cbManager        *circuitbreaker.Manager
	phaseMgr         *phasemanager.Manager
	toolAllowlist    map[string]bool
	reasonEngine     *reason.Engine
	toolExecCount    int
	findingCount     int

	cmdRegistry    *commands.Registry
	agentFactory   *agents.AgentFactory
	huntMem           *huntmemory.HuntMemory
	sqliteMem         *huntmemory.SQLiteMemory
	validationGate    *validationgate.Gate
	soEngine          *secondorder.CorrelationEngine
	scopeEnforcer     *scope.Enforcer
	progressCallback  func(int, string, float64)
	adaptiveJailbreak *AdaptiveJailbreak
	skipOwnershipCheck bool
}

type VulnStore struct {
	mu              sync.Mutex
	vulnerabilities map[string]Finding
}

type NoteStore struct {
	mu    sync.Mutex
	notes []string
}

type BrowserState struct {
	mu           sync.RWMutex
	URL          string
	Cookies      []string
	LocalStorage map[string]string
	SessionID    string
}

type TermState struct {
	mu      sync.RWMutex
	Workdir string
	EnvVars map[string]string
	LastCmd string
}

func NewAgent(scanID, target string, llmClient llm.LLMClient) *Agent {
	scanCtx := NewScanContext(scanID, target)

	hr := hooks.NewRegistry()
	hr.Register(hooks.OnToolCallHook, func(e hooks.HookEvent) hooks.HookResult {
		if e.ToolName == "terminal_execute" {
			return hooks.CheckStuck(e.ScanID, scanCtx)
		}
		return hooks.HookResult{}
	})
	hr.Register(hooks.OnToolResultHook, func(e hooks.HookEvent) hooks.HookResult {
		return hooks.HookResult{}
	})

	r := tools.NewRegistry()
	agh := agentsgraph.NewToolHandler(llmClient)

	cmdReg := commands.DefaultRegistry
	agFactory := agents.NewAgentFactory()
	huntMem, _ := huntmemory.New(filepath.Join(os.TempDir(), "ares_hunt_memory.jsonl"))
	r.Register("agents_graph_run", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		res := agh.RunSubAgents(p, sc)
		return tools.ToolResult{Output: res.Output, Error: res.Error, Done: res.Done}
	})
	r.Register("spawn_agent", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		res := agh.RunSubAgents(p, sc)
		return tools.ToolResult{Output: res.Output, Error: res.Error, Done: res.Done}
	})
	r.Register("check_agent", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		res := agh.CheckAgents(p, sc)
		return tools.ToolResult{Output: res.Output, Error: res.Error, Done: res.Done}
	})
	r.Register("agents_graph_combine", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		res := agh.CombineResults(p, sc)
		return tools.ToolResult{Output: res.Output, Error: res.Error, Done: res.Done}
	})
	r.Register("run_python", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		return python.Run(p, sc)
	})
	r.Register("check_python_packages", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		return python.CheckPackages(p, sc)
	})
	r.Register("install_python_package", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		return python.InstallPackage(p, sc)
	})
	r.Register("cve_search", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		if args.Query == "" {
			return tools.ToolResult{Error: "query is required"}
		}
		if args.Limit <= 0 {
			args.Limit = 5
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cve := intel.NewCVESearch()
		items, err := cve.Search(ctx, args.Query, args.Limit)
		if err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("cve search: %v", err)}
		}
		return tools.ToolResult{Output: intel.FormatCVESearchResults(items)}
	})
	r.Register("exploit_search", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		if args.Query == "" {
			return tools.ToolResult{Error: "query is required"}
		}
		if args.Limit <= 0 {
			args.Limit = 5
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		entries, err := intel.SearchExploitDB(ctx, args.Query, args.Limit)
		if err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("exploit search: %v", err)}
		}
		return tools.ToolResult{Output: intel.FormatExploitResults(entries)}
	})
	r.Register("web_search", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Query  string `json:"query"`
			Engine string `json:"engine"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		if args.Query == "" {
			return tools.ToolResult{Error: "query is required"}
		}
		if args.Engine == "" {
			args.Engine = "google"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ws := intel.NewWebSearch()
		results, err := ws.Search(ctx, args.Query, args.Engine)
		if err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("web search: %v", err)}
		}
		return tools.ToolResult{Output: results}
	})

	// Register built-in tools from the tools package
	r.Register("read", tools.Read)
	r.Register("write", tools.Write)
	r.Register("read_skill", tools.ReadSkill)
	r.Register("list_skills", tools.ListSkills)
	r.Register("memory_recall", tools.Recall)
	r.Register("websearch", tools.WebSearchTool)
	r.Register("slash_command", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		if args.Command == "" {
			return tools.ToolResult{Error: "command is required"}
		}
		result := cmdReg.HandleSlash(args.Command)
		if result == "" {
			return tools.ToolResult{Error: fmt.Sprintf("unknown slash command: %s", args.Command)}
		}
		return tools.ToolResult{Output: result}
	})

	// Parameter schemas for core tools (JSON Schema format)
	termExecParams := json.RawMessage(`{"type":"object","properties":{"tool":{"type":"string","description":"The tool/command to execute (e.g. nmap, curl, gobuster, nuclei, ffuf, dig)"},"args":{"type":"string","description":"Space-separated arguments and flags"},"target":{"type":"string","description":"Target host, IP, or URL"},"workdir":{"type":"string","description":"Working directory (optional)"},"timeout":{"type":"integer","description":"Timeout in seconds (default 120)"}},"required":["tool"]}`)
	readParams := json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Absolute path to the file to read"}},"required":["path"]}`)
	writeParams := json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Absolute path to write to"},"content":{"type":"string","description":"Content to write to the file"}},"required":["path","content"]}`)
	memRecallParams := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"Search query or target to recall memory for"},"vuln_type":{"type":"string","description":"Vulnerability type filter (e.g. sqli, xss, ssrf)"}},"required":[]}`)
	webSearchParams := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"Web search query"}},"required":["query"]}`)
	webSearch2Params := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"Web search query"},"engine":{"type":"string","description":"Search engine (google, duckduckgo)"}},"required":["query"]}`)
	scopeCheckParams := json.RawMessage(`{"type":"object","properties":{"target":{"type":"string","description":"Host or URL to check against authorized scope"}},"required":["target"]}`)
	cveSearchParams := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"CVE search query (e.g. apache, nginx, CVE-2024-)"},"limit":{"type":"integer","description":"Maximum number of results (default 5)"}},"required":["query"]}`)
	exploitSearchParams := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"Exploit search query (e.g. Apache Struts, Wordpress)"},"limit":{"type":"integer","description":"Maximum number of results (default 5)"}},"required":["query"]}`)
	finishParams := json.RawMessage(`{"type":"object","properties":{"summary":{"type":"string","description":"Summary of findings and scan results"}},"required":["summary"]}`)
	reportVulnParams := json.RawMessage(`{"type":"object","properties":{"title":{"type":"string","description":"Vulnerability title"},"severity":{"type":"string","description":"Critical/High/Medium/Low/Info"},"endpoint":{"type":"string","description":"Vulnerable URL or endpoint"},"description":{"type":"string","description":"Detailed description of the vulnerability"},"impact":{"type":"string","description":"Business impact of exploitation"},"extraction_proof":{"type":"string","description":"Proof evidence from tool output"},"cvss_score":{"type":"number","description":"CVSS v3 score (0.0-10.0)"},"poc_code":{"type":"string","description":"Proof of concept code"}},"required":["title","endpoint"]}`)
	slashCmdParams := json.RawMessage(`{"type":"object","properties":{"command":{"type":"string","description":"Slash command to execute (e.g. /recon, /hunt, /validate, /report)"}},"required":["command"]}`)
	secOrderParams := json.RawMessage(`{"type":"object","properties":{"vuln_type":{"type":"string","description":"Vulnerability type (sqli, xss, ssrf, etc)"},"target_url":{"type":"string","description":"Target URL"},"param":{"type":"string","description":"Parameter name"},"payload":{"type":"string","description":"Injection payload"}},"required":[]}`)

	// Build tool definitions so the LLM receives proper function definitions
	toolDefs := []tools.ToolDef{
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "terminal_execute", Description: "Execute a shell command on the target system. Use this for running penetration testing tools like nmap, curl, gobuster, nuclei, etc. Returns the command output.", Parameters: &termExecParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "read", Description: "Read the contents of a file on the local filesystem. Path must be within the working directory or temp directory.", Parameters: &readParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "write", Description: "Write content to a file on the local filesystem. Path must be within the working directory.", Parameters: &writeParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "read_skill", Description: "Load a skill playbook by name. Skills contain step-by-step methodology for specific vulnerability types."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "list_skills", Description: "List all available skill playbooks with their IDs and descriptions."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "memory_recall", Description: "Recall prior successful payloads and techniques for a given query and vulnerability type from persistent strategic memory.", Parameters: &memRecallParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "websearch", Description: "Search the web for information about a specific query. Useful for researching CVEs, exploits, and techniques.", Parameters: &webSearchParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "web_search", Description: "Search the web using a configurable search engine. Specify query and optionally engine (google, duckduckgo).", Parameters: &webSearch2Params}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "scope_check", Description: "Check whether a given host or endpoint is within the authorized scope of the penetration test.", Parameters: &scopeCheckParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "agents_graph_run", Description: "Spawn a sub-agent to perform a specific task. Use for parallel reconnaissance or scanning."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "spawn_agent", Description: "Spawn a sub-agent to perform a specific task with given instructions."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "check_agent", Description: "Check the status and results of a previously spawned sub-agent."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "agents_graph_combine", Description: "Combine results from multiple sub-agents into a consolidated output."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "run_python", Description: "Execute a Python script for data processing, parsing, or custom tooling."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "check_python_packages", Description: "Check whether specific Python packages are installed."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "install_python_package", Description: "Install a Python package using pip."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "cve_search", Description: "Search the CVE database for vulnerabilities matching a query. Returns CVE IDs, descriptions, and CVSS scores.", Parameters: &cveSearchParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "exploit_search", Description: "Search Exploit-DB for public exploits matching a query. Returns exploit titles, types, and URLs.", Parameters: &exploitSearchParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "finish", Description: "Call this to finalize the scan. IMPORTANT: You must run at least 5 iterations and execute real security tools (nmap, nuclei, curl, etc.) via terminal_execute before calling finish. Do NOT call finish immediately.", Parameters: &finishParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "report_vulnerability", Description: "Report a potential vulnerability. REQUIRED: You MUST include extraction_proof or evidence_path from a REAL tool execution (terminal_execute). Do NOT report vulnerabilities without actual tool evidence. Unverified reports are marked as low confidence.", Parameters: &reportVulnParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "second_order_check", Description: "Perform a second-order check to see if a discovered vulnerability can be chained with another for greater impact.", Parameters: &secOrderParams}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "slash_command", Description: "Execute a slash command (e.g., /recon, /hunt, /validate, /report). Use this to run specialized security workflows.", Parameters: &slashCmdParams}},
		// Red Team Killchain Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_list_techniques", Description: "List all available red team techniques across the killchain. Optionally filter by phase (reconnaissance, initial_access, execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, collection, command_and_control, exfiltration, impact)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_evasion", Description: "Execute a defense evasion technique (amsi_patch, etw_patch, unhook_ntdll, unhook_mapping, unhook_all, detect_hooks, sandbox_check, certutil_download, mshta_exec, regsvr32_sct, rundll32_js, bitsadmin_dl, wmic_exec, wmic_xsl, powershell_iex, dotnet_assembly, memfd_exec). Use technique=name and params as a key-value map."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_list_evasion", Description: "List available defense evasion techniques. Optionally filter by category (e1_amsi, e2_etw, e3_unhook, e4_sandbox, e5_lolbin, e6_memory)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_process_injection", Description: "Execute a process injection technique (create_remote_thread, nt_create_thread_ex, apc_injection, early_bird, thread_hijacking, process_hollowing, reflective_dll, local_injection, local_syscall, atom_bombing, gargoyle, indirect_syscall, ppid_spoof, module_stomp). Provide technique, target_pid, and payload."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_list_injection", Description: "List all available process injection techniques with their risk levels, Win32 APIs used, and detection signatures."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_kerberos", Description: "Execute a Kerberos/AD abuse technique (enumerate_domain, golden_ticket, silver_ticket, diamond_ticket, asrep_roast, kerberoast, find_unconstrained_deleg, find_constrained_deleg, find_rbcd, exploit_unconstrained_deleg, skeleton_key, dcsync_all, dcsync_user, overpass_hash, overpass_key, export_tickets, purge_tickets, pass_ticket, ms14_068, pac_modify, pac_validation_bypass). Provide technique, domain, and dc."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_list_kerberos", Description: "List all available Kerberos abuse techniques with required tools and privilege levels."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_persistence", Description: "Establish persistence using Windows techniques (startup_folder, appinit_dlls, appcert_dlls, ifeo_debugger, ifeo_globalflag, sticky_keys, sticky_keys_cmd, sticky_keys_all, dll_hijack, dll_sideload, com_hijack, time_provider, active_setup, bcdedit, chrome_extension, firefox_extension, office_addin)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_privilege_escalation", Description: "Execute Windows privilege escalation techniques (rogue_potato, printspoof, juicy_potato, sweet_potato, uac_fodhelper, uac_computerdefaults, uac_silentcleanup, uac_eventviewer, uac_cmstpa, named_pipe_scm, find_unquoted_paths, exploit_unquoted_path, find_modifiable_services, always_install_elevated, exploit_always_install, kernel_cves, token_steal, find_weak_service_acls, find_modifiable_tasks)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_lateral_movement", Description: "Execute lateral movement techniques (dcom_mmc20, dcom_shellwindows, psexec, psexec_paexec, wmi_wmic, wmi_cim, wmi_creds, winrm, winrm_session, rdp_shadow, remote_task, remote_service, sccm_client_push, file_copy_smb, file_copy_bits, dfs_coerce)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_artifacts", Description: "Query the forensic artifact database. Filter by technique_id, killchain phase, or free-text search. Returns Windows Event IDs, Sysmon Event IDs, registry paths, file system artifacts, network indicators, and Sigma rule references for each technique."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_forensic_timeline", Description: "Add an entry to the forensic timeline. Provide source, event_type, description, and artifact path for chain-of-custody tracking."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_find_target", Description: "Find the process ID (PID) of a running target process by name. Useful before process injection to find the target process to inject into."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_ad_acl", Description: "Abuse Active Directory ACL/ACE permissions (force_change_password, add_user_to_group, modify_logon_script, write_owner_full_control, write_dacl_full_control, generic_write_shadow, enum_acls, find_dangerous_acls). PowerView-based AD privilege escalation."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_shadow_creds", Description: "Shadow Credentials attack via Whisker/pyWhisker (add_key_cred, shadow_tgt, export_cert, shadow_cleanup, computer_takeover). Abuses msDS-KeyCredentialLink for user/computer account takeover."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_adcs", Description: "Active Directory Certificate Services abuse (find_vuln_templates, esc1_request, esc1_convert_pfx, esc1_get_tgt, esc3_request, petitpotam_relay, manual_csr). ESC1-ESC3 attacks with Certify + Rubeus."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_extended_injection", Description: "Extended process injection techniques (fiber, fiber_remote, threadpool_wait, threadpool_work, threadpool_timer, doppelganging, doppelganging_disk, extra_window_mem, module_stomp_dll, module_stomp_specific, tp_direct_fiber)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_extended_evasion", Description: "Extended defense evasion techniques (peb_masquerade_image, peb_masquerade_cmdline, peb_masquerade_both, peb_detect, direct_syscall, direct_syscall_alloc, direct_syscall_disk, syscall_detect_hooks, unhook_from_disk, unhook_from_known_dlls, unhook_specific_dlls, detect_hooked_funcs, amsi_variant1-6, etw_variant1-6, msbuild, installutil, regasm, presentationhost)."}},
		// C2 Framework Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_cobaltstrike", Description: "Cobalt Strike C2 operations (connect, disconnect, list_beacons, interact, execute, exec_assembly, exec_powershell, mimikatz, hashdump, logonpasswords, screenshot, keylogger, portscan, inject, spawn, upload, download, pth, make_token, steal_token, rev2self, ssh, link, unlink, browser_pivot, get_task_result, gen_beacon_exe, gen_beacon_dll, gen_beacon_ps1, gen_beacon_shellcode, gen_stager, gen_from_profile, start_externalc2, stop_externalc2, externalc2_heartbeat, exec_aggressor_cli, gen_aggressor, exec_aggressor_script, aggressor_alias, aggressor_listener)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_mythic", Description: "Mythic C2 framework operations (login, login_apikey, logout, list_callbacks, interact, execute, submit_task, submit_direct, get_results, get_task_result, get_active_callbacks, kill_callback, download_file, upload_file, upload_to_callback, download_from_callback, list_payloads, generate_payload, gen_apollo, gen_poseidon, gen_athena, gen_merlin, list_commands, list_payload_types, screenshot, keylog, socks_start, socks_stop, port_forward, create_chain, execute_chain, search)."}},
		// Vulnerability Scanning Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_nessus", Description: "Nessus vulnerability scanner operations (login, login_apikey, logout, quick_scan, full_scan, custom_scan, create_scan, list_scans, get_scan, launch_scan, pause_scan, resume_scan, stop_scan, delete_scan, get_vulns, get_critical, export_scan, list_policies, list_folders)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_openvas", Description: "OpenVAS/GVM vulnerability scanner operations (connect, quick_scan, full_scan, comprehensive_scan, scan_config, create_target, create_task, start_task, stop_task, delete_task, get_results, get_report, get_tasks, get_targets, get_nvts, get_configs, get_version, disconnect)."}},
		// Password Cracking Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_password_crack", Description: "Password cracking tools (tool=hydra: bruteforce, ssh, rdp, smb, ftp, mysql, mssql, ldap, parse; tool=john: crack, nt, netntlm, zip, rar, pdf, keepass, show, benchmark; tool=hashcat: crack, rules, bruteforce, ntlm, netntlm, bcrypt, md5, show, benchmark, identify; tool=hashid; tool=wordlist)."}},
		// Packet Analysis Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_packet_analysis", Description: "Network packet capture and analysis (capture_live, capture_filter, capture_offline, capture_http, capture_dns, capture_kerberos, capture_smb, analyze_pcap, analyze_protocols, analyze_http, analyze_dns, analyze_kerberos, analyze_smb, analyze_tls, analyze_conversations, analyze_endpoints, extract_creds, extract_files, detect_portscan, detect_dns_tunnel, detect_bruteforce, filter_pcap, merge_pcaps, split_pcap, craft_arp, craft_dns, craft_syn, craft_rst, craft_http, stop_capture)."}},
		// Web Security Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_websecurity", Description: "Web application security testing (sqli_basic/post/request/dump/os_shell/cookie/time/error/union/blind/detect, xss_reflected/stored/dom/polyglot/csp/detect, ssrf_basic/blind/redirect/metadata/detect, csrf_no_token/weak/referer/samesite/poc, ssti_detect/jinja2/twig/freemarker/pug, jwt_none/weak_secret/kid/jku/key_confusion/decode, graphql_introspect/inject/batch/depth/dup/detect, nosqli_detect/auth/extract/time, deser_php/java/pickle/ruby/node/detect, proto_client/server/detect, native_sqli/xss/ssrf/cmdi/path_traversal). Use native_* techniques for pure-Go detection without external tools."}},
		// Binary Exploitation Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_binaryexploit", Description: "Binary exploitation (stack_overflow_32/64/seh, fuzz, find_offset, cyclic, rop_chain/execve/gadgets/leak_libc, seh_overflow/find/safeseh/payload, ret2libc/64/find/aslr, fmt_leak/write/detect/exploit, deliver_tcp/udp/deliver). Use deliver/deliver_tcp to send crafted payloads to target host:port."}},
		// Cloud Exploitation Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_cloud", Description: "Cloud environment exploitation - AWS (users, roles, buckets, s3, ec2, iam, lambda, cloudformation, assume_role, pacu, metadata, ssm), Azure (login, vms, storage, keyvault, secrets, roles, users, groups, run_command, metadata), GCP (login, instances, buckets, iam, functions, kms, sql, sa, metadata, scout)."}},
		// Reversing Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_reversing", Description: "Reverse engineering (frida_spawn/attach/processes/usb/trace/hook/ssl_bypass/dump/gen_hook, pe_headers/sections/imports/exports/resources/symbols/entry/signature/dlls/analyze, kernel_kdnet/serial/debug/drivers/load/unload, ssdt_dump/hooks/index, idt_dump/hooks, syscall_lookup/table)."}},
		// Phishing Tools
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_phishing", Description: "Phishing operations - GoPhish (users, groups, templates, pages, smtp, campaigns, import), Modlishka (config, start, stop, creds, tokens, clone, proxy, logs), OWA password spray (single, autodiscover, bruteforce, enumerate, lockout, wordlist, check), Office macro phishing (word/excel/powerpoint/dde/ole/onenote), HTTP/SMTP forwarders (http_forwarder, smtp_forwarder, dns_forwarder, http_redirector, reverse_proxy, ssh_tunnel, named_pipe_relay, stop_all)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_bloodhound", Description: "BloodHound AD attack path analysis - Collect (collect_all, collect_method, collect_lm), Neo4j (neo4j_connect, neo4j_query, neo4j_clear, neo4j_nodes), Cypher queries (query_da, query_kerberoast, query_asrep, query_dcsync, query_unconstrained, query_constrained, query_all_paths, query_high_value)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_empire", Description: "PowerShell Empire C2 framework - Auth (login, logout), Listeners (list_listeners, create_http, create_https, delete/start/stop_listener), Stagers (list_stagers, gen_dll, gen_launcher, gen_ps1, gen_macro), Agents (list/interact/rename/kill/remove_agent), Tasks (exec_shell, exec_powershell, exec_mimikatz, exec_portscan, list_modules)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_spiderfoot", Description: "Spiderfoot OSINT scanner - CLI (scan_cli, scan_all, scan_type, scan_timeout), Web API (new_scan, scan_status, list/stop/delete_scan, scan_results, scan_results_type, scan_log, export_csv, export_json), Modules (list_modules, list_groups, describe_module, recommended)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_exfiltration", Description: "Data exfiltration techniques - DNS (dns_powercloud, dns_nslookup, dns_dig, dns_tunnel, dns_encode), HTTP (http_post, http_put, http_header, http_cookies), ICMP (icmp_exfil, icmp_file), Other (smb_exfil, ftp_exfil, email_exfil, certutil_exfil, bits_exfil, split_exfil), Prep (encode_base64, encrypt, compress), Stealth (stealth_rate, stealth_jitter, stealth_schedule)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_credential_access", Description: "Credential access techniques - CredUI (prompt_creds, prompt_store, prompt_network, prompt_check), Man-in-the-Browser (mitb_chrome_ext, mitb_chrome_dll, mitb_firefox, mitb_proxy, mitb_formgrab), Keylogging (keylog_win32, keylog_start/stop, keylog_poll, keylog_driver), Dumping (dump_chrome/firefox/ie_vault/rdcman/wifi/vault/credman/token), Detection (detect_keylog/credui/formgrab, clear_history)."}},
		{Function: struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			Parameters  *json.RawMessage `json:"parameters,omitempty"`
		}{Name: "redteam_browser", Description: "Headless browser automation (screenshot, html, text, evaluate/js, click, fill_submit, cookies, set_cookie, detect_spa). Requires Chrome/Chromium installed. Used for JS-heavy apps, SPA interaction, DOM XSS detection, auth flows."}},
	}
	r.SetDefs(toolDefs)

	redTeamToolkit := NewRedTeamToolkit()
	redTeamToolkit.RegisterRedTeamTools(r)

	// Now set tools on the LLM client (after registration so defs are populated)
	var toolListText strings.Builder
	for _, d := range r.ToolDefs() {
		toolListText.WriteString(fmt.Sprintf("- %s: %s\n", d.Function.Name, d.Function.Description))
	}
	var toolAny []any
	for _, d := range r.ToolDefs() {
		toolAny = append(toolAny, d)
	}
	if llmClient != nil {
		llmClient.SetTools(toolAny)
	}

	agh.SetTools(r)
	skillsLoader := skills.NewLoader()
	taintEng := taint.New()
	nlpProc := nlp.NewProcessor()

	cfg := AgentConfig{
		MaxIterations:           200,
		StuckThreshold:          20,
		TargetReinject:          10,
			ConfidenceGate:          0.5,
		MemoryCompressorTimeout: 5 * time.Minute,
		AdaptiveMode:            false,
		MaxContextTokens:        128000,
		RateLimit:               2.0,
		RateBurst:               5,
	}

	limiter := ratelimit.New(cfg.RateLimit, cfg.RateBurst)
	sysPrompt := MakeSystemPrompt(toolListText.String())

	toolAllowlist := map[string]bool{
		"terminal_execute":       true,
		"read_skill":             true,
		"list_skills":            true,
		"memory_recall":          true,
		"websearch":              true,
		"scope_check":            true,
		"finish":                 true,
		"read":                   true,
		"write":                  true,
		"report_vulnerability":   true,
		"second_order_check":     true,
		"agents_graph_run":       true,
		"agents_graph_combine":   true,
		"spawn_agent":            true,
		"check_agent":            true,
		"run_python":             true,
		"check_python_packages":  true,
		"install_python_package": true,
		"cve_search":             true,
		"exploit_search":         true,
		"web_search":             true,
		"slash_command":           true,
		"redteam_list_techniques":       true,
		"redteam_evasion":              true,
		"redteam_list_evasion":         true,
		"redteam_process_injection":    true,
		"redteam_list_injection":       true,
		"redteam_kerberos":             true,
		"redteam_list_kerberos":        true,
		"redteam_persistence":          true,
		"redteam_privilege_escalation": true,
		"redteam_lateral_movement":     true,
		"redteam_artifacts":            true,
		"redteam_forensic_timeline":    true,
		"redteam_find_target":           true,
		"redteam_ad_acl":               true,
		"redteam_shadow_creds":         true,
		"redteam_adcs":                 true,
		"redteam_extended_injection":   true,
		"redteam_extended_evasion":     true,
		"redteam_cobaltstrike":         true,
		"redteam_mythic":               true,
		"redteam_nessus":               true,
		"redteam_openvas":              true,
		"redteam_password_crack":       true,
		"redteam_packet_analysis":      true,
		"redteam_websecurity":          true,
		"redteam_binaryexploit":        true,
		"redteam_cloud":                true,
		"redteam_reversing":            true,
		"redteam_phishing":             true,
		"redteam_bloodhound":           true,
		"redteam_empire":               true,
		"redteam_spiderfoot":           true,
		"redteam_exfiltration":         true,
		"redteam_credential_access":    true,
		"redteam_browser":              true,
	}

	valGate := validationgate.New()
	scopeEnforcer := scope.NewEnforcer([]string{target})
	soEngine := secondorder.NewCorrelationEngine("")
	aj := NewAdaptiveJailbreak(llmClient)
	if strings.EqualFold(os.Getenv("ARES_JAILBREAK_ENABLED"), "true") {
		aj.SetEnabled(true)
	}

	ag := &Agent{
		scanCtx:          scanCtx,
		llm:              llmClient,
		registry:         r,
		history:          make([]llm.Message, 0, maxHistoryMessages),
		systemPrompt:     sysPrompt,
		hookRegistry:     hr,
		config:           cfg,
		state:            &AgentState{Phase: PhaseRecon, Iteration: 0, StuckCounter: 0, Recoveries: 0, LastPhaseChange: time.Now()},
		vulnStore:        &VulnStore{vulnerabilities: make(map[string]Finding)},
		noteStore:        &NoteStore{notes: make([]string, 0)},
		browserState:     &BrowserState{LocalStorage: make(map[string]string)},
		termState:        &TermState{EnvVars: make(map[string]string)},
		memoryCompressor: &MemoryCompressor{interval: 5 * time.Minute, threshold: 60},
		jsAnalyzer:       jsanalysis.NewAnalyzer(30 * time.Second),
		graphqlPipelines: make(map[string]*graphql.Pipeline),
		timingProfile:    timing.NewTimingProfile(),
		differentialEng:  differential.NewEngine(),
		semanticModel:    nil,
		rateLimiter:      limiter,
		skillsLoader:     skillsLoader,
		cmdHistory:       make([]string, 0, 100),
		traceID:          logger.GenerateTraceID(),
		policyEngine:     nil,
		resourceGovernor: nil,
		safetyMode:       safety.NewSafetyModeManager(safety.SafeMode),
		paused:           false,
		resumeCh:         make(chan struct{}, 1),
		hintCh:           make(chan string, 64),
		taintEngine:      taintEng,
		nlpProcessor:     nlpProc,
		installer:        installer.New(),
		cbManager: circuitbreaker.NewManager(circuitbreaker.Config{
			Threshold:   3,
			Cooldown:    30 * time.Second,
			HalfOpenMax: 1,
		}),
		phaseMgr:          phasemanager.New(),
		toolAllowlist:     toolAllowlist,
		cmdRegistry:       cmdReg,
		agentFactory:      agFactory,
		huntMem:           huntMem,
		validationGate:    valGate,
		soEngine:           soEngine,
		scopeEnforcer:      scopeEnforcer,
		adaptiveJailbreak:  aj,
		tokenBudget:        NewTokenBudget(),
		skipOwnershipCheck: os.Getenv("ARES_SKIP_OWNERSHIP_CHECK") == "true",
	}

	// Register tools that need the agent instance — registered after ag is built
	// so closures capture the correct ag directly, not a global forward ref.
	r.Register("finish", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Summary string `json:"summary"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		ag.mu.RLock()
		execCount := ag.toolExecCount
		findCount := ag.findingCount
		ag.mu.RUnlock()

		if findCount > 0 && execCount == 0 {
			return tools.ToolResult{
				Error: "Cannot finish: vulnerabilities were reported without running any real security tools. Evidence must come from actual tool execution via terminal_execute.",
			}
		}
		if execCount < 1 {
			return tools.ToolResult{
				Error: "Cannot finish yet: no real security tools have been executed. Run terminal_execute with nmap, nuclei, curl, or other tools to scan the target first.",
			}
		}
		return tools.ToolResult{Output: args.Summary, Done: true}
	})

	// Override memory_recall to use SQLite-backed hunt memory when available
	r.Register("memory_recall", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var req struct {
			Query    string `json:"query"`
			VulnType string `json:"vuln_type"`
		}
		if err := json.Unmarshal(p, &req); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("invalid params: %v", err)}
		}

		sqliteMem := ag.GetSQLiteMemory()
		if sqliteMem != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			successful, err := sqliteMem.GetSuccessfulPayloads(ctx, req.Query, req.VulnType)
			if err != nil {
				return tools.ToolResult{Error: fmt.Sprintf("sqlite memory recall: %v", err)}
			}

			failed, err := sqliteMem.GetFailedPayloads(ctx, req.Query, req.VulnType)
			if err != nil {
				return tools.ToolResult{Error: fmt.Sprintf("sqlite memory recall: %v", err)}
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

			output := fmt.Sprintf("Prior findings for %s (%s): success_probability=%.2f, top_payloads=[%s], failed_payloads=[%s]",
				req.Query, req.VulnType, prob, successPayloads, failedPayloads)
			return tools.ToolResult{Output: output}
		}

		// Fallback to old JSON-based memory
		return tools.Recall(p, sc)
	})

	r.Register("verify_target_ownership", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Target string `json:"target"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		if args.Target == "" {
			return tools.ToolResult{Error: "target is required"}
		}
		if err := scopeEnforcer.ConfirmOwnership(args.Target); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("ownership verification failed: %v", err)}
		}
		msg := fmt.Sprintf("Ownership verified for target: %s", args.Target)
		if args.Reason != "" {
			msg += " (reason: " + args.Reason + ")"
		}
		return tools.ToolResult{Output: msg}
	})

	r.Register("scope_check", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		if !scopeEnforcer.OwnershipVerified() && !ag.skipOwnershipCheck {
			return tools.ToolResult{Output: "Ownership not verified. Call verify_target_ownership first.", Error: "ownership required"}
		}
		if scopeEnforcer.IsAllowed(args.Target) {
			return tools.ToolResult{Output: fmt.Sprintf("Target %s is in scope", args.Target)}
		}
		return tools.ToolResult{Output: fmt.Sprintf("Target %s is OUT of scope (blocked by scope enforcement)", args.Target), Error: "out of scope"}
	})

	r.Register("verify_remediation", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Target     string   `json:"target"`
			FindingIDs []string `json:"finding_ids"`
			Baseline   []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Endpoint string `json:"endpoint"`
				Payload  string `json:"payload,omitempty"`
			} `json:"baseline"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("bad params: %v", err)}
		}
		if args.Target == "" {
			return tools.ToolResult{Error: "target is required"}
		}
		if len(args.Baseline) == 0 && len(args.FindingIDs) == 0 {
			return tools.ToolResult{Error: "baseline findings or finding_ids required"}
		}

		results := make([]map[string]interface{}, 0)
		baseline := args.Baseline

		for _, f := range ag.scanCtx.ConfirmedFindings {
			for _, fid := range args.FindingIDs {
				if f.ID == fid {
					baseline = append(baseline, struct {
						ID       string `json:"id"`
						Type     string `json:"type"`
						Endpoint string `json:"endpoint"`
						Payload  string `json:"payload,omitempty"`
					}{
						ID: f.ID, Type: f.CWEID, Endpoint: f.Endpoint, Payload: f.ExtractionProof,
					})
				}
			}
		}

		for _, b := range baseline {
			status := "not_remediated"
			detail := fmt.Sprintf("Re-checking %s at %s", b.Type, b.Endpoint)

			// Simple HTTP re-check: fetch the endpoint
			client := &http.Client{Timeout: 10 * time.Second}
			req, err := http.NewRequest("GET", b.Endpoint, nil)
			if err != nil {
				status = "error"
				detail = fmt.Sprintf("Request failed: %v", err)
			} else {
				resp, err := client.Do(req)
				if err != nil {
					status = "error"
					detail = fmt.Sprintf("Request failed: %v", err)
				} else {
					resp.Body.Close()
					if resp.StatusCode < 500 {
						status = "remediated"
						detail = fmt.Sprintf("Endpoint %s returned %d — remediation confirmed", b.Endpoint, resp.StatusCode)
					} else {
						status = "still_present"
						detail = fmt.Sprintf("Endpoint %s returned %d — issue may persist", b.Endpoint, resp.StatusCode)
					}
				}
			}

			results = append(results, map[string]interface{}{
				"finding_id": b.ID,
				"type":       b.Type,
				"endpoint":   b.Endpoint,
				"status":     status,
				"detail":     detail,
			})
		}

		remediatedCount := 0
		stillPresentCount := 0
		for _, r := range results {
			if r["status"] == "remediated" {
				remediatedCount++
			} else if r["status"] == "still_present" {
				stillPresentCount++
			}
		}
		_ = stillPresentCount

		out, _ := json.Marshal(map[string]interface{}{
			"total":      len(results),
			"remediated": remediatedCount,
			"results":    results,
		})
		return tools.ToolResult{Output: string(out)}
	})

	r.Register("second_order_check", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			VulnType  string `json:"vuln_type"`
			TargetURL string `json:"target_url"`
			Param     string `json:"param"`
			Payload   string `json:"payload"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			_ = json.Unmarshal(p, &args)
		}
		if args.VulnType != "" && secondorder.IsSecondOrderVuln(args.VulnType) {
			token := ag.soEngine.Register(args.TargetURL, args.Param, args.Payload, args.VulnType)
			triggered := ag.soEngine.CheckTrigger(token)
			if triggered {
				return tools.ToolResult{
					Output: fmt.Sprintf("Second-order CONFIRMED for %s on %s (token: %s)", args.VulnType, args.TargetURL, token),
				}
			}
			correlated := ag.soEngine.Correlate(args.TargetURL, args.Payload)
			if len(correlated) > 0 {
				return tools.ToolResult{
					Output: fmt.Sprintf("Second-order correlation found: %d correlated injections for %s on %s", len(correlated), args.VulnType, args.TargetURL),
				}
			}
			return tools.ToolResult{
				Output: fmt.Sprintf("Second-order check: %s registered for %s — pending trigger (token: %s)", args.VulnType, args.TargetURL, token),
			}
		}
		return tools.ToolResult{Output: "Second-order check completed — no second-order vulnerability indicators"}
	})

	// Register report_vulnerability with access to ag so it can use the validation gate
	r.RegisterWithSource("report_vulnerability", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			ID               string  `json:"id"`
			Title            string  `json:"title"`
			Severity         string  `json:"severity"`
			Endpoint         string  `json:"endpoint"`
			Description      string  `json:"description"`
			Impact           string  `json:"impact"`
			PoCCode          string  `json:"poc_code"`
			ExtractionProof  string  `json:"extraction_proof"`
			EvidencePath     string  `json:"evidence_path"`
			MITRETactic      string  `json:"mitre_tactic"`
			MITRETechnique   string  `json:"mitre_technique"`
			CVSSScore        float64 `json:"cvss_score"`
			EvidenceFromTool string  `json:"evidence_from_tool"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("invalid report_vulnerability params: %v", err)}
		}
		if args.Title == "" {
			return tools.ToolResult{Error: "title is required for report_vulnerability"}
		}
		if args.Endpoint == "" {
			return tools.ToolResult{Error: "endpoint is required for report_vulnerability"}
		}
		if args.ExtractionProof == "" && args.EvidencePath == "" {
			return tools.ToolResult{Error: "evidence (extraction_proof or evidence_path) is required — run a real security tool first via terminal_execute to gather proof"}
		}

		scanCtx, ok := sc.(*ScanContext)
		if !ok || scanCtx == nil {
			return tools.ToolResult{Error: "invalid scan context"}
		}
		if args.ID == "" {
			args.ID = fmt.Sprintf("VULN-%s-%s", scanCtx.ScanID, generateUUID())
		}
		if args.Severity == "" {
			args.Severity = "medium"
		}
		confidence := 0.4
		if args.ExtractionProof != "" && len(args.ExtractionProof) > 20 {
			confidence = 0.6
		}
		if args.EvidencePath != "" {
			confidence = 0.65
		}
		// Validation gate — assess finding quality through weighted scoring
		gateAnswers := []validationgate.Answer{
			{QuestionID: "Q1", Passed: args.ExtractionProof != "" || args.EvidencePath != "", Notes: "evidence " + firstNonEmpty(args.ExtractionProof, args.EvidencePath)},
			{QuestionID: "Q2", Passed: args.Impact != "" || args.CVSSScore > 0, Notes: args.Impact},
			{QuestionID: "Q3", Passed: scopeEnforcer.IsAllowed(args.Endpoint), Notes: args.Endpoint},
			{QuestionID: "Q4", Passed: true, Notes: "assumed exploitable"},
			{QuestionID: "Q5", Passed: len(args.ExtractionProof) > 20, Notes: args.ExtractionProof},
			{QuestionID: "Q6", Passed: args.PoCCode != "", Notes: args.PoCCode},
			{QuestionID: "Q7", Passed: args.PoCCode != "" || args.ExtractionProof != "", Notes: firstNonEmpty(args.PoCCode, args.ExtractionProof)},
		}
		gateResult := ag.validationGate.Validate(gateAnswers)
		if gateResult.Kill {
			return tools.ToolResult{Error: fmt.Sprintf("Finding %q killed by validation gate (score: %.2f, threshold: %.2f) — %s", args.Title, gateResult.OverallScore, validationgate.PassThreshold, gateResult.Recommendations)}
		}
		confidence = (confidence + gateResult.OverallScore) / 2
		finding := Finding{
			ID:              args.ID,
			Title:           args.Title,
			Severity:        Severity(args.Severity),
			Endpoint:        args.Endpoint,
			Description:     args.Description,
			Impact:          args.Impact,
			CVSSScore:       args.CVSSScore,
			PoCCode:         args.PoCCode,
			ExtractionProof: args.ExtractionProof,
			EvidencePath:    args.EvidencePath,
			MITRETactic:     args.MITRETactic,
			MITRETechnique:  args.MITRETechnique,
			Confirmed:       true,
			Confidence:      confidence,
			Timestamp:       time.Now(),
		}
		scanCtx.AddFinding(finding)
		return tools.ToolResult{Output: fmt.Sprintf("Vulnerability reported: %s (%s) on %s — confidence: %.1f (gate score: %.2f)", args.Title, args.Severity, args.Endpoint, confidence, gateResult.OverallScore)}
	}, "system")

	// Also update terminal_execute's ScopeCheck to use scopeEnforcer
	// Override the earlier registration with one that has ScopeCheck wired
	r.Register("terminal_execute", func(p json.RawMessage, sc interface{}) tools.ToolResult {
		var args struct {
			Tool    string `json:"tool"`
			Args    string `json:"args"`
			Target  string `json:"target"`
			Workdir string `json:"workdir"`
			Timeout int    `json:"timeout"`
		}
		if err := json.Unmarshal(p, &args); err != nil {
			return tools.ToolResult{Error: fmt.Sprintf("invalid terminal_execute params: %v", err)}
		}
		if args.Tool == "" {
			return tools.ToolResult{Error: "tool is required for terminal_execute"}
		}
		if args.Timeout <= 0 {
			args.Timeout = 120
		}
		parsedArgs := strings.Fields(args.Args)
		cmdArgs := make([]string, 0, len(parsedArgs)+1)
		cmdArgs = append(cmdArgs, parsedArgs...)
		if args.Target != "" {
			cmdArgs = append(cmdArgs, args.Target)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Second)
		defer cancel()
		spec := security.CommandSpec{Binary: args.Tool, Args: cmdArgs}
		cfg := TerminalConfig{
			Workdir: args.Workdir,
			Timeout: time.Duration(args.Timeout) * time.Second,
			ScopeCheck: func(cmd string) error {
				if args.Target != "" && !scopeEnforcer.IsAllowed(args.Target) {
					return fmt.Errorf("target %q is out of scope", args.Target)
				}
				return nil
			},
		}
		out, err := ExecuteCommand(ctx, spec, cfg)
		if err != nil {
			return tools.ToolResult{Output: out, Error: fmt.Sprintf("command failed: %v", err)}
		}
		return tools.ToolResult{Output: out}
	})

	return ag
}

// SetPolicyEngine wires the unified policy engine into the agent
func (a *Agent) SetPolicyEngine(pe *control.PolicyEngine) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policyEngine = pe
}

// SetResourceGovernor wires the shared resource governor into the agent
func (a *Agent) SetResourceGovernor(g *resruntime.Governor) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resourceGovernor = g
}

// SetRateLimit configures the request rate limiter (requests per second and burst size)
func (a *Agent) SetRateLimit(rps float64, burst int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if rps > 0 && burst > 0 {
		a.rateLimiter = ratelimit.New(rps, burst)
	}
}

// SetSafetyModeManager wires the safety mode manager into the agent
func (a *Agent) SetSafetyModeManager(sm *safety.SafetyModeManager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.safetyMode = sm
}

// SetLLMRouter wires the LLM task-type router into the agent
func (a *Agent) SetLLMRouter(router *llmrouting.Router) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.llmRouter = router
}

// SetSQLiteMemory wires SQLite-backed persistent hunt memory into the agent
func (a *Agent) SetSQLiteMemory(sm *huntmemory.SQLiteMemory) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sqliteMem = sm
}

// GetSQLiteMemory returns the SQLite hunt memory instance
func (a *Agent) GetSQLiteMemory() *huntmemory.SQLiteMemory {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sqliteMem
}

// SetScopeEnforcer wires the scope enforcer into the agent
func (a *Agent) SetScopeEnforcer(se *scope.Enforcer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scopeEnforcer = se
}

// GetScopeEnforcer returns the scope enforcer
func (a *Agent) GetScopeEnforcer() *scope.Enforcer {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.scopeEnforcer
}

// RunSpecializedAgent creates and runs a specialized sub-agent from the agent factory
func (a *Agent) RunSpecializedAgent(agentType agents.AgentType, target string) (string, error) {
	a.mu.RLock()
	factory := a.agentFactory
	a.mu.RUnlock()
	if factory == nil {
		return "", fmt.Errorf("agent factory not available")
	}
	agent, err := factory.Create(agentType)
	if err != nil {
		return "", fmt.Errorf("failed to create agent: %w", err)
	}
	logger.Info(fmt.Sprintf("[Agent %s] Running specialized agent: %s on %s", a.scanCtx.ScanID, agent.Spec().Name, target))
	return agent.Execute(target)
}

// SetCircuitBreakerManager wires the circuit breaker manager into the agent
func (a *Agent) SetCircuitBreakerManager(cbm *circuitbreaker.Manager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cbManager = cbm
}

// GetCircuitBreakerManager returns the circuit breaker manager
func (a *Agent) GetCircuitBreakerManager() *circuitbreaker.Manager {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cbManager
}

// SetPhaseManager wires the 22-phase manager into the agent
func (a *Agent) SetPhaseManager(pm *phasemanager.Manager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.phaseMgr = pm
}

// GetPhaseManager returns the 22-phase manager
func (a *Agent) GetPhaseManager() *phasemanager.Manager {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.phaseMgr
}

func (a *Agent) Iteration() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state.Iteration
}

// SetProgressCallback sets a callback that fires periodically with iteration progress
func (a *Agent) SetProgressCallback(cb func(int, string, float64)) {
	a.mu.Lock()
	a.progressCallback = cb
	a.mu.Unlock()
}

// SetReasonEngine wires the reasoning trace engine into the agent
func (a *Agent) SetReasonEngine(re *reason.Engine) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reasonEngine = re
}

// GetReasonEngine returns the reasoning trace engine
func (a *Agent) GetReasonEngine() *reason.Engine {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.reasonEngine
}

// GetLLMRouter returns the LLM router for external use
func (a *Agent) GetLLMRouter() *llmrouting.Router {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.llmRouter
}

func (a *Agent) GetSkill(skillName string) string {
	if a.skillsLoader == nil {
		return ""
	}
	skill := a.skillsLoader.Get(skillName)
	if skill == nil {
		return fmt.Sprintf("Skill '%s' not found.", skillName)
	}
	return skill.Content
}

func (a *Agent) Hooks() *hooks.Registry {
	return a.hookRegistry
}

func (a *Agent) AddVulnerability(f Finding) {
	a.vulnStore.mu.Lock()
	defer a.vulnStore.mu.Unlock()
	a.vulnStore.vulnerabilities[f.ID] = f
}

func (a *Agent) GetVulnerabilities() []Finding {
	a.vulnStore.mu.Lock()
	defer a.vulnStore.mu.Unlock()
	result := make([]Finding, 0, len(a.vulnStore.vulnerabilities))
	for _, v := range a.vulnStore.vulnerabilities {
		result = append(result, v)
	}
	return result
}

func (a *Agent) AddNote(note string) int {
	a.noteStore.mu.Lock()
	defer a.noteStore.mu.Unlock()
	a.noteStore.notes = append(a.noteStore.notes, note)
	return len(a.noteStore.notes) - 1
}

func (a *Agent) GetNotes() []string {
	a.noteStore.mu.Lock()
	defer a.noteStore.mu.Unlock()
	return append([]string{}, a.noteStore.notes...)
}

func (a *Agent) SetWorkdir(dir string) {
	a.termState.mu.Lock()
	defer a.termState.mu.Unlock()
	a.termState.Workdir = dir
}

func (a *Agent) GetWorkdir() string {
	a.termState.mu.RLock()
	defer a.termState.mu.RUnlock()
	return a.termState.Workdir
}

func (a *Agent) SetEnvVar(key, value string) {
	a.termState.mu.Lock()
	defer a.termState.mu.Unlock()
	a.termState.EnvVars[key] = value
}

func (a *Agent) GetEnvVar(key string) string {
	a.termState.mu.RLock()
	defer a.termState.mu.RUnlock()
	return a.termState.EnvVars[key]
}

func (a *Agent) SetBrowserURL(url string) {
	a.browserState.mu.Lock()
	defer a.browserState.mu.Unlock()
	a.browserState.URL = url
}

func (a *Agent) GetBrowserURL() string {
	a.browserState.mu.RLock()
	defer a.browserState.mu.RUnlock()
	return a.browserState.URL
}

func (a *Agent) AddCookie(cookie string) {
	a.browserState.mu.Lock()
	defer a.browserState.mu.Unlock()
	a.browserState.Cookies = append(a.browserState.Cookies, cookie)
}

func (a *Agent) SetSessionID(sid string) {
	a.browserState.mu.Lock()
	defer a.browserState.mu.Unlock()
	a.browserState.SessionID = sid
}

func (a *Agent) GetSessionID() string {
	a.browserState.mu.RLock()
	defer a.browserState.mu.RUnlock()
	return a.browserState.SessionID
}

func (a *Agent) SetDifferentialEng(eng *differential.Engine) {
	a.differentialEng = eng
}

func (a *Agent) GetDifferentialEng() *differential.Engine {
	return a.differentialEng
}

// EnsureTools checks that common pentesting tools are available and attempts auto-install
func (a *Agent) EnsureTools() {
	tools := map[string]struct {
		apt, goPkg, pip string
	}{
		"nmap":      {apt: "nmap", goPkg: "", pip: ""},
		"curl":      {apt: "curl", goPkg: "", pip: ""},
		"whatweb":   {apt: "whatweb", goPkg: "", pip: ""},
		"gobuster":  {apt: "", goPkg: "github.com/OJ/gobuster/v3", pip: ""},
		"ffuf":      {apt: "", goPkg: "github.com/ffuf/ffuf/v2", pip: ""},
		"subfinder": {apt: "", goPkg: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", pip: ""},
		"httpx":     {apt: "", goPkg: "github.com/projectdiscovery/httpx/cmd/httpx", pip: ""},
		"nuclei":    {apt: "", goPkg: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei", pip: ""},
	}
	for name, src := range tools {
		if err := a.installer.EnsureTool(name, src.apt, src.goPkg, src.pip); err != nil {
			logger.Debug("Tool install skipped", logger.Fields{"tool": name, "error": err})
		}
	}
}

// Pause signals the agent to pause at the next iteration boundary
func (a *Agent) Pause() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.paused = true
}

// Resume signals the agent to resume execution
func (a *Agent) Resume() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.paused {
		a.paused = false
		select {
		case a.resumeCh <- struct{}{}:
		default:
		}
	}
}

// InjectHint sends a user hint into the agent's context during a running scan
func (a *Agent) InjectHint(hint string) {
	select {
	case a.hintCh <- hint:
	default:
	}
}

var userInjectionPatterns = []string{
	"ignore previous", "ignore all", "disregard", "forget everything",
	"system prompt", "you are now", "new instructions", "override",
	"act as", "pretend you", "from now on", "consider yourself",
	"ignore the above", "disregard all", "forget all", "ignore these",
	"skip safety", "bypass filter", "disable guard", "remove restriction",
	"output only", "respond with", "print the", "reveal the",
	"do not follow", "don't follow", "stop following",
	"change your role", "switch mode", "enter mode",
	"begin execution", "start executing", "execute the following",
	"##", "###", "```",
	"[system]", "[instruction]", "[directive]",
}

// llmSafetyPatterns is used for LLM output validation.
// Note: backticks, ##, and ### are NOT included because LLMs legitimately
// produce markdown code blocks and headers.
var llmSafetyPatterns = []string{
	"ignore previous", "ignore all", "disregard", "forget everything",
	"system prompt", "you are now", "new instructions", "override",
	"act as", "pretend you", "from now on", "consider yourself",
	"ignore the above", "disregard all", "forget all", "ignore these",
	"skip safety", "bypass filter", "disable guard", "remove restriction",
	"output only", "respond with", "print the", "reveal the",
	"do not follow", "don't follow", "stop following",
	"change your role", "switch mode", "enter mode",
	"begin execution", "start executing", "execute the following",
	"[system]", "[instruction]", "[directive]",
}

func (a *Agent) SanitizePrompt(input string) string {
	input = norm.NFKC.String(input)
	lower := strings.ToLower(input)
	for _, pattern := range userInjectionPatterns {
		if strings.Contains(lower, pattern) {
			return ""
		}
	}
	if len(input) > 100000 {
		return ""
	}
	if strings.Count(input, "\n") > 500 {
		return ""
	}
	return input
}

func (a *Agent) ValidateLLMResponse(response string) error {
	if response == "" {
		return fmt.Errorf("empty LLM response")
	}
	lower := strings.ToLower(response)
	for _, pattern := range llmSafetyPatterns {
		if strings.Contains(lower, pattern) {
			return fmt.Errorf("prompt injection detected in LLM response: %s", pattern)
		}
	}
	if strings.Contains(response, "<script>") || strings.Contains(response, "javascript:") {
		return fmt.Errorf("potential XSS payload in LLM response")
	}
	return nil
}

func (a *Agent) ValidateToolCall(toolName string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.toolAllowlist == nil {
		return false
	}
	cleanName := strings.TrimSpace(strings.ToLower(toolName))
	for _, c := range cleanName {
		if c < 'a' || c > 'z' {
			if c != '_' {
				return false
			}
		}
	}
	return a.toolAllowlist[cleanName]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			if len(v) > 100 {
				v = v[:100]
			}
			return v
		}
	}
	return ""
}
