package agents

import (
	"fmt"

	"github.com/ares/engine/internal/logger"
)

type AgentType int

const (
	ReconAgent            AgentType = iota
	ValidatorAgent        AgentType = iota
	ReportWriterAgent     AgentType = iota
	Web3AuditorAgent      AgentType = iota
	ChainBuilderAgent     AgentType = iota
	AutopilotAgent        AgentType = iota
	CredentialHunterAgent AgentType = iota
	TokenAuditorAgent     AgentType = iota
)

func (t AgentType) String() string {
	switch t {
	case ReconAgent:
		return "ReconAgent"
	case ValidatorAgent:
		return "ValidatorAgent"
	case ReportWriterAgent:
		return "ReportWriterAgent"
	case Web3AuditorAgent:
		return "Web3AuditorAgent"
	case ChainBuilderAgent:
		return "ChainBuilderAgent"
	case AutopilotAgent:
		return "AutopilotAgent"
	case CredentialHunterAgent:
		return "CredentialHunterAgent"
	case TokenAuditorAgent:
		return "TokenAuditorAgent"
	default:
		return "UnknownAgent"
	}
}

type ToolSet []string

type AgentSpec struct {
	Type           AgentType
	Name           string
	Description    string
	Tools          ToolSet
	MaxIterations  int
	ConfidenceGate float64
	SystemPrompt   string
}

type Agent interface {
	Type() AgentType
	Spec() AgentSpec
	Execute(target string) (string, error)
}

type AgentFactory struct {
	specs map[AgentType]*AgentSpec
}

func NewAgentFactory() *AgentFactory {
	f := &AgentFactory{
		specs: make(map[AgentType]*AgentSpec),
	}
	for _, spec := range DefaultSpecs {
		f.specs[spec.Type] = spec
	}
	return f
}

func (f *AgentFactory) Create(agentType AgentType) (Agent, error) {
	spec, ok := f.specs[agentType]
	if !ok {
		return nil, fmt.Errorf("unknown agent type: %v", agentType)
	}

	logger.Debug("Creating agent", logger.Fields{"type": agentType.String(), "name": spec.Name})

	switch agentType {
	case ReconAgent:
		return &reconAgent{spec: *spec}, nil
	case ValidatorAgent:
		return &validatorAgent{spec: *spec}, nil
	case ReportWriterAgent:
		return &reportWriterAgent{spec: *spec}, nil
	case Web3AuditorAgent:
		return &web3AuditorAgent{spec: *spec}, nil
	case ChainBuilderAgent:
		return &chainBuilderAgent{spec: *spec}, nil
	case AutopilotAgent:
		return &autopilotAgent{spec: *spec}, nil
	case CredentialHunterAgent:
		return &credentialHunterAgent{spec: *spec}, nil
	case TokenAuditorAgent:
		return &tokenAuditorAgent{spec: *spec}, nil
	default:
		return nil, fmt.Errorf("unsupported agent type: %v", agentType)
	}
}

func (f *AgentFactory) Specs() map[AgentType]*AgentSpec {
	return f.specs
}

var DefaultSpecs = []*AgentSpec{
	{
		Type:           ReconAgent,
		Name:           "Recon Agent",
		Description:    "Specialized for subdomain enumeration, host discovery, and URL crawling",
		Tools:          []string{"subfinder", "httpx", "nuclei", "katana", "gau", "assetfinder", "amass"},
		MaxIterations:  50,
		ConfidenceGate: 0.6,
		SystemPrompt:   "You are a reconnaissance specialist. Your role is to map the attack surface by discovering subdomains, live hosts, and crawling URLs. Be thorough and methodical.",
	},
	{
		Type:           ValidatorAgent,
		Name:           "Validator Agent",
		Description:    "Implements the 7-Question Gate to independently validate findings",
		Tools:          []string{"curl", "httpie", "python3", "nuclei"},
		MaxIterations:  30,
		ConfidenceGate: 0.75,
		SystemPrompt:   "You are a validation specialist. Independently re-test each finding through the 7-Question Gate. Assign confidence scores and kill false positives.",
	},
	{
		Type:           ReportWriterAgent,
		Name:           "Report Writer Agent",
		Description:    "Generates impact-first reports with platform-specific templates",
		Tools:          []string{"python3"},
		MaxIterations:  20,
		ConfidenceGate: 0.0,
		SystemPrompt:   "You are a report writing specialist. Generate clear, impact-first vulnerability reports. Format for HackerOne, Bugcrowd, Intigriti, or Immunefi.",
	},
	{
		Type:           Web3AuditorAgent,
		Name:           "Web3 Auditor Agent",
		Description:    "Smart contract audit across 10 bug classes with Foundry PoC generation",
		Tools:          []string{"slither", "foundry", "python3"},
		MaxIterations:  60,
		ConfidenceGate: 0.7,
		SystemPrompt:   "You are a smart contract security auditor. Analyze Solidity code for reentrancy, access control, overflow, and 7 other bug classes. Generate Foundry PoCs.",
	},
	{
		Type:           ChainBuilderAgent,
		Name:           "Chain Builder Agent",
		Description:    "Takes finding A and finds B, C that chain with it for impact amplification",
		Tools:          []string{"python3"},
		MaxIterations:  25,
		ConfidenceGate: 0.65,
		SystemPrompt:   "You are a chain-building specialist. Given a finding, identify other vulnerabilities that can chain with it to amplify impact. Map attack paths.",
	},
	{
		Type:           AutopilotAgent,
		Name:           "Autopilot Agent",
		Description:    "Full autonomous hunt loop with safety checkpoints and progress reporting",
		Tools:          []string{"subfinder", "httpx", "nuclei", "katana", "gau", "curl", "python3"},
		MaxIterations:  200,
		ConfidenceGate: 0.5,
		SystemPrompt:   "You are the autopilot coordinator. Execute the full pentesting loop: scope -> recon -> hunt -> validate -> report. Report progress at each phase boundary.",
	},
	{
		Type:           CredentialHunterAgent,
		Name:           "Credential Hunter Agent",
		Description:    "OSINT-based credential discovery with hard-stop before active spraying",
		Tools:          []string{"python3", "curl"},
		MaxIterations:  40,
		ConfidenceGate: 0.8,
		SystemPrompt:   "You are a credential hunter. Perform OSINT-based credential discovery, breach data correlation, and wordlist generation. CRITICAL: Never perform active credential spraying.",
	},
	{
		Type:           TokenAuditorAgent,
		Name:           "Token Auditor Agent",
		Description:    "Meme coin/token rug pull scanner with LP lock and honeypot detection",
		Tools:          []string{"python3", "curl", "foundry"},
		MaxIterations:  35,
		ConfidenceGate: 0.7,
		SystemPrompt:   "You are a token security auditor. Analyze tokens for rug pull indicators: LP locks, honeypot detection, bonding curve analysis, and ownership risks.",
	},
}
