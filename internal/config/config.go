package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/ares/engine/internal/logger"

	"github.com/ares/engine/internal/security"
)

var (
	envMu      sync.RWMutex
	envOverlay map[string]string
	envOnce    sync.Once
)

func getEnvOverlay() map[string]string {
	envOnce.Do(func() {
		envOverlay = make(map[string]string)
	})
	return envOverlay
}

type Config struct {
	LLM       LLMConfig       `json:"llm"`
	AttackLLM AttackLLMConfig `json:"attack_llm"`
	AgentMail AgentMailConfig `json:"agentmail"`
	Gemini    GeminiConfig    `json:"gemini"`
	Scan      ScanConfig      `json:"scan"`
	OOB       OOBConfig       `json:"oob"`
	SIEM      SIEMConfig      `json:"siem"`
	Memory    MemoryConfig    `json:"memory"`
	Output    OutputConfig    `json:"output"`
	Resources ResourcesConfig `json:"resources"`
	Python    PythonConfig    `json:"python"`
	Caido     CaidoConfig     `json:"caido"`
	Federated FederatedConfig `json:"federated"`
	Sliver    SliverConfig    `json:"sliver"`
	Pivot     PivotConfig     `json:"pivot"`
	SecretMgr SecretMgrConfig `json:"secretmgr"`
	Web       WebConfig       `json:"web"`
	Ticketing TicketingConfig `json:"ticketing"`
	Discord   DiscordConfig   `json:"discord"`
	Proxy     ProxyConfig     `json:"proxy"`
}

type WebConfig struct {
	HTTPPort  int                   `json:"http_port"`
	Host      string                `json:"host"`
	AuthToken security.SecretString `json:"auth_token"`
}

type TicketingProviderConfig struct {
	Provider  string                `json:"provider"`
	URL       string                `json:"url"`
	Token     security.SecretString `json:"token"`
	Email     string                `json:"email"`
	Project   string                `json:"project"`
	Enabled   bool                  `json:"enabled"`
	Assignees []string              `json:"assignees,omitempty"`
	Owner     string                `json:"owner,omitempty"`
	Repo      string                `json:"repo,omitempty"`
	Labels    []string              `json:"labels,omitempty"`
}

type TicketingConfig struct {
	Providers map[string]*TicketingProviderConfig `json:"providers"`
}

type AgentMailConfig struct {
	APIKey security.SecretString `json:"api_key"`
	APIURL string                `json:"api_url"`
	Domain string                `json:"domain"`
}

type GeminiConfig struct {
	APIKey security.SecretString `json:"api_key"`
}

type AttackLLMConfig struct {
	Provider string                `json:"provider"`
	BaseURL  string                `json:"base_url"`
	Model    string                `json:"model"`
	APIKey   security.SecretString `json:"api_key"`
}

type LLMConfig struct {
	Provider         string                `json:"provider"`
	BaseURL          string                `json:"base_url"`
	Model            string                `json:"model"`
	APIKey           security.SecretString `json:"api_key"`
	MaxTokens        int                   `json:"max_tokens"`
	MaxContextTokens int                   `json:"max_context_tokens"`
	Temperature      float64               `json:"temperature"`
	ReasoningEffort  string                `json:"reasoning_effort"`
	Streaming        bool                  `json:"streaming"`
	ThinkTagStrip    bool                  `json:"think_tag_strip"`
	ExtraHeaders     map[string]string     `json:"extra_headers"`
}

// SafetyMode defines the operational safety level for a scan
type SafetyMode string

const (
	SafetyModePassive    SafetyMode = "passive"    // Observe only — no requests sent to target
	SafetyModeActive     SafetyMode = "active"     // Standard testing with safe payloads
	SafetyModeAggressive SafetyMode = "aggressive" // Destructive tests, brute force, exploit confirmation
)

type ScanConfig struct {
	MaxWorkers     int        `json:"max_workers"`
	MaxIterations  int        `json:"max_iterations"`
	MinScanMinutes int        `json:"min_scan_minutes"`
	ConfidenceGate float64    `json:"confidence_gate"`
	StuckThreshold int        `json:"stuck_threshold"`
	RepeatLimit    int        `json:"repeat_limit"`
	TargetReinject int        `json:"target_reinject_interval"`
	ScanTimeoutSec int        `json:"scan_timeout_sec"`
	RateLimit      float64    `json:"rate_limit"`
	RateBurst      int        `json:"rate_burst"`
	SafetyMode     SafetyMode `json:"safety_mode"` // passive, active, or aggressive
}

type OOBConfig struct {
	Enabled   bool   `json:"enabled"`
	HTTPPort  int    `json:"http_port"`
	DNSPort   int    `json:"dns_port"`
	Domain    string `json:"domain"`
	TokenAttr string `json:"token_attr"`
}

type SIEMConfig struct {
	Enabled  bool                  `json:"enabled"`
	Type     string                `json:"type"`
	Endpoint string                `json:"endpoint"`
	APIKey   security.SecretString `json:"api_key"`
	Index    string                `json:"index"`
	FanOut   bool                  `json:"fan_out"`
}

type MemoryConfig struct {
	Enabled bool   `json:"enabled"`
	DSN     string `json:"dsn"`
}

type OutputConfig struct {
	ReportPath string `json:"report_path"`
	FirmName   string `json:"firm_name"`
	Format     string `json:"format"`
}

type DiscordConfig struct {
	WebhookURL  security.SecretString `json:"webhook_url"`
	Username    string                `json:"username"`
	MinSeverity string                `json:"min_severity"`
	Enabled     bool                  `json:"enabled"`
}

type ProxyConfig struct {
	URLs    []string `json:"urls"`
	Enabled bool     `json:"enabled"`
}

type ResourcesConfig struct {
	MaxCPUPercent float64 `json:"max_cpu_percent"`
	MaxRAMMB      uint64  `json:"max_ram_mb"`
	MaxDiskGB     uint64  `json:"max_disk_gb"`
	Monitor       bool    `json:"monitor"`
	IntervalSec   int     `json:"interval_sec"`
}

type PythonConfig struct {
	Enabled bool   `json:"enabled"`
	WorkDir string `json:"work_dir"`
	Timeout int    `json:"timeout_seconds"`
}

type CaidoConfig struct {
	Enabled bool                  `json:"enabled"`
	URL     string                `json:"url"`
	Token   security.SecretString `json:"token"`
	Port    int                   `json:"port"`
}

type FederatedConfig struct {
	Enabled      bool                  `json:"enabled"`
	HubURL       string                `json:"hub_url"`
	HubToken     security.SecretString `json:"hub_token"`
	PushInterval int                   `json:"push_interval"`
	PullOnStart  bool                  `json:"pull_on_start"`
	FNVHash      bool                  `json:"fnv_hash"`
}

type SliverConfig struct {
	Enabled      bool                  `json:"enabled"`
	Host         string                `json:"host"`
	Port         int                   `json:"port"`
	CaCert       string                `json:"ca_cert"`
	LInterval    int                   `json:"linterval"`
	MaxErrors    int                   `json:"max_errors"`
	KillDate     string                `json:"kill_date"`
	SharedSecret security.SecretString `json:"shared_secret"`
}

type PivotConfig struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

type VaultConfig struct {
	Address string                `json:"address"`
	Token   security.SecretString `json:"token"`
	Path    string                `json:"path"`
}

type AWSSecretsConfig struct {
	Region    string                `json:"region"`
	AccessKey security.SecretString `json:"access_key"`
	SecretKey security.SecretString `json:"secret_key"`
}

type SecretMgrConfig struct {
	Vault VaultConfig      `json:"vault"`
	AWS   AWSSecretsConfig `json:"aws"`
}

func Default() Config {
	return Config{
		LLM: LLMConfig{
			Provider:         "",
			BaseURL:          "",
			Model:            "",
			MaxTokens:        4096,
			MaxContextTokens: 128000,
			Temperature:      0.1,
			Streaming:        true,
			ThinkTagStrip:    true,
		},
		AttackLLM: AttackLLMConfig{
			Provider: "",
			BaseURL:  "",
			Model:    "",
		},
		AgentMail: AgentMailConfig{},
		Gemini:    GeminiConfig{},
		Scan: ScanConfig{
			MaxWorkers:     3,
			MaxIterations:  200,
			MinScanMinutes: 10,
			ConfidenceGate: 0.5,
			StuckThreshold: 20,
			RepeatLimit:    3,
			TargetReinject: 10,
			ScanTimeoutSec: 1800,
			RateLimit:      2.0,
			RateBurst:      5,
			SafetyMode:     SafetyModeActive,
		},
		OOB: OOBConfig{
			Enabled:  true,
			HTTPPort: 8181,
			DNSPort:  5353,
			Domain:   "localhost",
		},
		SIEM: SIEMConfig{
			Enabled: false,
		},
		Memory: MemoryConfig{
			Enabled: false,
		},
		Output: OutputConfig{
			ReportPath: "report.txt",
			FirmName:   "Ares Security",
			Format:     "text",
		},
		Resources: ResourcesConfig{
			MaxCPUPercent: 90.0,
			MaxRAMMB:      8192,
			MaxDiskGB:     100,
			Monitor:       false,
			IntervalSec:   10,
		},
		Python: PythonConfig{
			Enabled: false,
			WorkDir: filepath.Join(os.TempDir(), "ares_python"),
			Timeout: 60,
		},
		Caido: CaidoConfig{
			Enabled: false,
			Port:    8080,
		},
		Federated: FederatedConfig{
			Enabled:      true,
			PushInterval: 300,
			PullOnStart:  true,
			FNVHash:      true,
		},
		Sliver: SliverConfig{
			Enabled:   false,
			LInterval: 60,
			MaxErrors: 3,
		},
		Pivot: PivotConfig{
			Enabled: false,
			Port:    8888,
		},
		Web: WebConfig{
			HTTPPort:  8080,
			Host:      "localhost",
			AuthToken: security.NewSecret(""),
		},
		Ticketing: TicketingConfig{
			Providers: make(map[string]*TicketingProviderConfig),
		},
	}
}

func LoadEnv() Config {
	cfg := Default()

	getEnv := func(key string) string {
		envMu.RLock()
		overlay := getEnvOverlay()
		if val, ok := overlay[key]; ok {
			envMu.RUnlock()
			return val
		}
		envMu.RUnlock()
		return os.Getenv(key)
	}

	if v := getEnv("ARES_LLM_PROVIDER"); v != "" {
		cfg.LLM.Provider = v
	}
	if v := getEnv("ARES_LLM_BASE_URL"); v != "" {
		if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			logger.Warn("[Config] Warning: ARES_LLM_BASE_URL should start with http:// or https://")
		}
		cfg.LLM.BaseURL = v
	}
	if v := getEnv("ARES_LLM_MODEL"); v != "" {
		cfg.LLM.Model = v
	}
	if v := getEnv("ARES_LLM_API_KEY"); v != "" {
		cfg.LLM.APIKey = security.NewSecret(v)
	}
	if v := getEnv("ARES_LLM_MAX_TOKENS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.LLM.MaxTokens = i
		}
	}
	if v := getEnv("ARES_LLM_MAX_CONTEXT_TOKENS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.LLM.MaxContextTokens = i
		}
	}
	if v := getEnv("ARES_LLM_TEMPERATURE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.LLM.Temperature = f
		}
	}

	if v := getEnv("ARES_ATTACK_LLM_PROVIDER"); v != "" {
		cfg.AttackLLM.Provider = v
	}
	if v := getEnv("ARES_ATTACK_LLM_BASE_URL"); v != "" {
		cfg.AttackLLM.BaseURL = v
	}
	if v := getEnv("ARES_ATTACK_LLM_MODEL"); v != "" {
		cfg.AttackLLM.Model = v
	}
	if v := getEnv("ARES_ATTACK_LLM_API_KEY"); v != "" {
		cfg.AttackLLM.APIKey = security.NewSecret(v)
	}

	if v := getEnv("ARES_AGENTMAIL_API_KEY"); v != "" {
		cfg.AgentMail.APIKey = security.NewSecret(v)
	}
	if v := getEnv("ARES_AGENTMAIL_API_URL"); v != "" {
		cfg.AgentMail.APIURL = v
	}
	if v := getEnv("ARES_AGENTMAIL_DOMAIN"); v != "" {
		cfg.AgentMail.Domain = v
	}

	if v := getEnv("ARES_GEMINI_API_KEY"); v != "" {
		cfg.Gemini.APIKey = security.NewSecret(v)
	}

	if v := getEnv("ARES_MEMORY_DSN"); v != "" {
		if !strings.HasPrefix(v, "postgres://") && !strings.HasPrefix(v, "postgresql://") && !strings.HasPrefix(v, "file://") {
			logger.Warn("[Config] Warning: ARES_MEMORY_DSN should use postgres:// or file:// scheme")
		} else if _, err := url.Parse(v); err != nil {
			logger.Error(fmt.Sprintf("[Config] Warning: ARES_MEMORY_DSN failed URL parse: %v", err))
		}
		cfg.Memory.DSN = v
		cfg.Memory.Enabled = true
	}
	if v := getEnv("ARES_MEMORY_ENABLED"); v != "" {
		cfg.Memory.Enabled = strings.ToLower(v) == "true"
	}

	if v := getEnv("ARES_OOB_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.OOB.HTTPPort = i
		}
	}
	if v := getEnv("ARES_OOB_ENABLED"); v != "" {
		cfg.OOB.Enabled = strings.ToLower(v) == "true"
	}

	if v := getEnv("ARES_SCAN_MAX_ITERATIONS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.MaxIterations = i
		}
	}
	if v := getEnv("ARES_SCAN_MAX_WORKERS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.MaxWorkers = i
		}
	}
	if v := getEnv("ARES_SCAN_STUCK_THRESHOLD"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.StuckThreshold = i
		}
	}
	if v := getEnv("ARES_SCAN_TARGET_REINJECT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.TargetReinject = i
		}
	}
	if v := getEnv("ARES_SCAN_RATE_LIMIT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.Scan.RateLimit = f
		}
	}
	if v := getEnv("ARES_SCAN_RATE_BURST"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			cfg.Scan.RateBurst = i
		}
	}

	if v := getEnv("ARES_TARGET"); v != "" {
		cfg.Scan.MaxWorkers = 1
	}
	if v := getEnv("ARES_WORKERS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.MaxWorkers = i
		}
	}

	if v := getEnv("ARES_OUTPUT"); v != "" {
		cfg.Output.ReportPath = v
	}
	if v := getEnv("ARES_FORMAT"); v != "" {
		cfg.Output.Format = v
	}

	if v := getEnv("ARES_DASH_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Web.HTTPPort = i
		}
	}

	if v := getEnv("ARES_WEB_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Web.HTTPPort = i
		}
	}

	if v := getEnv("ARES_PIVOT_ENABLED"); v != "" {
		cfg.Pivot.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_PIVOT_HOST"); v != "" {
		cfg.Pivot.Host = v
	}
	if v := getEnv("ARES_PIVOT_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Pivot.Port = i
		}
	}

	if v := getEnv("ARES_SLIVER_ENABLED"); v != "" {
		cfg.Sliver.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_SLIVER_HOST"); v != "" {
		cfg.Sliver.Host = v
	}
	if v := getEnv("ARES_SLIVER_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Sliver.Port = i
		}
	}
	if v := getEnv("ARES_SLIVER_SHARED_SECRET"); v != "" {
		cfg.Sliver.SharedSecret = security.NewSecret(v)
	}

	if v := getEnv("ARES_FEDERATED_ENABLED"); v != "" {
		cfg.Federated.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_FEDERATED_HUB_URL"); v != "" {
		cfg.Federated.HubURL = v
	}

	if v := getEnv("ARES_VAULT_ADDR"); v != "" {
		cfg.SecretMgr.Vault.Address = v
	}
	if v := getEnv("ARES_VAULT_TOKEN"); v != "" {
		cfg.SecretMgr.Vault.Token = security.NewSecret(v)
	}
	if v := getEnv("ARES_VAULT_PATH"); v != "" {
		cfg.SecretMgr.Vault.Path = v
	}
	if v := getEnv("ARES_AWS_REGION"); v != "" {
		cfg.SecretMgr.AWS.Region = v
	}
	if v := getEnv("ARES_AWS_ACCESS_KEY_ID"); v != "" {
		cfg.SecretMgr.AWS.AccessKey = security.NewSecret(v)
	}
	if v := getEnv("ARES_AWS_SECRET_ACCESS_KEY"); v != "" {
		cfg.SecretMgr.AWS.SecretKey = security.NewSecret(v)
	}

	// LLM additional options
	if v := getEnv("ARES_LLM_REASONING_EFFORT"); v != "" {
		cfg.LLM.ReasoningEffort = v
	}
	if v := getEnv("ARES_LLM_STREAMING"); v != "" {
		cfg.LLM.Streaming = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_LLM_THINK_TAG_STRIP"); v != "" {
		cfg.LLM.ThinkTagStrip = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_LLM_MAX_CONTEXT_TOKENS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.LLM.MaxContextTokens = i
		}
	}

	// Scan config
	if v := getEnv("ARES_SCAN_SAFETY_MODE"); v != "" {
		mode := SafetyMode(strings.ToLower(v))
		switch mode {
		case SafetyModePassive, SafetyModeActive, SafetyModeAggressive:
			cfg.Scan.SafetyMode = mode
		default:
			logger.Warn("[Config] Invalid ARES_SCAN_SAFETY_MODE, defaulting to active")
			cfg.Scan.SafetyMode = SafetyModeActive
		}
	}
	if v := getEnv("ARES_SCAN_TIMEOUT_SEC"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.ScanTimeoutSec = i
		}
	}
	if v := getEnv("ARES_SCAN_MIN_SCAN_MINUTES"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.MinScanMinutes = i
		}
	}
	if v := getEnv("ARES_SCAN_CONFIDENCE_GATE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Scan.ConfidenceGate = f
		}
	}
	if v := getEnv("ARES_SCAN_REPEAT_LIMIT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Scan.RepeatLimit = i
		}
	}

	// OOB config
	if v := getEnv("ARES_OOB_DNS_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.OOB.DNSPort = i
		}
	}
	if v := getEnv("ARES_OOB_DOMAIN"); v != "" {
		cfg.OOB.Domain = v
	}
	if v := getEnv("ARES_OOB_TOKEN_ATTR"); v != "" {
		cfg.OOB.TokenAttr = v
	}

	// SIEM config
	if v := getEnv("ARES_SIEM_ENABLED"); v != "" {
		cfg.SIEM.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_SIEM_TYPE"); v != "" {
		cfg.SIEM.Type = v
	}
	if v := getEnv("ARES_SIEM_ENDPOINT"); v != "" {
		cfg.SIEM.Endpoint = v
	}
	if v := getEnv("ARES_SIEM_API_KEY"); v != "" {
		cfg.SIEM.APIKey = security.NewSecret(v)
	}

	// Resources config
	if v := getEnv("ARES_RESOURCES_MAX_CPU_PERCENT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Resources.MaxCPUPercent = f
		}
	}
	if v := getEnv("ARES_RESOURCES_MAX_RAM_MB"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Resources.MaxRAMMB = uint64(i)
		}
	}
	if v := getEnv("ARES_RESOURCES_MONITOR"); v != "" {
		cfg.Resources.Monitor = strings.ToLower(v) == "true"
	}

	// Python config
	if v := getEnv("ARES_PYTHON_ENABLED"); v != "" {
		cfg.Python.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_PYTHON_TIMEOUT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Python.Timeout = i
		}
	}

	// Caido config
	if v := getEnv("ARES_CAIDO_ENABLED"); v != "" {
		cfg.Caido.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_CAIDO_URL"); v != "" {
		cfg.Caido.URL = v
	}
	if v := getEnv("ARES_CAIDO_TOKEN"); v != "" {
		cfg.Caido.Token = security.NewSecret(v)
	}

	// Federated config
	if v := getEnv("ARES_FEDERATED_HUB_TOKEN"); v != "" {
		cfg.Federated.HubToken = security.NewSecret(v)
	}
	if v := getEnv("ARES_FEDERATED_PUSH_INTERVAL"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Federated.PushInterval = i
		}
	}
	if v := getEnv("ARES_FEDERATED_PULL_ON_START"); v != "" {
		cfg.Federated.PullOnStart = strings.ToLower(v) == "true"
	}

	// Discord config
	if v := getEnv("ARES_DISCORD_ENABLED"); v != "" {
		cfg.Discord.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_DISCORD_WEBHOOK_URL"); v != "" {
		cfg.Discord.WebhookURL = security.NewSecret(v)
	}
	if v := getEnv("ARES_DISCORD_USERNAME"); v != "" {
		cfg.Discord.Username = v
	}
	if v := getEnv("ARES_DISCORD_MIN_SEVERITY"); v != "" {
		cfg.Discord.MinSeverity = v
	}

	// Proxy config
	if v := getEnv("ARES_PROXY_ENABLED"); v != "" {
		cfg.Proxy.Enabled = strings.ToLower(v) == "true"
	}
	if v := getEnv("ARES_PROXY_URLS"); v != "" {
		cfg.Proxy.URLs = strings.Split(v, ",")
	}

	// Web auth token
	if v := getEnv("ARES_WEB_AUTH_TOKEN"); v != "" {
		cfg.Web.AuthToken = security.NewSecret(v)
	}

	if err := cfg.Validate(); err != nil {
		logger.Warn(fmt.Sprintf("[Config] validation: %v", err))
	}

	return cfg
}

func LoadDotEnv(path string) (Config, error) {
	cfg := LoadEnv()

	// Resolve symlinks to prevent TOCTOU symlink swaps
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return cfg, fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Limit file size to prevent resource exhaustion
	info, err := os.Stat(resolved)
	if err != nil {
		return cfg, fmt.Errorf("failed to stat .ares.env file: %w", err)
	}
	if info.Size() > 1<<20 { // 1MB max
		return cfg, fmt.Errorf(".ares.env file too large: %d bytes", info.Size())
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return cfg, fmt.Errorf("failed to read .ares.env file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, "\"'")

		envKey := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
		if !strings.HasPrefix(envKey, "ARES_") {
			envKey = "ARES_" + envKey
		}
		envMu.Lock()
		overlay := getEnvOverlay()
		overlay[envKey] = value
		envMu.Unlock()
	}

	return LoadEnv(), nil
}

func (c *Config) Validate() error {
	if c.LLM.Provider == "" {
		return fmt.Errorf("LLM provider is required")
	}
	if c.LLM.BaseURL == "" {
		return fmt.Errorf("LLM base URL is required")
	}
	if c.LLM.Model == "" {
		return fmt.Errorf("LLM model is required")
	}

	requiredWithKey := map[string][]string{
		"openai":    {"APIKey"},
		"anthropic": {"APIKey"},
		"gemini":    {"APIKey"},
		"deepseek":  {"APIKey"},
		"azure":     {"APIKey"},
	}

	if requiredFields, ok := requiredWithKey[c.LLM.Provider]; ok {
		for _, field := range requiredFields {
			switch field {
			case "APIKey":
				if !c.LLM.APIKey.IsSet() {
					return fmt.Errorf("API key required for provider %s", c.LLM.Provider)
				}
			}
		}
	}

	if c.Scan.MaxIterations <= 0 {
		return fmt.Errorf("max iterations must be positive")
	}
	if c.Scan.MaxWorkers <= 0 {
		return fmt.Errorf("max workers must be positive")
	}
	if c.Scan.ConfidenceGate < 0 || c.Scan.ConfidenceGate > 1 {
		return fmt.Errorf("confidence gate must be between 0 and 1")
	}

	if c.Pivot.Enabled && (c.Pivot.Host == "" || c.Pivot.Port == 0) {
		return fmt.Errorf("pivot host and port are required when pivot is enabled")
	}

	if c.Sliver.Enabled && (c.Sliver.Host == "" || c.Sliver.Port == 0) {
		return fmt.Errorf("sliver host and port are required when sliver is enabled")
	}

	if c.OOB.Enabled && c.OOB.Domain != "" {
		if strings.Contains(c.OOB.Domain, "..") || strings.ContainsAny(c.OOB.Domain, "<>\"'\\;") {
			return fmt.Errorf("OOB domain contains invalid characters")
		}
		if _, err := url.Parse("http://" + c.OOB.Domain); err != nil {
			return fmt.Errorf("OOB domain is not a valid hostname: %w", err)
		}
	}

	return nil
}

// Zeroize clears all sensitive data from the config to prevent memory leakage.
func (c *Config) Zeroize() {
	c.LLM.APIKey.Zero()
	c.AttackLLM.APIKey.Zero()
	c.AgentMail.APIKey.Zero()
	c.Gemini.APIKey.Zero()
	c.SIEM.APIKey.Zero()
	c.Caido.Token.Zero()
	c.Federated.HubToken.Zero()
	c.Sliver.CaCert = ""
	c.Sliver.SharedSecret.Zero()
	c.SecretMgr.Vault.Token.Zero()
	c.SecretMgr.AWS.AccessKey.Zero()
	c.SecretMgr.AWS.SecretKey.Zero()
	c.Web.AuthToken.Zero()
	envMu.Lock()
	for k := range envOverlay {
		delete(envOverlay, k)
	}
	envOverlay = make(map[string]string)
	envMu.Unlock()
	envOnce = sync.Once{}
	runtime.GC()
	runtime.KeepAlive(c)
}
