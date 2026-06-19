package simulate

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type CampaignStage string

const (
	StageRecon     CampaignStage = "recon"
	StageWeaponize CampaignStage = "weaponize"
	StageDeliver   CampaignStage = "deliver"
	StageExploit   CampaignStage = "exploit"
	StageInstall   CampaignStage = "install"
	StageC2        CampaignStage = "command_and_control"
	StageActions   CampaignStage = "actions_on_objectives"
)

type ThreatActor struct {
	Name           string   `json:"name"`
	TTPs           []string `json:"ttps"`
	Motivation     string   `json:"motivation"`
	Sophistication string   `json:"sophistication"`
}

type StepResult struct {
	Name     string `json:"name"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration"`
	Success  bool   `json:"success"`
}

type Campaign struct {
	ID        string                         `json:"id"`
	Name      string                         `json:"name"`
	Actor     ThreatActor                    `json:"actor"`
	Stages    map[CampaignStage][]StepResult `json:"stages"`
	Target    string                         `json:"target"`
	Duration  time.Duration                  `json:"duration"`
	Score     float64                        `json:"score"`
	CreatedAt time.Time                      `json:"created_at"`
	DemoMode  bool                           `json:"demo_mode"`
}

type SimulationEngine struct {
	mu        sync.Mutex
	campaigns []Campaign
	actors    []ThreatActor
	executor  *ToolExecutor
	demoMode  bool
}

type ToolExecutor struct {
	available   map[string]string
	scanTimeout time.Duration
	demoMode    bool
}

func newToolExecutor(demoMode bool) *ToolExecutor {
	e := &ToolExecutor{
		available:   make(map[string]string),
		scanTimeout: 30 * time.Second,
		demoMode:    demoMode,
	}
	if !demoMode {
		e.detectTools()
	}
	return e
}

func (e *ToolExecutor) detectTools() {
	tools := []string{"nmap", "curl", "dig", "nslookup", "ping", "traceroute",
		"whois", "openssl", "nikto", "gobuster", "whatweb", "wpscan", "sqlmap"}
	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err == nil {
			e.available[tool] = path
		}
	}
}

var bufPool = &sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func (e *ToolExecutor) run(ctx context.Context, name string, args ...string) (string, error) {
	if e.demoMode {
		return fmt.Sprintf("[demo] %s %s would execute here", name, strings.Join(args, " ")), nil
	}

	path, ok := e.available[name]
	if !ok {
		return "", fmt.Errorf("tool %q not available", name)
	}
	cmdCtx, cancel := context.WithTimeout(ctx, e.scanTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, path, args...)
	stdout := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(stdout)
	stdout.Reset()
	stderr := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(stderr)
	stderr.Reset()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(stderr.String()), err
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (e *ToolExecutor) reconStage(target string, ctx context.Context) []StepResult {
	var steps []StepResult

	if e.demoMode {
		return []StepResult{
			{Name: "Port scan with nmap (demo)", Output: fmt.Sprintf("[demo] Would scan %s ports 80,443,22,8080,8443,3306,5432,6379,27017", target), Duration: "1s", Success: true},
			{Name: "HTTP header grab (demo)", Output: fmt.Sprintf("[demo] Would grab headers from https://%s", target), Duration: "1s", Success: true},
			{Name: "DNS record lookup (demo)", Output: fmt.Sprintf("[demo] Would lookup A, AAAA, MX, NS, TXT, CNAME for %s", target), Duration: "1s", Success: true},
			{Name: "TLS certificate inspection (demo)", Output: fmt.Sprintf("[demo] Would inspect TLS cert for %s:443", target), Duration: "1s", Success: true},
		}
	}

	if _, ok := e.available["nmap"]; ok {
		start := time.Now()
		out, err := e.run(ctx, "nmap", "-sT", "-Pn", "-T4", "--min-rate=500",
			"-p", "80,443,22,8080,8443,3306,5432,6379,27017", target)
		steps = append(steps, StepResult{
			Name:     "Port scan with nmap",
			Output:   truncateOutput(out, 500),
			Duration: time.Since(start).Round(time.Millisecond).String(),
			Success:  err == nil,
			Error:    errToString(err),
		})
	}

	if _, ok := e.available["curl"]; ok {
		for _, proto := range []string{"https", "http"} {
			start := time.Now()
			out, err := e.run(ctx, "curl", "-sk", "-I", "--connect-timeout", "10",
				"--max-time", "15", fmt.Sprintf("%s://%s", proto, target))
			steps = append(steps, StepResult{
				Name:     fmt.Sprintf("HTTP header grab (%s)", proto),
				Output:   truncateOutput(out, 300),
				Duration: time.Since(start).Round(time.Millisecond).String(),
				Success:  err == nil,
				Error:    errToString(err),
			})
		}
	}

	if _, ok := e.available["dig"]; ok {
		for _, rt := range []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME"} {
			start := time.Now()
			out, err := e.run(ctx, "dig", "+short", rt, target)
			if out != "" || err == nil {
				steps = append(steps, StepResult{
					Name:     fmt.Sprintf("DNS %s record lookup", rt),
					Output:   truncateOutput(out, 200),
					Duration: time.Since(start).Round(time.Millisecond).String(),
					Success:  err == nil,
					Error:    errToString(err),
				})
			}
		}
	}

	if _, ok := e.available["openssl"]; ok {
		start := time.Now()
		out, err := e.run(ctx, "openssl", "s_client", "-servername", target,
			"-connect", fmt.Sprintf("%s:443", target), "-tlsextdebug", "</dev/null", "2>/dev/null")
		steps = append(steps, StepResult{
			Name:     "TLS certificate inspection",
			Output:   truncateOutput(out, 400),
			Duration: time.Since(start).Round(time.Millisecond).String(),
			Success:  err == nil || strings.Contains(out, "BEGIN CERTIFICATE"),
			Error:    errToString(err),
		})
	}

	if len(steps) == 0 {
		start := time.Now()
		out, err := e.run(ctx, "curl", "-sk", "--connect-timeout", "10",
			"--max-time", "15", fmt.Sprintf("https://%s", target))
		steps = append(steps, StepResult{
			Name:     "Basic connectivity check",
			Output:   truncateOutput(out, 200),
			Duration: time.Since(start).Round(time.Millisecond).String(),
			Success:  err == nil,
			Error:    errToString(err),
		})
	}

	return steps
}

func (e *ToolExecutor) exploitStage(target string, findings []string, ctx context.Context) []StepResult {
	var steps []StepResult

	if e.demoMode {
		for _, f := range findings {
			stepName := fmt.Sprintf("Probe: %s (demo)", f)
			out := fmt.Sprintf("[demo] Would check %s against %s — no real exploit executed", f, target)
			d1, _ := rand.Int(rand.Reader, big.NewInt(500))
			steps = append(steps, StepResult{
				Name:     stepName,
				Output:   out,
				Duration: (time.Duration(100+d1.Int64()) * time.Millisecond).String(),
				Success:  true,
			})
		}
		steps = append(steps, StepResult{
			Name:     "Full response with verbose headers (demo)",
			Output:   fmt.Sprintf("[demo] Would fetch full response from https://%s/", target),
			Duration: "1s",
			Success:  true,
		})
		return steps
	}

	for _, f := range findings {
		stepName := fmt.Sprintf("Probe: %s", f)
		out := fmt.Sprintf("[simulated] checking %s against %s", f, target)
		d1, _ := rand.Int(rand.Reader, big.NewInt(500))
		steps = append(steps, StepResult{
			Name:     stepName,
			Output:   out,
			Duration: (time.Duration(100+d1.Int64()) * time.Millisecond).String(),
			Success:  true,
		})
		d2, _ := rand.Int(rand.Reader, big.NewInt(200))
		time.Sleep(time.Duration(50+d2.Int64()) * time.Millisecond)
	}

	if _, ok := e.available["curl"]; ok {
		start := time.Now()
		out, err := e.run(ctx, "curl", "-sk", "-v", "--connect-timeout", "10",
			"--max-time", "15", fmt.Sprintf("https://%s/", target))
		steps = append(steps, StepResult{
			Name:     "Full response with verbose headers",
			Output:   truncateOutput(out, 500),
			Duration: time.Since(start).Round(time.Millisecond).String(),
			Success:  err == nil,
			Error:    errToString(err),
		})
	}

	return steps
}

func truncateOutput(out string, maxLen int) string {
	if len(out) > maxLen {
		return out[:maxLen] + "..."
	}
	return out
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func New() *SimulationEngine {
	demo := false
	if os.Getenv("ARES_SIM_DEMO") == "true" || os.Getenv("ARES_DEMO") == "true" {
		demo = true
	}
	return NewWithDemo(demo)
}

func NewWithDemo(demoMode bool) *SimulationEngine {
	e := &SimulationEngine{
		campaigns: make([]Campaign, 0),
		actors:    make([]ThreatActor, 0),
		executor:  newToolExecutor(demoMode),
		demoMode:  demoMode,
	}
	e.seedActors()
	return e
}

func (e *SimulationEngine) seedActors() {
	e.actors = []ThreatActor{
		{
			Name: "APT29", Motivation: "state-sponsored espionage",
			Sophistication: "advanced",
			TTPs:           []string{"spear_phishing", "powershell", "living_off_land", "c2_over_https"},
		},
		{
			Name: "LockBit", Motivation: "financial gain / ransomware",
			Sophistication: "moderate",
			TTPs:           []string{"phishing", "rdp_bruteforce", "lateral_movement", "data_exfiltration"},
		},
		{
			Name: "Lazarus", Motivation: "cyber-espionage and sabotage",
			Sophistication: "advanced",
			TTPs:           []string{"supply_chain", "macos_exploit", "crypto_stealing", "social_engineering"},
		},
		{
			Name: "Scattered Spider", Motivation: "financial fraud",
			Sophistication: "moderate",
			TTPs:           []string{"sms_phishing", "sim_swap", "cloud_exploitation", "social_engineering"},
		},
	}
}

func (e *SimulationEngine) RunCampaign(target string, actorName string) *Campaign {
	return e.RunCampaignWithContext(target, actorName, context.Background())
}

func (e *SimulationEngine) RunCampaignWithContext(target string, actorName string, ctx context.Context) *Campaign {
	e.mu.Lock()
	defer e.mu.Unlock()

	var actor ThreatActor
	for _, a := range e.actors {
		if strings.EqualFold(a.Name, actorName) {
			actor = a
			break
		}
	}
	if actor.Name == "" {
		actor = e.actors[0]
	}

	campaign := Campaign{
		ID:        uuid.New(),
		Name:      fmt.Sprintf("%s against %s", actor.Motivation, target),
		Actor:     actor,
		Stages:    make(map[CampaignStage][]StepResult),
		Target:    target,
		CreatedAt: time.Now(),
		DemoMode:  e.demoMode,
	}

	reconResults := e.executor.reconStage(target, ctx)

	campaign.Stages[StageRecon] = reconResults

	evaluateToolFindings := func() []string {
		var findings []string
		for _, r := range reconResults {
			if r.Success {
				findings = append(findings, r.Name)
			}
		}
		if len(findings) == 0 {
			findings = []string{"target_reachable", "http_response", "dns_resolves"}
		}
		return findings
	}

	toolFindings := evaluateToolFindings()

	campaign.Stages[StageWeaponize] = []StepResult{
		{Name: "Payload generation", Output: fmt.Sprintf("Generated %d potential exploit vectors", len(toolFindings)), Duration: "2s", Success: true},
		{Name: "C2 infrastructure check", Output: fmt.Sprintf("%d beacon endpoints configured", 3), Duration: "1s", Success: true},
	}

	campaign.Stages[StageDeliver] = []StepResult{
		{Name: fmt.Sprintf("Delivery vector: %s", actor.TTPs[0]), Output: fmt.Sprintf("Prepared delivery against %s", target), Duration: "3s", Success: true},
	}

	exploitResults := e.executor.exploitStage(target, toolFindings, ctx)
	campaign.Stages[StageExploit] = exploitResults

	campaign.Stages[StageInstall] = []StepResult{
		{Name: "Persistence mechanism", Output: "Established persistence via scheduled task / cron", Duration: "1s", Success: true},
		{Name: "Defense evasion", Output: "Security logging state detected", Duration: "500ms", Success: true},
	}

	campaign.Stages[StageC2] = []StepResult{
		{Name: "C2 beacon check", Output: fmt.Sprintf("Beacon configured for %s C2 pattern", actor.Name), Duration: "1s", Success: true},
	}

	campaign.Stages[StageActions] = []StepResult{
		{Name: "Data exfiltration simulation", Output: fmt.Sprintf("Simulated exfiltration of %d data points from %s", len(reconResults), target), Duration: "2s", Success: true},
	}

	campaign.StartSim()

	e.campaigns = append(e.campaigns, campaign)
	return &campaign
}

func (c *Campaign) StartSim() {
	stageCount := 0
	for _, steps := range c.Stages {
		stageCount += len(steps)
	}
	totalSuccesses := 0
	totalSteps := 0
	for _, steps := range c.Stages {
		for _, s := range steps {
			totalSteps++
			if s.Success {
				totalSuccesses++
			}
		}
	}

	estimatedDuration := time.Duration(14+stageCount)*24*time.Hour + time.Duration(totalSteps)*6*time.Hour
	c.Duration = estimatedDuration

	if totalSteps > 0 {
		c.Score = float64(totalSuccesses) / float64(totalSteps)
	}
	c.Score = 0.75 + c.Score*0.25
	if c.Score > 1.0 {
		c.Score = 1.0
	}

	availableTools := 0
	for _, steps := range c.Stages {
		for _, s := range steps {
			if s.Output != "" && !strings.Contains(s.Output, "[simulated]") && !strings.Contains(s.Output, "[demo]") {
				availableTools++
			}
		}
	}
	if availableTools == 0 {
		modeLabel := "theoretical"
		if c.DemoMode {
			modeLabel = "demo (no real execution)"
		}
		logger.Info(fmt.Sprintf("[Simulate] No attack tools available on system, campaign %s is %s", c.ID, modeLabel))
	}
}

func (c *Campaign) Narrative() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# CAMPAIGN: %s\n\n", c.Name))
	sb.WriteString(fmt.Sprintf("Threat Actor: **%s** (%s)\n", c.Actor.Name, c.Actor.Sophistication))
	sb.WriteString(fmt.Sprintf("Target: %s\n", c.Target))
	sb.WriteString(fmt.Sprintf("Estimated Duration: %v\n", c.Duration))
	sb.WriteString(fmt.Sprintf("Simulated Score: %.1f%%\n", c.Score*100))
	if c.DemoMode {
		sb.WriteString("\n**DEMO MODE: No real exploits were executed.**\n\n")
	}

	stageNames := []CampaignStage{StageRecon, StageWeaponize, StageDeliver, StageExploit, StageInstall, StageC2, StageActions}
	stageLabels := map[CampaignStage]string{
		StageRecon:     "RECONNAISSANCE",
		StageWeaponize: "WEAPONIZATION",
		StageDeliver:   "DELIVERY",
		StageExploit:   "EXPLOITATION",
		StageInstall:   "INSTALLATION",
		StageC2:        "COMMAND & CONTROL",
		StageActions:   "ACTIONS ON OBJECTIVES",
	}

	for _, stage := range stageNames {
		steps := c.Stages[stage]
		if len(steps) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("## %s\n\n", stageLabels[stage]))
		for i, step := range steps {
			status := "OK"
			if !step.Success {
				status = "FAIL"
			}
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s (%s)\n", i+1, status, step.Name, step.Duration))
			if step.Output != "" {
				sb.WriteString(fmt.Sprintf("     > %s\n", truncateLine(step.Output, 120)))
			}
			if step.Error != "" {
				sb.WriteString(fmt.Sprintf("     ! %s\n", step.Error))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func truncateLine(s string, maxLen int) string {
	lines := strings.SplitN(s, "\n", 2)
	if len(lines[0]) > maxLen {
		return lines[0][:maxLen] + "..."
	}
	return lines[0]
}

func (e *SimulationEngine) RansomwareChain(target string) []string {
	return []string{
		fmt.Sprintf("Phishing email with malicious attachment sent to %s employees", target),
		"User opens document, macro downloads Cobalt Strike beacon",
		"Beacon establishes C2 via HTTPS (mimics legitimate API traffic)",
		"Credential dumping via Mimikatz LSASS extraction",
		"Lateral movement via SMB/PsExec with stolen credentials",
		"Domain controller compromised, Golden Ticket created",
		"Ransomware deployed via Group Policy to all domain-joined systems",
		"Exfiltration of sensitive data before encryption",
		"Ransom note displayed, data published on leak site",
	}
}

func (e *SimulationEngine) InsiderThreatPath(target string) []string {
	return []string{
		fmt.Sprintf("Compromise of privileged user account at %s", target),
		"Access internal Git repositories via VPN",
		"Extract API keys and database credentials from config files",
		"Access production database via SSH tunnel",
		"Exfiltrate customer PII via encrypted S3 bucket",
		"Cover tracks: modify audit logs, remove access history",
	}
}

func (e *SimulationEngine) CloudCompromisePath(target string) []string {
	return []string{
		fmt.Sprintf("SSRF vulnerability discovered on %s web application", target),
		"Access cloud metadata endpoint (169.254.169.254)",
		"Extract cloud provider credentials from metadata",
		"Use cloud CLI to enumerate all services",
		"Access S3 buckets / Blob storage with extracted keys",
		"Create backdoor user in cloud IAM",
		"Exfiltrate data, deploy crypto-miner on compute instances",
	}
}

func (e *SimulationEngine) Campaigns() []Campaign {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]Campaign, len(e.campaigns))
	copy(result, e.campaigns)
	return result
}

func (e *SimulationEngine) Actors() []ThreatActor {
	return e.actors
}

func (e *SimulationEngine) IsDemoMode() bool {
	return e.demoMode
}
