package chainer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/chaindsl"
	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/report"
)

func generateSecureID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		logger.Error(fmt.Sprintf("[Chainer] CRITICAL: crypto/rand failed: %v", err))
		return ""
	}
	return hex.EncodeToString(b)
}

type ChainStep struct {
	Type          string   `json:"type"`
	Target        string   `json:"target"`
	Technique     string   `json:"technique"`
	Confidence    float64  `json:"confidence"`
	Impact        string   `json:"impact"`
	NextSteps     []string `json:"next_steps"`
	ConfidenceMin float64  `json:"confidence_min,omitempty"`
	ConfidenceMax float64  `json:"confidence_max,omitempty"`
	Complexity    string   `json:"complexity,omitempty"`
}

type ExploitChain struct {
	ID        string      `json:"id"`
	Steps     []ChainStep `json:"steps"`
	Score     float64     `json:"score"`
	Impact    string      `json:"impact"`
	Summary   string      `json:"summary"`
	CreatedAt time.Time   `json:"created_at"`
	TTE       string      `json:"tte,omitempty"`
}

type Chainer struct {
	mu     sync.RWMutex
	graph  *graph.AttackGraph
	chains []ExploitChain
}

func New(g *graph.AttackGraph) *Chainer {
	return &Chainer{
		graph:  g,
		chains: make([]ExploitChain, 0),
	}
}

type ChainRule struct {
	Name       string   `json:"name"`
	Prereqs    []string `json:"prereqs"`
	Result     string   `json:"result"`
	Impact     string   `json:"impact"`
	Confidence float64  `json:"confidence"`
}

var chainRules = []ChainRule{
	{
		Name:       "ssrf_to_metadata",
		Prereqs:    []string{"ssrf"},
		Result:     "cloud_credentials",
		Impact:     "critical",
		Confidence: 0.85,
	},
	{
		Name:       "sqli_to_creds",
		Prereqs:    []string{"sqli"},
		Result:     "database_credentials",
		Impact:     "critical",
		Confidence: 0.9,
	},
	{
		Name:       "xss_to_session",
		Prereqs:    []string{"xss"},
		Result:     "session_hijack",
		Impact:     "high",
		Confidence: 0.75,
	},
	{
		Name:       "open_redirect_to_ssrf",
		Prereqs:    []string{"open_redirect"},
		Result:     "ssrf",
		Impact:     "high",
		Confidence: 0.7,
	},
	{
		Name:       "weak_jwt_to_admin",
		Prereqs:    []string{"weak_jwt", "exposed_admin"},
		Result:     "admin_access",
		Impact:     "critical",
		Confidence: 0.9,
	},
	{
		Name:       "idor_to_pii",
		Prereqs:    []string{"idor"},
		Result:     "pii_disclosure",
		Impact:     "high",
		Confidence: 0.8,
	},
	{
		Name:       "credentials_to_pivot",
		Prereqs:    []string{"credentials", "internal_reach"},
		Result:     "lateral_movement",
		Impact:     "critical",
		Confidence: 0.85,
	},
	{
		Name:       "lfi_to_rce",
		Prereqs:    []string{"lfi", "file_write"},
		Result:     "rce",
		Impact:     "critical",
		Confidence: 0.7,
	},
	{
		Name:       "api_leak_to_pivot",
		Prereqs:    []string{"api_key_leak"},
		Result:     "service_compromise",
		Impact:     "high",
		Confidence: 0.8,
	},
	{
		Name:       "ssrf_to_rce_internal",
		Prereqs:    []string{"ssrf", "internal_service"},
		Result:     "internal_rce",
		Impact:     "critical",
		Confidence: 0.8,
	},
}

func (c *Chainer) Analyze(findings []string) []ExploitChain {
	c.mu.Lock()
	defer c.mu.Unlock()

	findingSet := make(map[string]bool)
	for _, f := range findings {
		findingSet[strings.ToLower(f)] = true
	}

	var newChains []ExploitChain

	for _, rule := range chainRules {
		allMet := true
		for _, prereq := range rule.Prereqs {
			if !findingSet[prereq] {
				allMet = false
				break
			}
		}
		if !allMet {
			continue
		}

		chainID := fmt.Sprintf("chain-%s-%s", rule.Name, generateSecureID())

		steps := make([]ChainStep, 0)
		for _, prereq := range rule.Prereqs {
			steps = append(steps, ChainStep{
				Type:       prereq,
				Technique:  prereq,
				Confidence: 0.9,
				NextSteps:  []string{rule.Result},
			})
		}
		steps = append(steps, ChainStep{
			Type:       rule.Result,
			Technique:  rule.Result,
			Confidence: rule.Confidence,
			Impact:     rule.Impact,
		})

		chain := ExploitChain{
			ID:        chainID,
			Steps:     steps,
			Score:     c.scoreChain(steps),
			Impact:    rule.Impact,
			Summary:   c.buildSummary(steps),
			CreatedAt: time.Now(),
		}
		newChains = append(newChains, chain)
	}

	for _, chain := range newChains {
		c.graph.AddNode(chain.ID, graph.NodeTechnique, chain.Summary)
		c.graph.SetNodeProperty(chain.ID, "score", chain.Score)
		c.graph.SetNodeProperty(chain.ID, "impact", chain.Impact)

		for i := 1; i < len(chain.Steps); i++ {
			prev := fmt.Sprintf("%s-%s", chain.ID, chain.Steps[i-1].Type)
			curr := fmt.Sprintf("%s-%s", chain.ID, chain.Steps[i].Type)
			c.graph.AddNode(prev, graph.NodeTechnique, chain.Steps[i-1].Type)
			c.graph.AddNode(curr, graph.NodeTechnique, chain.Steps[i].Type)
			c.graph.AddEdge(prev, curr, graph.EdgeExploits)
		}
	}

	c.chains = append(c.chains, newChains...)
	return newChains
}

func (c *Chainer) scoreChain(steps []ChainStep) float64 {
	if len(steps) == 0 {
		return 0
	}
	score := 0.0
	for _, s := range steps {
		score += s.Confidence
	}
	score /= float64(len(steps))

	for _, s := range steps {
		switch s.Impact {
		case "critical":
			score += 0.2
		case "high":
			score += 0.1
		}
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

func (c *Chainer) buildSummary(steps []ChainStep) string {
	var parts []string
	for _, s := range steps {
		parts = append(parts, s.Type)
	}
	return strings.Join(parts, " → ")
}

func (c *Chainer) Chains() []ExploitChain {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]ExploitChain, len(c.chains))
	copy(result, c.chains)
	return result
}

func (c *Chainer) HighValueChains(minScore float64) []ExploitChain {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var result []ExploitChain
	for _, chain := range c.chains {
		if chain.Score >= minScore {
			result = append(result, chain)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Score > result[j].Score
	})
	return result
}

func (c *Chainer) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chains = make([]ExploitChain, 0)
}

func (c *Chainer) AllChains() []ExploitChain {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]ExploitChain, len(c.chains))
	copy(result, c.chains)
	return result
}

func (c *Chainer) ImpactSummary() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	summary := make(map[string]int)
	for _, chain := range c.chains {
		summary[chain.Impact]++
	}
	return summary
}

func (c *Chainer) LoadDSLChains(builder *chaindsl.ChainBuilder, findings []string) {
	if builder == nil {
		return
	}
	matched := builder.Match(findings)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, def := range matched {
		steps := make([]ChainStep, len(def.Steps))
		for i, s := range def.Steps {
			steps[i] = ChainStep{
				Type:       s.Technique,
				Technique:  s.Technique,
				Confidence: def.Score,
				Impact:     s.Impact,
			}
		}
		exploitChain := ExploitChain{
			ID:        fmt.Sprintf("dsl-%s-%s", def.Name, generateSecureID()),
			Steps:     steps,
			Score:     def.Score,
			Summary:   def.Description,
			CreatedAt: time.Now(),
		}
		c.chains = append(c.chains, exploitChain)
	}
}

var complexMap = map[string]time.Duration{
	"low":      5 * time.Minute,
	"medium":   30 * time.Minute,
	"high":     2 * time.Hour,
	"critical": 8 * time.Hour,
}

var defaultComplexity = 1 * time.Hour

var MITREAttackMap = map[string]struct {
	ID   string
	Name string
}{
	"ssrf":                         {"T1190", "Exploit Public-Facing Application"},
	"sqli":                         {"T1190", "Exploit Public-Facing Application"},
	"xss":                          {"T1059", "Command and Scripting Interpreter"},
	"open_redirect":                {"T1204", "User Execution"},
	"weak_jwt":                     {"T1528", "Steal Application Access Token"},
	"idor":                         {"T1213", "Data from Information Repositories"},
	"credentials":                  {"T1078", "Valid Accounts"},
	"lfi":                          {"T1190", "Exploit Public-Facing Application"},
	"api_key_leak":                 {"T1552", "Unsecured Credentials"},
	"internal_service":             {"T1021", "Remote Services"},
	"cloud_credentials":            {"T1528", "Steal Application Access Token"},
	"database_credentials":         {"T1552", "Unsecured Credentials"},
	"session_hijack":               {"T1539", "Steal Web Session Cookie"},
	"admin_access":                 {"T1078", "Valid Accounts"},
	"pii_disclosure":               {"T1048", "Exfiltration Over Alternative Protocol"},
	"lateral_movement":             {"T1021", "Remote Services"},
	"rce":                          {"T1203", "Exploitation for Client Execution"},
	"service_compromise":           {"T1190", "Exploit Public-Facing Application"},
	"internal_rce":                 {"T1203", "Exploitation for Client Execution"},
	"internal_reach":               {"T1090", "Proxy"},
	"exposed_admin":                {"T1078", "Valid Accounts"},
	"file_write":                   {"T1574", "Hijack Execution Flow"},
	"data_exfiltration":            {"T1048", "Exfiltration Over Alternative Protocol"},
	"container_escape":             {"T1611", "Escape to Host"},
	"ransomware":                   {"T1486", "Data Encrypted for Impact"},
	"credential_theft":             {"T1003", "OS Credential Dumping"},
	"cloud_abuse":                  {"T1078", "Valid Accounts"},
	"ssrf-to-rce":                  {"T1190", "Exploit Public-Facing Application"},
	"sqli-to-pwn":                  {"T1190", "Exploit Public-Facing Application"},
	"xss-to-account-takeover":      {"T1059", "Command and Scripting Interpreter"},
	"open-redirect-to-ssrf-to-rce": {"T1204", "User Execution"},
	"idor-to-privilege-escalation": {"T1213", "Data from Information Repositories"},
}

func MapToMITRE(findingTitle string) (techniqueID, techniqueName string) {
	key := strings.ToLower(strings.TrimSpace(findingTitle))
	if entry, ok := MITREAttackMap[key]; ok {
		return entry.ID, entry.Name
	}
	return "T1585", "Establish Accounts"
}

type ChainTemplate struct {
	Name        string
	Description string
	Tags        []string
	Steps       []ChainStep
}

func DefaultTemplates() []ChainTemplate {
	return []ChainTemplate{
		{
			Name:        "ransomware",
			Description: "Ransomware deployment chain: initial access to data encryption",
			Tags:        []string{"ransomware", "impact", "encryption"},
			Steps: []ChainStep{
				{Type: "phishing", Technique: "Phishing", Confidence: 0.7, ConfidenceMin: 0.5, ConfidenceMax: 0.85, Impact: "medium", Complexity: "low", NextSteps: []string{"initial_access"}},
				{Type: "initial_access", Technique: "Initial Access", Confidence: 0.75, ConfidenceMin: 0.6, ConfidenceMax: 0.9, Impact: "high", Complexity: "low", NextSteps: []string{"persistence"}},
				{Type: "persistence", Technique: "Establish Persistence", Confidence: 0.8, ConfidenceMin: 0.65, ConfidenceMax: 0.9, Impact: "high", Complexity: "medium", NextSteps: []string{"lateral_movement"}},
				{Type: "lateral_movement", Technique: "Lateral Movement", Confidence: 0.7, ConfidenceMin: 0.55, ConfidenceMax: 0.85, Impact: "critical", Complexity: "medium", NextSteps: []string{"data_theft"}},
				{Type: "data_theft", Technique: "Data Exfiltration", Confidence: 0.75, ConfidenceMin: 0.6, ConfidenceMax: 0.85, Impact: "critical", Complexity: "high", NextSteps: []string{"ransomware"}},
				{Type: "ransomware", Technique: "Ransomware Deployment", Confidence: 0.85, ConfidenceMin: 0.7, ConfidenceMax: 0.95, Impact: "critical", Complexity: "medium"},
			},
		},
		{
			Name:        "data_exfiltration",
			Description: "Data exfiltration chain: from access to data theft",
			Tags:        []string{"exfiltration", "data_theft", "pii"},
			Steps: []ChainStep{
				{Type: "ssrf", Technique: "Server-Side Request Forgery", Confidence: 0.7, ConfidenceMin: 0.5, ConfidenceMax: 0.85, Impact: "high", Complexity: "medium", NextSteps: []string{"internal_access"}},
				{Type: "internal_access", Technique: "Internal Network Access", Confidence: 0.8, ConfidenceMin: 0.65, ConfidenceMax: 0.9, Impact: "high", Complexity: "medium", NextSteps: []string{"data_discovery"}},
				{Type: "data_discovery", Technique: "Data Discovery", Confidence: 0.75, ConfidenceMin: 0.6, ConfidenceMax: 0.85, Impact: "medium", Complexity: "low", NextSteps: []string{"data_exfiltration"}},
				{Type: "data_exfiltration", Technique: "Data Exfiltration", Confidence: 0.8, ConfidenceMin: 0.65, ConfidenceMax: 0.9, Impact: "critical", Complexity: "high"},
			},
		},
		{
			Name:        "credential_theft",
			Description: "Credential theft chain: from initial access to credential dumping",
			Tags:        []string{"credentials", "theft", "T1003"},
			Steps: []ChainStep{
				{Type: "sqli", Technique: "SQL Injection", Confidence: 0.75, ConfidenceMin: 0.6, ConfidenceMax: 0.9, Impact: "critical", Complexity: "medium", NextSteps: []string{"database_credentials"}},
				{Type: "database_credentials", Technique: "Database Credential Extraction", Confidence: 0.85, ConfidenceMin: 0.7, ConfidenceMax: 0.95, Impact: "critical", Complexity: "low", NextSteps: []string{"credential_theft"}},
				{Type: "credential_theft", Technique: "OS Credential Dumping", Confidence: 0.8, ConfidenceMin: 0.65, ConfidenceMax: 0.9, Impact: "critical", Complexity: "high"},
			},
		},
		{
			Name:        "container_escape",
			Description: "Container escape chain: from container access to host compromise",
			Tags:        []string{"container", "escape", "T1611"},
			Steps: []ChainStep{
				{Type: "container_access", Technique: "Container Access", Confidence: 0.7, ConfidenceMin: 0.5, ConfidenceMax: 0.85, Impact: "high", Complexity: "medium", NextSteps: []string{"container_escape"}},
				{Type: "container_escape", Technique: "Container Escape to Host", Confidence: 0.6, ConfidenceMin: 0.4, ConfidenceMax: 0.8, Impact: "critical", Complexity: "high", NextSteps: []string{"host_access"}},
				{Type: "host_access", Technique: "Host Compromise", Confidence: 0.75, ConfidenceMin: 0.6, ConfidenceMax: 0.9, Impact: "critical", Complexity: "low"},
			},
		},
		{
			Name:        "cloud_credential_abuse",
			Description: "Cloud credential abuse chain: from leaked key to full compromise",
			Tags:        []string{"cloud", "credentials", "abuse", "T1078"},
			Steps: []ChainStep{
				{Type: "api_key_leak", Technique: "Cloud API Key Leak", Confidence: 0.7, ConfidenceMin: 0.5, ConfidenceMax: 0.85, Impact: "high", Complexity: "low", NextSteps: []string{"cloud_discovery"}},
				{Type: "cloud_discovery", Technique: "Cloud Resource Discovery", Confidence: 0.8, ConfidenceMin: 0.65, ConfidenceMax: 0.9, Impact: "medium", Complexity: "low", NextSteps: []string{"privilege_escalation"}},
				{Type: "privilege_escalation", Technique: "Cloud Privilege Escalation", Confidence: 0.65, ConfidenceMin: 0.45, ConfidenceMax: 0.8, Impact: "critical", Complexity: "high", NextSteps: []string{"data_exfiltration"}},
				{Type: "data_exfiltration", Technique: "Cloud Data Exfiltration", Confidence: 0.75, ConfidenceMin: 0.6, ConfidenceMax: 0.9, Impact: "critical", Complexity: "medium"},
			},
		},
	}
}

func ProbabilisticScore(chain ExploitChain) float64 {
	if len(chain.Steps) == 0 {
		return 0
	}
	prob := 1.0
	var prevImpact string
	for i, step := range chain.Steps {
		p := step.Confidence
		if step.ConfidenceMin > 0 || step.ConfidenceMax > 0 {
			p = (step.ConfidenceMin + step.ConfidenceMax) / 2.0
		}
		if p <= 0 || p > 1 {
			p = 0.5
		}
		if i > 0 {
			factor := 1.0
			switch step.Impact {
			case "critical":
				factor = 0.95
			case "high":
				factor = 0.97
			case "medium":
				factor = 0.99
			}
			switch prevImpact {
			case "critical":
				factor *= 0.98
			case "high":
				factor *= 0.99
			}
			p *= factor
		}
		prob *= p
		prevImpact = step.Impact
	}
	return math.Round(prob*10000) / 10000
}

func (c *Chainer) ChainGraph() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dag := make(map[string][]string)
	for _, chain := range c.chains {
		for i, step := range chain.Steps {
			nodeID := fmt.Sprintf("%s:%s", chain.ID, step.Type)
			if _, ok := dag[nodeID]; !ok {
				dag[nodeID] = nil
			}
			if i > 0 {
				prevID := fmt.Sprintf("%s:%s", chain.ID, chain.Steps[i-1].Type)
				dag[prevID] = append(dag[prevID], nodeID)
			}
		}
	}
	return dag
}

func EstimateTimeToExploit(chain ExploitChain) string {
	if len(chain.Steps) == 0 {
		return "0s"
	}
	total := time.Duration(0)
	for _, step := range chain.Steps {
		complexity := step.Complexity
		if complexity == "" {
			complexity = "medium"
		}
		d, ok := complexMap[strings.ToLower(complexity)]
		if !ok {
			d = defaultComplexity
		}
		total += d
	}
	return total.Round(time.Minute).String()
}

// CVSSChainScore computes a combined CVSS-like score for the entire exploit
// chain. Each step's Impact is mapped to a CVSS base score (critical=9.5,
// high=7.5, medium=5.5, low=2.5). The chain score is the mean of step scores
// de-rated by attack-complexity multipliers based on chain length and severity
// diversity. Returns a score in [0,10].
func CVSSChainScore(chain ExploitChain) float64 {
	if len(chain.Steps) == 0 {
		return 0
	}
	sum := 0.0
	for _, s := range chain.Steps {
		sum += impactToCVSS(s.Impact)
	}
	mean := sum / float64(len(chain.Steps))

	multiplier := 1.0
	if len(chain.Steps) > 1 {
		multiplier *= 1.0 - 0.05*float64(len(chain.Steps)-1)
	}
	seen := make(map[string]bool)
	for _, s := range chain.Steps {
		seen[s.Impact] = true
	}
	if len(seen) > 1 {
		multiplier *= 1.0 - 0.05*float64(len(seen)-1)
	}
	if chain.Score > 0 {
		multiplier *= chain.Score
	}
	if multiplier < 0.1 {
		multiplier = 0.1
	}
	score := mean * multiplier
	if score > 10 {
		score = 10
	}
	return math.Round(score*100) / 100
}

func impactToCVSS(impact string) float64 {
	switch impact {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.5
	case "low":
		return 2.5
	default:
		return 5.0
	}
}

// ChainCVSSReport produces a structured CVSS-like breakdown for the chain
// using the report package's CVSS calculator for the final step when possible.
type ChainCVSSReport struct {
	ChainID              string    `json:"chain_id"`
	Summary              string    `json:"summary"`
	StepScores           []float64 `json:"step_scores"`
	MeanScore            float64   `json:"mean_score"`
	LengthPenalty        float64   `json:"length_penalty"`
	DiversityPenalty     float64   `json:"diversity_penalty"`
	ConfidenceMultiplier float64   `json:"confidence_multiplier"`
	ChainScore           float64   `json:"chain_score"`
	Vector               string    `json:"vector,omitempty"`
	LastStepScore        float64   `json:"last_step_score,omitempty"`
}

// ProduceCVSSReport builds a ChainCVSSReport for the given chain, optionally
// attaching a CVSS v3.1 vector from the report package if the final step maps
// to a known finding type.
func (c *Chainer) ProduceCVSSReport(chain ExploitChain) ChainCVSSReport {
	if len(chain.Steps) == 0 {
		return ChainCVSSReport{ChainID: chain.ID, Summary: chain.Summary}
	}
	stepScores := make([]float64, len(chain.Steps))
	for i, s := range chain.Steps {
		stepScores[i] = impactToCVSS(s.Impact)
	}

	lengthPenalty := 1.0
	if len(chain.Steps) > 1 {
		lengthPenalty = 1.0 - 0.05*float64(len(chain.Steps)-1)
	}

	seen := make(map[string]bool)
	for _, s := range chain.Steps {
		seen[s.Impact] = true
	}
	diversityPenalty := 1.0
	if len(seen) > 1 {
		diversityPenalty = 1.0 - 0.05*float64(len(seen)-1)
	}

	confidenceMult := chain.Score
	if confidenceMult <= 0 {
		confidenceMult = 1.0
	}

	finalScore := CVSSChainScore(chain)

	r := ChainCVSSReport{
		ChainID:              chain.ID,
		Summary:              chain.Summary,
		StepScores:           stepScores,
		MeanScore:            math.Round((sumFloat64s(stepScores)/float64(len(stepScores)))*100) / 100,
		LengthPenalty:        math.Round(lengthPenalty*100) / 100,
		DiversityPenalty:     math.Round(diversityPenalty*100) / 100,
		ConfidenceMultiplier: math.Round(confidenceMult*100) / 100,
		ChainScore:           finalScore,
	}

	if len(chain.Steps) > 0 {
		lastStep := chain.Steps[len(chain.Steps)-1]
		cvss := report.CVSSForFinding(lastStep.Type, lastStep.Impact)
		r.Vector = cvss.Vector
		r.LastStepScore = math.Round(cvss.BaseScore*10) / 10
	}

	return r
}

func sumFloat64s(vals []float64) float64 {
	s := 0.0
	for _, v := range vals {
		s += v
	}
	return s
}
