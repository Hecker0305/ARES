package chaindsl

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var allowedYAMLDir = ""

func SetAllowedYAMLDir(dir string) {
	allowedYAMLDir = dir
}

type ChainDef struct {
	Name        string    `json:"name" yaml:"name"`
	Description string    `json:"description" yaml:"description"`
	Steps       []StepDef `json:"steps" yaml:"steps"`
	Score       float64   `json:"score" yaml:"score"`
}

type StepDef struct {
	ID          string   `json:"id" yaml:"id"`
	Technique   string   `json:"technique" yaml:"technique"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Prereqs     []string `json:"prereqs,omitempty" yaml:"prereqs,omitempty"`
	Produces    []string `json:"produces,omitempty" yaml:"produces,omitempty"`
	Impact      string   `json:"impact,omitempty" yaml:"impact,omitempty"`
}

type ChainBuilder struct {
	mu     sync.RWMutex
	chains map[string]ChainDef
}

func New() *ChainBuilder {
	b := &ChainBuilder{chains: make(map[string]ChainDef)}
	b.registerDefaultChains()
	return b
}

func (b *ChainBuilder) registerDefaultChains() {
	b.Register(ChainDef{
		Name:        "ssrf-to-rce",
		Description: "SSRF → Cloud Metadata → Credentials → Privilege Escalation → RCE",
		Steps: []StepDef{
			{ID: "ssrf", Technique: "SSRF", Description: "Server-Side Request Forgery", Produces: []string{"internal_access"}, Impact: "high"},
			{ID: "metadata", Technique: "Cloud Metadata Access", Prereqs: []string{"ssrf"}, Produces: []string{"cloud_creds"}, Impact: "critical"},
			{ID: "creds", Technique: "Credential Extraction", Prereqs: []string{"metadata"}, Produces: []string{"aws_keys", "iam_role"}, Impact: "critical"},
			{ID: "escalate", Technique: "Cloud Privilege Escalation", Prereqs: []string{"creds"}, Produces: []string{"admin_access"}, Impact: "critical"},
			{ID: "rce", Technique: "Remote Code Execution", Prereqs: []string{"escalate"}, Produces: []string{"full_compromise"}, Impact: "critical"},
		},
		Score: 0.95,
	})
	b.Register(ChainDef{
		Name:        "sqli-to-pwn",
		Description: "SQLi → Database Access → Credentials → Lateral Movement → RCE",
		Steps: []StepDef{
			{ID: "sqli", Technique: "SQL Injection", Produces: []string{"db_access"}, Impact: "critical"},
			{ID: "extract", Technique: "Credential Extraction", Prereqs: []string{"sqli"}, Produces: []string{"db_creds"}, Impact: "critical"},
			{ID: "pivot", Technique: "Lateral Movement", Prereqs: []string{"extract"}, Produces: []string{"internal_access"}, Impact: "critical"},
			{ID: "shell", Technique: "Command Execution", Prereqs: []string{"pivot"}, Produces: []string{"rce"}, Impact: "critical"},
		},
		Score: 0.9,
	})
	b.Register(ChainDef{
		Name:        "xss-to-account-takeover",
		Description: "XSS → Session Hijack → Admin Access → PII Theft",
		Steps: []StepDef{
			{ID: "xss", Technique: "Cross-Site Scripting", Produces: []string{"xss_trigger"}, Impact: "medium"},
			{ID: "session", Technique: "Session Hijacking", Prereqs: []string{"xss"}, Produces: []string{"user_session"}, Impact: "high"},
			{ID: "escalate", Technique: "Privilege Escalation", Prereqs: []string{"session"}, Produces: []string{"admin_access"}, Impact: "critical"},
			{ID: "exfil", Technique: "Data Exfiltration", Prereqs: []string{"escalate"}, Produces: []string{"pii_data"}, Impact: "critical"},
		},
		Score: 0.85,
	})
	b.Register(ChainDef{
		Name:        "open-redirect-to-ssrf-to-rce",
		Description: "Open Redirect → SSRF → Internal Service → RCE",
		Steps: []StepDef{
			{ID: "open_redirect", Technique: "Open Redirect", Produces: []string{"redirect"}, Impact: "low"},
			{ID: "ssrf", Technique: "SSRF via Redirect", Prereqs: []string{"open_redirect"}, Produces: []string{"internal_access"}, Impact: "high"},
			{ID: "rce", Technique: "RCE via Internal Service", Prereqs: []string{"ssrf"}, Produces: []string{"compromise"}, Impact: "critical"},
		},
		Score: 0.8,
	})
	b.Register(ChainDef{
		Name:        "idor-to-privilege-escalation",
		Description: "IDOR → Privilege Escalation → Admin Access",
		Steps: []StepDef{
			{ID: "idor", Technique: "Insecure Direct Object Reference", Produces: []string{"unauth_access"}, Impact: "high"},
			{ID: "escalate", Technique: "Privilege Escalation", Prereqs: []string{"idor"}, Produces: []string{"admin_access"}, Impact: "critical"},
		},
		Score: 0.75,
	})
	b.Register(ChainDef{
		Name:        "initial-access-phishing",
		Description: "Phishing → Credential Harvest → Initial Access",
		Steps: []StepDef{
			{ID: "phish", Technique: "Spearphishing Link", Produces: []string{"user_click"}, Impact: "medium"},
			{ID: "harvest", Technique: "Credential Harvesting", Prereqs: []string{"phish"}, Produces: []string{"access_creds"}, Impact: "high"},
			{ID: "access", Technique: "Initial Access", Prereqs: []string{"harvest"}, Produces: []string{"foothold"}, Impact: "critical"},
		},
		Score: 0.9,
	})
	b.Register(ChainDef{
		Name:        "persistence-backdoor",
		Description: "Code Execution → Registry Run Key → Persistence",
		Steps: []StepDef{
			{ID: "exec", Technique: "Execution via API", Produces: []string{"code_exec"}, Impact: "high"},
			{ID: "reg_run", Technique: "Registry Run Keys / Startup Folder", Prereqs: []string{"exec"}, Produces: []string{"persistence"}, Impact: "high"},
			{ID: "backdoor", Technique: "Backdoor Account", Prereqs: []string{"reg_run"}, Produces: []string{"persistent_access"}, Impact: "critical"},
		},
		Score: 0.8,
	})
	b.Register(ChainDef{
		Name:        "defense-evasion",
		Description: "Admin Access → Disable Logging → Process Injection → Defense Evasion",
		Steps: []StepDef{
			{ID: "admin", Technique: "Valid Accounts", Produces: []string{"admin_privilege"}, Impact: "high"},
			{ID: "disable_log", Technique: "Disable Windows Event Logging", Prereqs: []string{"admin"}, Produces: []string{"blindness"}, Impact: "high"},
			{ID: "inject", Technique: "Process Injection", Prereqs: []string{"disable_log"}, Produces: []string{"evasion"}, Impact: "critical"},
		},
		Score: 0.7,
	})
	b.Register(ChainDef{
		Name:        "credential-dumping",
		Description: "Admin Access → Credential Dumping → Lateral Movement",
		Steps: []StepDef{
			{ID: "admin", Technique: "Valid Accounts", Produces: []string{"admin_privilege"}, Impact: "high"},
			{ID: "dump", Technique: "OS Credential Dumping", Prereqs: []string{"admin"}, Produces: []string{"hashes", "tickets"}, Impact: "critical"},
			{ID: "pass_the_hash", Technique: "Pass the Hash", Prereqs: []string{"dump"}, Produces: []string{"lateral_access"}, Impact: "critical"},
		},
		Score: 0.85,
	})
	b.Register(ChainDef{
		Name:        "discovery-recon",
		Description: "Foothold → Network Discovery → Account Discovery",
		Steps: []StepDef{
			{ID: "foothold", Technique: "Initial Access", Produces: []string{"internal_foothold"}, Impact: "high"},
			{ID: "net_discover", Technique: "Network Service Discovery", Prereqs: []string{"foothold"}, Produces: []string{"network_map"}, Impact: "medium"},
			{ID: "account_discover", Technique: "Account Discovery", Prereqs: []string{"net_discover"}, Produces: []string{"user_enum"}, Impact: "medium"},
		},
		Score: 0.6,
	})
	b.Register(ChainDef{
		Name:        "command-and-control",
		Description: "Foothold → C2 Beacon → Data Staging → Exfiltration",
		Steps: []StepDef{
			{ID: "foothold", Technique: "Initial Access", Produces: []string{"internal_foothold"}, Impact: "high"},
			{ID: "c2_beacon", Technique: "C2 Beacon", Prereqs: []string{"foothold"}, Produces: []string{"c2_channel"}, Impact: "critical"},
			{ID: "stage", Technique: "Data Staging", Prereqs: []string{"c2_beacon"}, Produces: []string{"staged_data"}, Impact: "critical"},
			{ID: "exfil", Technique: "Data Exfiltration", Prereqs: []string{"stage"}, Produces: []string{"data_exfiltrated"}, Impact: "critical"},
		},
		Score: 0.7,
	})
	b.Register(ChainDef{
		Name:        "impact-ransomware",
		Description: "Admin Access → Data Destruction → Impact: Ransomware",
		Steps: []StepDef{
			{ID: "admin", Technique: "Valid Accounts", Produces: []string{"admin_privilege"}, Impact: "high"},
			{ID: "destroy", Technique: "Data Destruction", Prereqs: []string{"admin"}, Produces: []string{"data_loss"}, Impact: "critical"},
			{ID: "ransom", Technique: "Ransomware Deployment", Prereqs: []string{"destroy"}, Produces: []string{"business_impact"}, Impact: "critical"},
		},
		Score: 0.65,
	})
}

func (b *ChainBuilder) Register(def ChainDef) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.chains[def.Name] = def
}

func (b *ChainBuilder) Get(name string) *ChainDef {
	b.mu.RLock()
	defer b.mu.RUnlock()
	def, ok := b.chains[name]
	if !ok {
		return nil
	}
	return &def
}

func (b *ChainBuilder) Match(findings []string) []ChainDef {
	b.mu.RLock()
	defer b.mu.RUnlock()

	findingSet := make(map[string]bool)
	for _, f := range findings {
		findingSet[strings.ToLower(f)] = true
	}

	var matched []ChainDef
	for name, def := range b.chains {
		if b.matches(def, findingSet) {
			def.Name = name
			matched = append(matched, def)
		}
	}
	return matched
}

func (b *ChainBuilder) matches(def ChainDef, findings map[string]bool) bool {
	for _, step := range def.Steps {
		if len(step.Prereqs) == 0 {
			continue
		}
		allPrereqsMet := true
		for _, prereq := range step.Prereqs {
			if !findings[prereq] {
				allPrereqsMet = false
				break
			}
		}
		if allPrereqsMet {
			return true
		}
	}
	return false
}

func (b *ChainBuilder) All() []ChainDef {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []ChainDef
	for _, def := range b.chains {
		out = append(out, def)
	}
	return out
}

func (def ChainDef) Validate() error {
	if def.Name == "" {
		return fmt.Errorf("chain name required")
	}
	if len(def.Steps) == 0 {
		return fmt.Errorf("chain %s has no steps", def.Name)
	}

	idMap := make(map[string]bool)
	allIDs := make(map[string]bool)
	allPrereqs := make(map[string]bool)

	for _, step := range def.Steps {
		if step.ID == "" {
			return fmt.Errorf("chain %s: step missing id", def.Name)
		}
		if idMap[step.ID] {
			return fmt.Errorf("chain %s: duplicate step id %s", def.Name, step.ID)
		}
		idMap[step.ID] = true
		allIDs[step.ID] = true

		for _, prereq := range step.Prereqs {
			allPrereqs[prereq] = true
			if !idMap[prereq] {
				return fmt.Errorf("chain %s: step %s references unknown prereq %s", def.Name, step.ID, prereq)
			}
		}
	}

	for prereq := range allPrereqs {
		if !allIDs[prereq] {
			return fmt.Errorf("chain %s: prereq %s references nonexistent step", def.Name, prereq)
		}
	}

	referenced := make(map[string]bool)
	for _, step := range def.Steps {
		for _, p := range step.Prereqs {
			referenced[p] = true
		}
	}
	for _, step := range def.Steps {
		if !referenced[step.ID] && len(step.Prereqs) == 0 && len(step.Produces) == 0 && len(def.Steps) > 1 {
			return fmt.Errorf("chain %s: contains orphaned step %s with no prereqs or produces (may be disconnected)", def.Name, step.ID)
		}
	}

	if hasCycle(def) {
		return fmt.Errorf("chain %s: contains a cycle in prereq/produces DAG", def.Name)
	}

	return nil
}

func hasCycle(def ChainDef) bool {
	adj := make(map[string][]string)
	for _, step := range def.Steps {
		for _, prereq := range step.Prereqs {
			adj[prereq] = append(adj[prereq], step.ID)
		}
	}

	visited := make(map[string]int)
	var dfs func(id string) bool
	dfs = func(id string) bool {
		if visited[id] == 1 {
			return true
		}
		if visited[id] == 2 {
			return false
		}
		visited[id] = 1
		for _, neighbor := range adj[id] {
			if dfs(neighbor) {
				return true
			}
		}
		visited[id] = 2
		return false
	}

	for _, step := range def.Steps {
		if dfs(step.ID) {
			return true
		}
	}
	return false
}

func (def ChainDef) String() string {
	var parts []string
	for _, step := range def.Steps {
		parts = append(parts, step.Technique)
	}
	return strings.Join(parts, " → ")
}

func (b *ChainBuilder) LoadYAML(path string) error {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal not allowed in YAML path: %s", path)
	}
	if allowedYAMLDir != "" {
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path %s: %w", path, err)
		}
		absAllowed, err := filepath.Abs(allowedYAMLDir)
		if err != nil {
			return fmt.Errorf("failed to resolve allowed directory: %w", err)
		}
		if !strings.HasPrefix(absPath, absAllowed) {
			return fmt.Errorf("YAML path %s is outside allowed directory %s", absPath, absAllowed)
		}
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks not allowed for YAML files: %s", path)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var defs []ChainDef
	if err := yaml.Unmarshal(data, &defs); err != nil {
		return fmt.Errorf("failed to parse YAML from %s: %w", path, err)
	}

	for _, def := range defs {
		if err := def.Validate(); err != nil {
			return fmt.Errorf("validation failed for %s: %w", def.Name, err)
		}
		b.Register(def)
	}
	return nil
}

func GenerateFromFindings(findings []string) []ChainDef {
	if len(findings) < 2 {
		return nil
	}

	tacticPatterns := map[string]string{
		"sqli":                 "SQL Injection",
		"xss":                  "Cross-Site Scripting",
		"ssrf":                 "Server-Side Request Forgery",
		"rce":                  "Remote Code Execution",
		"idor":                 "Insecure Direct Object Reference",
		"lfi":                  "Local File Inclusion",
		"rfi":                  "Remote File Inclusion",
		"open_redirect":        "Open Redirect",
		"csrf":                 "Cross-Site Request Forgery",
		"xxe":                  "XML External Entity",
		"deserialization":      "Insecure Deserialization",
		"cmd_injection":        "Command Injection",
		"ldap_injection":       "LDAP Injection",
		"nosqli":               "NoSQL Injection",
		"phishing":             "Phishing",
		"log4j":                "Log4Shell",
		"privilege_escalation": "Privilege Escalation",
		"lateral_movement":     "Lateral Movement",
		"discovery":            "Discovery",
		"exfiltration":         "Exfiltration",
		"persistence":          "Persistence",
		"credential_access":    "Credential Access",
		"defense_evasion":      "Defense Evasion",
		"collection":           "Collection",
		"c2":                   "Command and Control",
		"impact":               "Impact",
	}

	steps := make([]StepDef, 0, len(findings))
	for i, f := range findings {
		lower := strings.ToLower(f)
		technique := tacticPatterns[lower]
		if technique == "" {
			technique = f
		}
		step := StepDef{
			ID:        fmt.Sprintf("step_%s", lower),
			Technique: technique,
			Produces:  []string{fmt.Sprintf("%s_done", lower)},
			Impact:    "medium",
		}
		if i > 0 {
			step.Prereqs = []string{fmt.Sprintf("step_%s", strings.ToLower(findings[i-1]))}
		}
		steps = append(steps, step)
	}

	chain := ChainDef{
		Name:        fmt.Sprintf("dynamic-%s", strings.Join(findings, "-to-")),
		Description: fmt.Sprintf("Auto-generated chain: %s", strings.Join(findings, " → ")),
		Steps:       steps,
		Score:       0.5,
	}

	last := strings.ToLower(findings[len(findings)-1])
	switch {
	case strings.Contains(last, "rce") || strings.Contains(last, "shell") || strings.Contains(last, "exec"):
		chain.Score = 0.7
	case strings.Contains(last, "exfil") || strings.Contains(last, "pii") || strings.Contains(last, "data"):
		chain.Score = 0.75
	case strings.Contains(last, "admin") || strings.Contains(last, "root") || strings.Contains(last, "escalat"):
		chain.Score = 0.65
	}

	return []ChainDef{chain}
}

func Compose(names ...string) (*ChainDef, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one chain name required")
	}

	b := New()
	var allSteps []StepDef
	seenIDs := make(map[string]int)
	var lastStepID string
	description := ""

	for i, name := range names {
		def := b.Get(name)
		if def == nil {
			return nil, fmt.Errorf("chain %s not found", name)
		}
		if i > 0 {
			description += " ++ "
		}
		description += def.Description

		for _, step := range def.Steps {
			suffix := ""
			if seenIDs[step.ID] > 0 {
				suffix = fmt.Sprintf("_%d", i)
			}
			newID := step.ID + suffix
			seenIDs[step.ID]++

			var newPrereqs []string
			for _, p := range step.Prereqs {
				newPrereqs = append(newPrereqs, p+suffix)
			}

			if i > 0 && step.ID == def.Steps[0].ID && lastStepID != "" {
				if step.Prereqs == nil {
					newPrereqs = []string{lastStepID}
				} else {
					found := false
					for _, p := range newPrereqs {
						if p == lastStepID {
							found = true
							break
						}
					}
					if !found {
						newPrereqs = append([]string{lastStepID}, newPrereqs...)
					}
				}
			}

			allSteps = append(allSteps, StepDef{
				ID:          newID,
				Technique:   step.Technique,
				Description: step.Description,
				Prereqs:     newPrereqs,
				Produces:    step.Produces,
				Impact:      step.Impact,
			})
		}
		lastStepID = def.Steps[len(def.Steps)-1].ID
		if seenIDs[lastStepID] > 1 {
			lastStepID = lastStepID + fmt.Sprintf("_%d", i)
		}
	}

	composite := ChainDef{
		Name:        "composite-" + strings.Join(names, "-"),
		Description: description,
		Steps:       allSteps,
		Score:       0.5,
	}

	if err := composite.Validate(); err != nil {
		return nil, fmt.Errorf("composite chain invalid: %w", err)
	}

	return &composite, nil
}

func ScoreChain(def ChainDef, findings []string) float64 {
	if len(def.Steps) == 0 || len(findings) == 0 {
		return 0
	}

	findingsLower := make([]string, len(findings))
	for i, f := range findings {
		findingsLower[i] = strings.ToLower(f)
	}

	findingTF := make(map[string]float64)
	for _, f := range findingsLower {
		findingTF[f]++
	}
	for k, v := range findingTF {
		findingTF[k] = v / float64(len(findings))
	}

	findingIDF := make(map[string]float64)
	docTermSet := make(map[int]map[string]bool)
	for i, f := range findingsLower {
		if docTermSet[i] == nil {
			docTermSet[i] = make(map[string]bool)
		}
		docTermSet[i][f] = true
	}
	for _, terms := range docTermSet {
		for term := range terms {
			findingIDF[term] = 1.0
		}
	}
	docCount := float64(len(findingsLower))
	for term := range findingIDF {
		docsWithTerm := 0
		for _, terms := range docTermSet {
			if terms[term] {
				docsWithTerm++
			}
		}
		if docsWithTerm > 0 {
			findingIDF[term] = math.Log(1 + (1+docCount)/(1+float64(docsWithTerm)))
		}
	}

	chainTF := make(map[string]float64)
	totalChainTerms := 0
	chainTerms := make([]string, 0)
	for _, step := range def.Steps {
		tokens := tokenize(step.Technique + " " + step.Description + " " + step.Impact + " " + strings.Join(step.Produces, " "))
		for _, t := range tokens {
			chainTerms = append(chainTerms, t)
		}
	}
	for _, t := range chainTerms {
		chainTF[t]++
	}
	totalChainTerms = len(chainTerms)
	if totalChainTerms == 0 {
		return 0
	}
	for k, v := range chainTF {
		chainTF[k] = v / float64(totalChainTerms)
	}

	findingTFIDF := make(map[string]float64)
	for term, tf := range findingTF {
		idf := findingIDF[term]
		if idf == 0 {
			idf = 1.0
		}
		findingTFIDF[term] = tf * idf
	}

	chainTFIDF := make(map[string]float64)
	for term, tf := range chainTF {
		idf := findingIDF[term]
		if idf == 0 {
			idf = 1.0
		}
		chainTFIDF[term] = tf * idf
	}

	var dotProduct, findingNorm, chainNorm float64
	for term, val := range findingTFIDF {
		dotProduct += val * chainTFIDF[term]
		findingNorm += val * val
	}
	for _, val := range chainTFIDF {
		chainNorm += val * val
	}

	findingNorm = math.Sqrt(findingNorm)
	chainNorm = math.Sqrt(chainNorm)

	if findingNorm == 0 || chainNorm == 0 {
		return 0
	}

	return dotProduct / (findingNorm * chainNorm)
}

func tokenize(s string) []string {
	lower := strings.ToLower(s)
	parts := strings.FieldsFunc(lower, func(r rune) bool {
		return r == ' ' || r == '_' || r == '-' || r == '/' || r == '\\' || r == '(' || r == ')' || r == ',' || r == '.'
	})
	var out []string
	for _, p := range parts {
		if len(p) > 0 {
			out = append(out, p)
		}
	}
	return out
}

func (b *ChainBuilder) saveYAML(path string) error {
	defs := b.All()

	data, err := yaml.Marshal(defs)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	return nil
}

func chainsByScore(defs []ChainDef) []ChainDef {
	sorted := make([]ChainDef, len(defs))
	copy(sorted, defs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})
	return sorted
}
