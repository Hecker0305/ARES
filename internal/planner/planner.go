package planner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/uuid"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/policy"
	"github.com/ares/engine/internal/security"
)

const llmPlanningTimeout = 30 * time.Second

type Phase int

const (
	PhaseRecon     Phase = 0
	PhaseDiscovery Phase = 1
	PhaseExploit   Phase = 2
	PhasePostExp   Phase = 3
	PhaseReport    Phase = 4
)

type IPlanningStrategy interface {
	Name() string
	CalculatePriority(target string) int
	CalculateRisk(target string, targetType string, objectives []Objective) float64
	EstimateDuration(targetType string, objectives []Objective) time.Duration
	RequiredTools(targetType string, phase Phase) []string
}

type DefaultStrategy struct{}

func (s *DefaultStrategy) Name() string { return "default" }

func (s *DefaultStrategy) CalculatePriority(target string) int {
	target = strings.ToLower(target)
	if strings.Contains(target, "admin") || strings.Contains(target, "internal") {
		return 1
	}
	if strings.Contains(target, "api") || strings.Contains(target, "graphql") {
		return 2
	}
	return 3
}

func (s *DefaultStrategy) CalculateRisk(target string, targetType string, objectives []Objective) float64 {
	risk := 0.0
	for _, obj := range objectives {
		if obj.Phase >= PhaseExploit {
			risk += 0.2
		}
	}
	if risk > 1.0 {
		risk = 1.0
	}
	return risk
}

func (s *DefaultStrategy) EstimateDuration(targetType string, objectives []Objective) time.Duration {
	base := 30 * time.Minute
	for _, obj := range objectives {
		switch obj.Phase {
		case PhaseRecon:
			base += 10 * time.Minute
		case PhaseDiscovery:
			base += 15 * time.Minute
		case PhaseExploit:
			base += 25 * time.Minute
		case PhasePostExp:
			base += 20 * time.Minute
		case PhaseReport:
			base += 5 * time.Minute
		}
	}
	return base
}

func (s *DefaultStrategy) RequiredTools(targetType string, phase Phase) []string {
	switch phase {
	case PhaseRecon:
		return []string{"dns_recon", "subdomain_discovery", "tech_fingerprinting"}
	case PhaseDiscovery:
		return []string{"port_scanner", "web_crawler", "dir_bruteforce"}
	case PhaseExploit:
		base := []string{"sqli_agent", "xss_agent", "auth_bypass_agent"}
		switch targetType {
		case "api":
			base = append(base, "api_tester", "graphql_scanner")
		case "cloud":
			base = append(base, "cloud_enum", "iam_scanner")
		case "network":
			base = append(base, "network_scanner", "vpn_tester")
		case "container":
			base = append(base, "container_escape", "registry_scanner")
		default:
			base = append(base, "api_tester")
		}
		return base
	case PhasePostExp:
		return []string{"cred_extractor", "pivot_agent", "priv_esc_agent"}
	default:
		return []string{"report_agent"}
	}
}

type AggressiveStrategy struct{}

func (s *AggressiveStrategy) Name() string { return "aggressive" }

func (s *AggressiveStrategy) CalculatePriority(target string) int {
	target = strings.ToLower(target)
	if strings.Contains(target, "admin") || strings.Contains(target, "internal") || strings.Contains(target, "prod") {
		return 1
	}
	return 2
}

func (s *AggressiveStrategy) CalculateRisk(target string, targetType string, objectives []Objective) float64 {
	risk := 0.3
	hasExploit := false
	for _, obj := range objectives {
		if obj.Phase == PhaseExploit {
			hasExploit = true
			risk += 0.3
		}
	}
	if !hasExploit {
		risk += 0.2
	}
	target = strings.ToLower(target)
	for _, kw := range []string{"prod", "production", "critical", "core"} {
		if strings.Contains(target, kw) {
			risk += 0.2
			break
		}
	}
	if risk > 1.0 {
		risk = 1.0
	}
	return risk
}

func (s *AggressiveStrategy) EstimateDuration(targetType string, objectives []Objective) time.Duration {
	base := 15 * time.Minute
	for _, obj := range objectives {
		if obj.Phase >= PhaseExploit {
			base += 20 * time.Minute
		} else {
			base += 5 * time.Minute
		}
	}
	return base
}

func (s *AggressiveStrategy) RequiredTools(targetType string, phase Phase) []string {
	if phase == PhaseRecon {
		return []string{"quick_recon"}
	}
	return (&DefaultStrategy{}).RequiredTools(targetType, phase)
}

type ConservativeStrategy struct{}

func (s *ConservativeStrategy) Name() string { return "conservative" }

func (s *ConservativeStrategy) CalculatePriority(target string) int {
	return (&DefaultStrategy{}).CalculatePriority(target)
}

func (s *ConservativeStrategy) CalculateRisk(target string, targetType string, objectives []Objective) float64 {
	risk := 0.0
	for _, obj := range objectives {
		if obj.Phase == PhaseExploit {
			risk += 0.1
		}
	}
	return math.Min(risk, 0.5)
}

func (s *ConservativeStrategy) EstimateDuration(targetType string, objectives []Objective) time.Duration {
	base := 60 * time.Minute
	for range objectives {
		base += 20 * time.Minute
	}
	return base
}

func (s *ConservativeStrategy) RequiredTools(targetType string, phase Phase) []string {
	tools := (&DefaultStrategy{}).RequiredTools(targetType, phase)
	if phase == PhaseExploit {
		tools = append(tools, "safe_mode_check", "rollback_agent")
	}
	return tools
}

type CoverageStrategy struct{}

func (s *CoverageStrategy) Name() string { return "coverage" }

func (s *CoverageStrategy) CalculatePriority(target string) int {
	return 2
}

func (s *CoverageStrategy) CalculateRisk(target string, targetType string, objectives []Objective) float64 {
	risk := 0.4
	for _, obj := range objectives {
		if obj.Phase == PhaseExploit {
			risk += 0.15
		}
	}
	return math.Min(risk, 1.0)
}

func (s *CoverageStrategy) EstimateDuration(targetType string, objectives []Objective) time.Duration {
	base := 90 * time.Minute
	for range objectives {
		base += 15 * time.Minute
	}
	return base
}

func (s *CoverageStrategy) RequiredTools(targetType string, phase Phase) []string {
	return append((&DefaultStrategy{}).RequiredTools(targetType, phase), "coverage_scanner", "compliance_check")
}

type Objective struct {
	ID            string    `json:"id"`
	Target        string    `json:"target"`
	Goal          string    `json:"goal"`
	Phase         Phase     `json:"phase"`
	SubObjectives []string  `json:"sub_objectives"`
	Dependencies  []string  `json:"dependencies"`
	Score         float64   `json:"score"`
	Completed     bool      `json:"completed"`
	CreatedAt     time.Time `json:"created_at"`
}

type KillChain struct {
	Objectives []Objective        `json:"objectives"`
	Graph      *graph.AttackGraph `json:"-"`
	Score      float64            `json:"score"`
	Summary    string             `json:"summary"`
}

type Plan struct {
	ID                string        `json:"id"`
	Target            string        `json:"target"`
	Chain             KillChain     `json:"chain"`
	Priority          int           `json:"priority"`
	EstimatedImpact   float64       `json:"estimated_impact"`
	RiskScore         float64       `json:"risk_score"`
	EstimatedDuration time.Duration `json:"estimated_duration"`
	RequiredTools     []string      `json:"required_tools"`
}

type bayesianModel struct {
	Alpha float64
	Beta  float64
}

func (m *bayesianModel) Prior() float64 {
	return m.Alpha / (m.Alpha + m.Beta)
}

func (m *bayesianModel) Posterior(successes, failures float64) float64 {
	a := m.Alpha + successes
	b := m.Beta + failures
	return a / (a + b)
}

type Planner struct {
	mu               sync.RWMutex
	llm              *llm.Client
	policy           *policy.PolicyEngine
	graph            *graph.AttackGraph
	objectives       []Objective
	plans            []Plan
	history          []Plan
	startTime        time.Time
	ctx              context.Context
	allowRawTargets  bool
	strategy         IPlanningStrategy
	bayesianPriors   map[string]*bayesianModel
	objectiveWeights map[string]float64
}

func New(llmClient *llm.Client, pe *policy.PolicyEngine, g *graph.AttackGraph) *Planner {
	return &Planner{
		llm:              llmClient,
		policy:           pe,
		graph:            g,
		strategy:         &DefaultStrategy{},
		objectives:       make([]Objective, 0),
		plans:            make([]Plan, 0),
		history:          make([]Plan, 0),
		startTime:        time.Now(),
		bayesianPriors:   defaultBayesianPriors(),
		objectiveWeights: defaultObjectiveWeights(),
	}
}

func NewWithStrategy(llmClient *llm.Client, pe *policy.PolicyEngine, g *graph.AttackGraph, strategy IPlanningStrategy) *Planner {
	p := New(llmClient, pe, g)
	p.strategy = strategy
	return p
}

func defaultBayesianPriors() map[string]*bayesianModel {
	return map[string]*bayesianModel{
		"web":       {Alpha: 2, Beta: 2},
		"api":       {Alpha: 3, Beta: 2},
		"cloud":     {Alpha: 2, Beta: 3},
		"network":   {Alpha: 2, Beta: 2},
		"container": {Alpha: 2, Beta: 3},
		"mobile":    {Alpha: 2, Beta: 2},
		"other":     {Alpha: 1, Beta: 1},
	}
}

func defaultObjectiveWeights() map[string]float64 {
	return map[string]float64{
		"recon":     1.0,
		"discovery": 1.0,
		"exploit":   1.0,
		"postexp":   1.0,
		"report":    1.0,
	}
}

func (p *Planner) Strategy() IPlanningStrategy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.strategy
}

func StrategyByName(name string) IPlanningStrategy {
	switch strings.ToLower(name) {
	case "aggressive":
		return &AggressiveStrategy{}
	case "conservative":
		return &ConservativeStrategy{}
	case "coverage":
		return &CoverageStrategy{}
	default:
		return &DefaultStrategy{}
	}
}

func (p *Planner) SetStrategy(s IPlanningStrategy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.strategy = s
}

func (p *Planner) WithContext(ctx context.Context) *Planner {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ctx = ctx
	return p
}

func (p *Planner) ClassifyTarget(target string) string {
	return p.classifyTarget(target)
}

func (p *Planner) classifyTarget(target string) string {
	if p.llm == nil {
		return p.ruleBasedClassify(target)
	}
	parentCtx := p.ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, llmPlanningTimeout)
	defer cancel()

	targetForLLM := target
	if !p.allowRawTargets {
		h := sha256.Sum256([]byte(target))
		targetForLLM = "target-" + hex.EncodeToString(h[:8])
	}
	targetForLLM = security.SanitizeInput(targetForLLM)
	if len(targetForLLM) > 200 {
		targetForLLM = targetForLLM[:200]
	}

	prompt := fmt.Sprintf(`Classify this target into exactly one category: "web", "api", "cloud", "network", "container", "mobile", or "other".
Respond with ONLY the category word, nothing else.

Target: %s`, targetForLLM)

	msg := []llm.Message{{Role: "user", Content: prompt}}
	resp, err := p.llm.Complete(ctx, msg, "")
	if err != nil || resp == "" {
		return p.ruleBasedClassify(target)
	}
	resp = strings.TrimSpace(strings.ToLower(resp))
	switch resp {
	case "web", "api", "cloud", "network", "container", "mobile", "other":
		return resp
	default:
		return p.ruleBasedClassify(target)
	}
}

func (p *Planner) ruleBasedClassify(target string) string {
	target = strings.ToLower(target)
	if strings.Contains(target, "api") || strings.Contains(target, "graphql") {
		return "api"
	}
	if strings.Contains(target, "amazonaws") || strings.Contains(target, "azure") || strings.Contains(target, "gcp") || strings.Contains(target, ".cloud") {
		return "cloud"
	}
	if strings.Contains(target, "docker") || strings.Contains(target, "kubernetes") || strings.Contains(target, "k8s") || strings.Contains(target, "container") {
		return "container"
	}
	if strings.Contains(target, ".com") || strings.Contains(target, ".org") || strings.Contains(target, ".net") || strings.Contains(target, ".io") {
		return "web"
	}
	return "web"
}

func (p *Planner) vulnObjectivesFor(tech string) []string {
	base := []string{
		"SQL injection testing",
		"XSS vulnerability detection",
		"CSRF testing",
		"Authentication bypass testing",
		"Authorization flaws testing",
	}
	switch tech {
	case "api":
		base = append(base,
			"GraphQL introspection",
			"Mass assignment testing",
			"Rate limit bypass",
			"Object-level authorization testing",
		)
	case "cloud":
		base = append(base,
			"S3 bucket enumeration",
			"IAM policy review",
			"Metadata service testing",
			"Cloud storage misconfiguration",
		)
	case "network":
		base = append(base,
			"Service fingerprinting",
			"VPN/SSL VPN testing",
			"Network segmentation testing",
		)
	case "container":
		base = append(base,
			"Container escape testing",
			"Registry misconfiguration",
			"Image vulnerability scanning",
			"Orchestrator API exposure",
		)
	case "mobile":
		base = append(base,
			"API endpoint discovery",
			"Insecure data storage testing",
			"Certificate pinning validation",
		)
	}
	return base
}

func (p *Planner) DecomposeTarget(target string) []Objective {
	p.mu.Lock()
	defer p.mu.Unlock()

	targetTech := p.classifyTarget(target)
	objectives := p.buildObjectives(target, targetTech)

	for _, obj := range objectives {
		p.graph.AddNode(obj.ID, graph.NodeTechnique, obj.Goal)
	}
	for i := 1; i < len(objectives); i++ {
		for _, dep := range objectives[i].Dependencies {
			p.graph.AddEdge(dep, objectives[i].ID, graph.EdgeLeadsTo)
		}
	}

	p.objectives = append(p.objectives, objectives...)
	return objectives
}

func (p *Planner) buildObjectives(target string, targetTech string) []Objective {
	objectives := []Objective{
		{
			ID:            fmt.Sprintf("obj-%s-recon", target),
			Target:        target,
			Goal:          "Perform passive reconnaissance on target",
			Phase:         PhaseRecon,
			SubObjectives: p.reconSubObjectives(targetTech),
			Score:         0.9,
			CreatedAt:     time.Now(),
		},
		{
			ID:            fmt.Sprintf("obj-%s-discovery", target),
			Target:        target,
			Goal:          "Discover attack surface and running services",
			Phase:         PhaseDiscovery,
			Dependencies:  []string{fmt.Sprintf("obj-%s-recon", target)},
			SubObjectives: p.discoverySubObjectives(targetTech),
			Score:         0.85,
			CreatedAt:     time.Now(),
		},
		{
			ID:            fmt.Sprintf("obj-%s-vuln", target),
			Target:        target,
			Goal:          fmt.Sprintf("Identify and exploit vulnerabilities in detected %s stack", targetTech),
			Phase:         PhaseExploit,
			Dependencies:  []string{fmt.Sprintf("obj-%s-discovery", target)},
			SubObjectives: p.vulnObjectivesFor(targetTech),
			Score:         0.75,
			CreatedAt:     time.Now(),
		},
		{
			ID:           fmt.Sprintf("obj-%s-pivot", target),
			Target:       target,
			Goal:         "Establish persistence and pivot laterally",
			Phase:        PhasePostExp,
			Dependencies: []string{fmt.Sprintf("obj-%s-vuln", target)},
			SubObjectives: []string{
				"Credential extraction",
				"Session hijacking",
				"Internal network scanning",
				"Privilege escalation",
			},
			Score:     0.6,
			CreatedAt: time.Now(),
		},
		{
			ID:           fmt.Sprintf("obj-%s-impact", target),
			Target:       target,
			Goal:         "Demonstrate business impact and validate findings",
			Phase:        PhasePostExp,
			Dependencies: []string{fmt.Sprintf("obj-%s-pivot", target)},
			SubObjectives: []string{
				"Data exfiltration proof",
				"Sensitive data access",
				"Persistence demonstration",
				"Impact assessment",
			},
			Score:     0.5,
			CreatedAt: time.Now(),
		},
	}

	extras := p.extraObjectivesFor(target, targetTech)
	objectives = append(objectives, extras...)
	return objectives
}

func (p *Planner) reconSubObjectives(tech string) []string {
	base := []string{
		"DNS enumeration",
		"Subdomain discovery",
		"Technology fingerprinting",
		"Certificate transparency lookup",
	}
	switch tech {
	case "cloud":
		base = append(base, "Cloud provider API enumeration", "Managed service discovery")
	case "container":
		base = append(base, "Container registry discovery", "Orchestrator endpoint discovery")
	case "network":
		base = append(base, "Network range discovery", "VPN endpoint discovery")
	case "api":
		base = append(base, "API documentation discovery", "API version fingerprinting")
	}
	return base
}

func (p *Planner) discoverySubObjectives(tech string) []string {
	base := []string{
		"Open port scanning",
		"Web server detection",
		"API endpoint discovery",
		"Directory enumeration",
	}
	switch tech {
	case "cloud":
		base = append(base, "Cloud service enumeration", "Storage bucket discovery")
	case "container":
		base = append(base, "Container runtime discovery", "Orchestrator API probing")
	case "network":
		base = append(base, "Network topology mapping", "Firewall rule detection")
	case "api":
		base = append(base, "GraphQL introspection", "OpenAPI spec discovery")
	}
	return base
}

func (p *Planner) extraObjectivesFor(target string, tech string) []Objective {
	switch tech {
	case "web":
		return []Objective{
			{
				ID:           fmt.Sprintf("obj-%s-webscan", target),
				Target:       target,
				Goal:         "Perform deep web application scanning",
				Phase:        PhaseDiscovery,
				Dependencies: []string{fmt.Sprintf("obj-%s-discovery", target)},
				SubObjectives: []string{
					"Client-side security review",
					"JavaScript analysis",
					"CORS misconfiguration testing",
					"WebSocket security review",
				},
				Score:     0.8,
				CreatedAt: time.Now(),
			},
		}
	case "api":
		return []Objective{
			{
				ID:           fmt.Sprintf("obj-%s-apifuzz", target),
				Target:       target,
				Goal:         "Fuzz API endpoints for hidden vulnerabilities",
				Phase:        PhaseExploit,
				Dependencies: []string{fmt.Sprintf("obj-%s-vuln", target)},
				SubObjectives: []string{
					"Input fuzzing",
					"Schema validation bypass",
					"Rate limiting analysis",
					"BOLA/IDOR testing",
				},
				Score:     0.7,
				CreatedAt: time.Now(),
			},
		}
	case "network":
		return []Objective{
			{
				ID:           fmt.Sprintf("obj-%s-networkscan", target),
				Target:       target,
				Goal:         "Perform deep network penetration testing",
				Phase:        PhaseDiscovery,
				Dependencies: []string{fmt.Sprintf("obj-%s-discovery", target)},
				SubObjectives: []string{
					"Vulnerability scanning",
					"SNMP enumeration",
					"Wireless security assessment",
					"VoIP security testing",
				},
				Score:     0.8,
				CreatedAt: time.Now(),
			},
		}
	case "cloud":
		return []Objective{
			{
				ID:           fmt.Sprintf("obj-%s-cloudenum", target),
				Target:       target,
				Goal:         "Enumerate cloud resources and permissions",
				Phase:        PhaseDiscovery,
				Dependencies: []string{fmt.Sprintf("obj-%s-discovery", target)},
				SubObjectives: []string{
					"Resource group enumeration",
					"IAM role analysis",
					"Provider API enumeration",
					"Cloud storage discovery",
				},
				Score:     0.8,
				CreatedAt: time.Now(),
			},
		}
	case "container":
		return []Objective{
			{
				ID:           fmt.Sprintf("obj-%s-containersec", target),
				Target:       target,
				Goal:         "Assess container and orchestrator security",
				Phase:        PhaseDiscovery,
				Dependencies: []string{fmt.Sprintf("obj-%s-discovery", target)},
				SubObjectives: []string{
					"Container escape testing",
					"Image vulnerability scanning",
					"Orchestrator security review",
					"Registry misconfiguration check",
				},
				Score:     0.8,
				CreatedAt: time.Now(),
			},
		}
	default:
		return nil
	}
}

func (p *Planner) GeneratePlan(target string, objectives []Objective) Plan {
	if objectives == nil {
		objectives = p.DecomposeTarget(target)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(objectives) == 0 {
		return Plan{}
	}

	targetTech := p.classifyTarget(target)

	chain := KillChain{
		Objectives: objectives,
		Graph:      p.graph,
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Attack chain for %s:\n", target))
	for i, obj := range objectives {
		sb.WriteString(fmt.Sprintf("  Phase %d: %s (score: %.2f)\n", i, obj.Goal, obj.Score))
		for _, sub := range obj.SubObjectives {
			sb.WriteString(fmt.Sprintf("    - %s\n", sub))
		}
	}
	chain.Summary = sb.String()

	estImpact := 0.0
	for _, obj := range objectives {
		estImpact += obj.Score
	}
	estImpact /= float64(len(objectives))

	bayesProb := p.bayesianProbabilityFor(objectives, targetTech)
	estImpact *= bayesProb

	toolsSet := make(map[string]struct{})
	for phase := PhaseRecon; phase <= PhaseReport; phase++ {
		for _, tool := range p.strategy.RequiredTools(targetTech, phase) {
			toolsSet[tool] = struct{}{}
		}
	}
	requiredTools := make([]string, 0, len(toolsSet))
	for tool := range toolsSet {
		requiredTools = append(requiredTools, tool)
	}

	plan := Plan{
		ID:                uuid.New(),
		Target:            target,
		Chain:             chain,
		Priority:          p.strategy.CalculatePriority(target),
		EstimatedImpact:   estImpact,
		RiskScore:         p.strategy.CalculateRisk(target, targetTech, objectives),
		EstimatedDuration: p.strategy.EstimateDuration(targetTech, objectives),
		RequiredTools:     requiredTools,
	}

	p.plans = append(p.plans, plan)
	p.history = append(p.history, plan)

	return plan
}

func (p *Planner) bayesianProbabilityFor(objectives []Objective, targetType string) float64 {
	model, ok := p.bayesianPriors[targetType]
	if !ok {
		model = p.bayesianPriors["other"]
	}

	prior := model.Prior()

	weightedSum := 0.0
	totalWeight := 0.0
	for _, obj := range objectives {
		weight := p.objectiveWeights[phaseKey(obj.Phase)]
		weightedSum += obj.Score * weight
		totalWeight += weight
	}
	avgEvidence := weightedSum / totalWeight

	pEvGivenSuccess := 0.5 + (avgEvidence-0.5)*0.5
	pEvGivenFailure := 1.0 - pEvGivenSuccess

	pEvidence := pEvGivenSuccess*prior + pEvGivenFailure*(1.0-prior)
	if pEvidence == 0 {
		return prior
	}

	return (pEvGivenSuccess * prior) / pEvidence
}

func phaseKey(p Phase) string {
	switch p {
	case PhaseRecon:
		return "recon"
	case PhaseDiscovery:
		return "discovery"
	case PhaseExploit:
		return "exploit"
	case PhasePostExp:
		return "postexp"
	case PhaseReport:
		return "report"
	default:
		return "other"
	}
}

func (p *Planner) calculatePriority(target string) int {
	return p.strategy.CalculatePriority(target)
}

func (p *Planner) calculateRisk(target string, objectives []Objective) float64 {
	return p.strategy.CalculateRisk(target, p.classifyTarget(target), objectives)
}

func (p *Planner) MarkCompleted(objectiveID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.objectives {
		if p.objectives[i].ID == objectiveID {
			p.objectives[i].Completed = true
			score := p.objectives[i].Score
			p.graph.UpdateNodeScore(objectiveID, score*0.9)
			return
		}
	}
}

func (p *Planner) NextPhase() (Phase, []Objective) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	phaseOrder := []Phase{PhaseRecon, PhaseDiscovery, PhaseExploit, PhasePostExp, PhaseReport}
	for _, phase := range phaseOrder {
		var pending []Objective
		allCompleted := true
		for _, obj := range p.objectives {
			if obj.Phase == phase {
				if !obj.Completed {
					allCompleted = false
					pending = append(pending, obj)
				}
			}
		}
		if !allCompleted {
			return phase, pending
		}
	}
	return PhaseReport, nil
}

func (p *Planner) GetObjective(id string) (Objective, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for i := range p.objectives {
		if p.objectives[i].ID == id {
			return p.objectives[i], true
		}
	}
	return Objective{}, false
}

func (p *Planner) AllPlans() []Plan {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]Plan, len(p.plans))
	copy(result, p.plans)
	return result
}

func (p *Planner) ActivePlan(target string) (Plan, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for i := range p.plans {
		if p.plans[i].Target == target {
			return p.plans[i], true
		}
	}
	return Plan{}, false
}

func (p *Planner) GetActiveObjectives(target string) []Objective {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var active []Objective
	for _, obj := range p.objectives {
		if !obj.Completed && strings.Contains(obj.Target, target) {
			active = append(active, obj)
		}
	}
	return active
}

func (p *Planner) SuggestNextActions(target string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	phase, pending := p.NextPhase()
	if len(pending) == 0 {
		return nil
	}

	var suggestions []string
	for _, obj := range pending {
		depsMet := true
		for _, dep := range obj.Dependencies {
			depMet := false
			for _, o := range p.objectives {
				if o.ID == dep && o.Completed {
					depMet = true
					break
				}
			}
			if !depMet {
				depsMet = false
				break
			}
		}
		if depsMet {
			suggestions = append(suggestions,
				fmt.Sprintf("[Phase %d] %s: %s", phase, obj.Goal, strings.Join(obj.SubObjectives, ", ")))
		}
	}
	return suggestions
}

func (p *Planner) AgentsForPhase(phase Phase) []string {
	switch phase {
	case PhaseRecon:
		return []string{"dns_recon", "subdomain_discovery", "tech_fingerprinting"}
	case PhaseDiscovery:
		return []string{"port_scanner", "web_crawler", "dir_bruteforce"}
	case PhaseExploit:
		return []string{"sqli_agent", "xss_agent", "auth_bypass_agent", "api_tester"}
	case PhasePostExp:
		return []string{"cred_extractor", "pivot_agent", "priv_esc_agent"}
	default:
		return []string{"report_agent"}
	}
}

func (p *Planner) Status() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	completed := 0
	total := len(p.objectives)
	for _, obj := range p.objectives {
		if obj.Completed {
			completed++
		}
	}
	return map[string]interface{}{
		"total_objectives": total,
		"completed":        completed,
		"progress":         float64(completed) / float64(max(total, 1)),
		"active_plans":     len(p.plans),
		"total_plans":      len(p.history),
	}
}

func (p *Planner) SetAllowRawTargets(allow bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowRawTargets = allow
}

func (p *Planner) BayesianPriority(plan Plan) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	targetType := p.classifyTarget(plan.Target)
	objectives := plan.Chain.Objectives
	return p.bayesianProbabilityFor(objectives, targetType)
}

func (p *Planner) LearnFromOutcome(objectiveID string, success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, obj := range p.objectives {
		if obj.ID == objectiveID {
			key := phaseKey(obj.Phase)
			current := p.objectiveWeights[key]
			if success {
				p.objectiveWeights[key] = current * 1.1
				if p.objectiveWeights[key] > 2.0 {
					p.objectiveWeights[key] = 2.0
				}
			} else {
				p.objectiveWeights[key] = current * 0.9
				if p.objectiveWeights[key] < 0.1 {
					p.objectiveWeights[key] = 0.1
				}
			}

			targetType := p.classifyTarget(obj.Target)
			model := p.bayesianPriors[targetType]
			if model == nil {
				model = p.bayesianPriors["other"]
			}
			if success {
				model.Alpha += 1.0
			} else {
				model.Beta += 1.0
			}
			return
		}
	}
}

func (p *Planner) GeneratePlansConcurrently(targets []string, maxParallel int) []Plan {
	if maxParallel <= 0 {
		maxParallel = 1
	}
	results := make([]Plan, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallel)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = p.GeneratePlan(tgt, nil)
		}(i, target)
	}

	wg.Wait()
	return results
}

func ComparePlans(a, b Plan) string {
	var sb strings.Builder
	sb.WriteString("Plan Comparison:\n")
	count := 0

	if a.Target != b.Target {
		sb.WriteString(fmt.Sprintf("  Target: %q vs %q\n", a.Target, b.Target))
		count++
	}
	if a.Priority != b.Priority {
		sb.WriteString(fmt.Sprintf("  Priority: %d vs %d\n", a.Priority, b.Priority))
		count++
	}
	riskDiff := a.RiskScore - b.RiskScore
	if riskDiff > 0.01 || riskDiff < -0.01 {
		sb.WriteString(fmt.Sprintf("  Risk Score: %.2f vs %.2f (delta: %+.2f)\n", a.RiskScore, b.RiskScore, riskDiff))
		count++
	}
	impactDiff := a.EstimatedImpact - b.EstimatedImpact
	if impactDiff > 0.01 || impactDiff < -0.01 {
		sb.WriteString(fmt.Sprintf("  Estimated Impact: %.2f vs %.2f (delta: %+.2f)\n", a.EstimatedImpact, b.EstimatedImpact, impactDiff))
		count++
	}
	if a.EstimatedDuration != b.EstimatedDuration {
		sb.WriteString(fmt.Sprintf("  Estimated Duration: %s vs %s\n", a.EstimatedDuration, b.EstimatedDuration))
		count++
	}
	objDiff := len(a.Chain.Objectives) - len(b.Chain.Objectives)
	if objDiff != 0 {
		sb.WriteString(fmt.Sprintf("  Objective Count: %d vs %d (delta: %+d)\n", len(a.Chain.Objectives), len(b.Chain.Objectives), objDiff))
		count++
	}

	aTools := make(map[string]struct{})
	for _, t := range a.RequiredTools {
		aTools[t] = struct{}{}
	}
	var missingFromB, missingFromA []string
	for _, t := range b.RequiredTools {
		if _, ok := aTools[t]; !ok {
			missingFromA = append(missingFromA, t)
		}
	}
	bTools := make(map[string]struct{})
	for _, t := range b.RequiredTools {
		bTools[t] = struct{}{}
	}
	for _, t := range a.RequiredTools {
		if _, ok := bTools[t]; !ok {
			missingFromB = append(missingFromB, t)
		}
	}
	if len(missingFromB) > 0 || len(missingFromA) > 0 {
		if len(missingFromB) > 0 {
			sb.WriteString(fmt.Sprintf("  Tools only in A: %v\n", missingFromB))
			count++
		}
		if len(missingFromA) > 0 {
			sb.WriteString(fmt.Sprintf("  Tools only in B: %v\n", missingFromA))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  No material differences found.\n")
	}
	return sb.String()
}
