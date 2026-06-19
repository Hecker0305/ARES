package scoring

import (
	"fmt"
	"math"
	"strings"
	"sync"
)

type AttackNode struct {
	ID        string
	Type      string
	Payload   string
	Target    string
	VulnType  string
	PDetect   float64
	Impact    float64
	Cost      float64
	PInit     float64
	CVSSScore float64
}

type AttackGraph struct {
	nodes map[string]*AttackNode
	edges map[string][]string
	mu    sync.RWMutex
}

func NewAttackGraph() *AttackGraph {
	return &AttackGraph{
		nodes: make(map[string]*AttackNode),
		edges: make(map[string][]string),
	}
}

func (g *AttackGraph) AddNode(node *AttackNode) error {
	if err := ValidateCVSS(node.CVSSScore); err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[node.ID] = node
	return nil
}

func (g *AttackGraph) AddEdge(from, to string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[from] = append(g.edges[from], to)
}

func (g *AttackGraph) Expand(targetID string, depth int) []*AttackNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*AttackNode
	g.expandRecursive(targetID, depth, map[string]bool{}, &result)
	return result
}

func (g *AttackGraph) expandRecursive(nodeID string, depth int, visited map[string]bool, result *[]*AttackNode) {
	if depth == 0 || visited[nodeID] {
		return
	}
	visited[nodeID] = true

	if node, ok := g.nodes[nodeID]; ok {
		*result = append(*result, node)
	}

	for _, childID := range g.edges[nodeID] {
		g.expandRecursive(childID, depth-1, visited, result)
	}
}

type ScoringEngine struct {
	graph        *AttackGraph
	wafModifiers map[string]float64
	mu           sync.RWMutex
}

func NewScoringEngine(graph *AttackGraph) *ScoringEngine {
	return &ScoringEngine{
		graph:        graph,
		wafModifiers: make(map[string]float64),
	}
}

func ValidateCVSS(score float64) error {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return fmt.Errorf("CVSS score must be a finite number, got %v", score)
	}
	if score < 0.0 {
		return fmt.Errorf("CVSS score must be >= 0.0, got %.1f", score)
	}
	if score > 10.0 {
		return fmt.Errorf("CVSS score must be <= 10.0, got %.1f", score)
	}
	return nil
}

func ClampCVSS(score float64) (float64, error) {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0.0, fmt.Errorf("CVSS score must be a finite number, got %v", score)
	}
	if score < 0.0 {
		return 0.0, nil
	}
	if score > 10.0 {
		return 10.0, nil
	}
	return score, nil
}

func (e *ScoringEngine) CalculateEV(node *AttackNode, ctx map[string]interface{}) (float64, error) {
	cvss, err := ClampCVSS(node.CVSSScore)
	if err != nil {
		return 0.0, err
	}

	wafDetected := false
	if w, ok := ctx["waf_detected"].(bool); ok {
		wafDetected = w
	}

	pDetect := node.PDetect
	if wafDetected {
		if mod, ok := e.wafModifiers[node.VulnType]; ok {
			pDetect *= mod
		}
	}

	cost := node.Cost
	if wafDetected {
		cost *= 1.5
	}

	ev := (node.PInit * cvss) - (pDetect * cost)

	if node.PInit > 0.7 {
		ev += 0.2
	}
	if cvss > 0.8 {
		ev += 0.15
	}

	return ev, nil
}

func (e *ScoringEngine) RankNodes(nodes []*AttackNode, ctx map[string]interface{}) ([]*AttackNode, error) {
	type scored struct {
		node *AttackNode
		ev   float64
	}

	var scoredNodes []scored
	for _, node := range nodes {
		if err := ValidateCVSS(node.CVSSScore); err != nil {
			return nil, fmt.Errorf("invalid CVSS score for node %s: %w", node.ID, err)
		}
		ev, err := e.CalculateEV(node, ctx)
		if err != nil {
			return nil, err
		}
		scoredNodes = append(scoredNodes, scored{node, ev})
	}

	for i := 0; i < len(scoredNodes)-1; i++ {
		for j := i + 1; j < len(scoredNodes); j++ {
			if scoredNodes[j].ev > scoredNodes[i].ev {
				scoredNodes[i], scoredNodes[j] = scoredNodes[j], scoredNodes[i]
			}
		}
	}

	var result []*AttackNode
	for _, s := range scoredNodes {
		result = append(result, s.node)
	}

	return result, nil
}

func (e *ScoringEngine) UpdateWAFModifier(vulnType string, modifier float64) error {
	if modifier < 0.0 {
		return fmt.Errorf("WAF modifier must be >= 0.0, got %.2f", modifier)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wafModifiers[vulnType] = modifier
	return nil
}

func (e *ScoringEngine) SuggestNextAttack(targets []string, ctx map[string]interface{}) (string, error) {
	if len(targets) == 0 {
		return "", nil
	}

	var bestNode *AttackNode
	var bestEV float64 = -math.MaxFloat64

	for _, target := range targets {
		nodes := e.graph.Expand(target, 3)
		ranked, err := e.RankNodes(nodes, ctx)
		if err != nil {
			return "", err
		}
		if len(ranked) > 0 && ranked[0] != nil {
			ev, err := e.CalculateEV(ranked[0], ctx)
			if err != nil {
				return "", err
			}
			if ev > bestEV {
				bestEV = ev
				bestNode = ranked[0]
			}
		}
	}

	if bestNode != nil {
		return bestNode.ID, nil
	}
	return targets[0], nil
}

type AgentChain struct {
	agents  map[string]*ChainAgent
	graph   *AttackGraph
	scoring *ScoringEngine
	mu      sync.RWMutex
}

type ChainAgent struct {
	ID      string
	Role    string
	Targets []string
	State   string
	Output  map[string]interface{}
	mu      sync.Mutex
}

func NewAgentChain() *AgentChain {
	graph := NewAttackGraph()
	return &AgentChain{
		agents:  make(map[string]*ChainAgent),
		graph:   graph,
		scoring: NewScoringEngine(graph),
	}
}

func (c *AgentChain) AddAgent(id, role string, targets []string) error {
	agent := &ChainAgent{
		ID:      id,
		Role:    role,
		Targets: targets,
		State:   "idle",
		Output:  make(map[string]interface{}),
	}

	c.mu.Lock()
	c.agents[id] = agent
	c.mu.Unlock()

	for _, target := range targets {
		node := &AttackNode{
			ID:        target,
			Type:      "recon",
			PInit:     0.5,
			PDetect:   0.1,
			Impact:    0.5,
			Cost:      0.3,
			CVSSScore: 5.0,
		}
		if err := c.graph.AddNode(node); err != nil {
			return fmt.Errorf("failed to add node for target %s: %w", target, err)
		}
	}

	return nil
}

func (c *AgentChain) Connect(from, to string) {
	c.graph.AddEdge(from, to)
}

func (c *AgentChain) Execute() error {
	c.mu.RLock()
	agents := make([]*ChainAgent, 0, len(c.agents))
	for _, agent := range c.agents {
		agents = append(agents, agent)
	}
	c.mu.RUnlock()

	for _, agent := range agents {
		agent.mu.Lock()
		if agent.State == "idle" {
			agent.State = "running"
			agent.Output["status"] = "completed"
			agent.Output["targets_scanned"] = len(agent.Targets)
			agent.Output["role"] = agent.Role
			agent.State = "completed"
		}
		agent.mu.Unlock()
	}
	return nil
}

func (c *AgentChain) GetReport() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var lines []string
	lines = append(lines, "## Agent Chain Report")
	for id, agent := range c.agents {
		agent.mu.Lock()
		lines = append(lines, fmt.Sprintf("- Agent %s (%s): %s", id, agent.Role, agent.State))
		agent.mu.Unlock()
	}
	return fmt.Sprintf("%s\nTotal agents: %d\n", strings.Join(lines, "\n"), len(c.agents))
}
