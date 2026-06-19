package attackpath

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type DifficultyLevel string

const (
	DifficultyTrivial  DifficultyLevel = "trivial"
	DifficultyLow      DifficultyLevel = "low"
	DifficultyMedium   DifficultyLevel = "medium"
	DifficultyHard     DifficultyLevel = "hard"
	DifficultyVeryHard DifficultyLevel = "very_hard"
)

type PathStep struct {
	Node       *graph.Node     `json:"node"`
	Edge       *graph.Edge     `json:"edge,omitempty"`
	CVEIDs     []string        `json:"cve_ids,omitempty"`
	Technique  string          `json:"technique,omitempty"`
	Difficulty DifficultyLevel `json:"difficulty"`
}

type AttackPath struct {
	ID             string                 `json:"id"`
	Steps          []PathStep             `json:"steps"`
	Likelihood     float64                `json:"likelihood"`
	BusinessImpact float64                `json:"business_impact"`
	RiskScore      float64                `json:"risk_score"`
	BlastRadius    int                    `json:"blast_radius"`
	TotalSteps     int                    `json:"total_steps"`
	Summary        string                 `json:"summary"`
	StartAsset     string                 `json:"start_asset"`
	TargetAsset    string                 `json:"target_asset"`
	CreatedAt      time.Time              `json:"created_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type CrownJewel struct {
	Node  *graph.Node `json:"node"`
	Label string      `json:"label"`
	Score float64     `json:"score"`
}

type BlastRadiusResult struct {
	SourceNodeID string                   `json:"source_node_id"`
	Reachable    map[string]ReachableNode `json:"reachable"`
	MaxDepth     int                      `json:"max_depth"`
	TotalImpact  float64                  `json:"total_impact"`
}

type ReachableNode struct {
	Node   *graph.Node `json:"node"`
	Depth  int         `json:"depth"`
	Path   []string    `json:"path"`
	Impact float64     `json:"impact"`
}

type SimulationConfig struct {
	MaxPathDepth         int     `json:"max_path_depth"`
	LikelihoodWeight     float64 `json:"likelihood_weight"`
	ImpactWeight         float64 `json:"impact_weight"`
	BlastRadiusWeight    float64 `json:"blast_radius_weight"`
	MinCrownJewelScore   float64 `json:"min_crown_jewel_score"`
	CriticalityThreshold float64 `json:"criticality_threshold"`
}

var DefaultSimulationConfig = SimulationConfig{
	MaxPathDepth:         15,
	LikelihoodWeight:     0.4,
	ImpactWeight:         0.4,
	BlastRadiusWeight:    0.2,
	MinCrownJewelScore:   0.7,
	CriticalityThreshold: 0.6,
}

type PathSimulator struct {
	mu     sync.RWMutex
	graph  *graph.AttackGraph
	config SimulationConfig
}

func NewPathSimulator(g *graph.AttackGraph) *PathSimulator {
	return &PathSimulator{
		graph:  g,
		config: DefaultSimulationConfig,
	}
}

func (ps *PathSimulator) SetConfig(cfg SimulationConfig) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.config = cfg
}

func (ps *PathSimulator) Config() SimulationConfig {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.config
}

func (ps *PathSimulator) FindAllPaths(startID, endID string) []AttackPath {
	ps.mu.RLock()
	cfg := ps.config
	ps.mu.RUnlock()

	logger.Debug("[AttackPath] Finding all paths", logger.Fields{
		"start": startID,
		"end":   endID,
	})

	chains := ps.graph.FindChains(startID, endID, cfg.MaxPathDepth)
	if len(chains) == 0 {
		logger.Warn("[AttackPath] No paths found", logger.Fields{
			"start": startID,
			"end":   endID,
		})
		return nil
	}

	logger.Info("[AttackPath] Paths found", logger.Fields{
		"count": len(chains),
		"start": startID,
		"end":   endID,
	})

	paths := make([]AttackPath, 0, len(chains))
	for _, chain := range chains {
		path := ps.buildAttackPath(chain, startID, endID)
		paths = append(paths, path)
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].RiskScore > paths[j].RiskScore
	})

	return paths
}

func (ps *PathSimulator) FindCriticalPaths() []AttackPath {
	crownJewels := ps.identifyCrownJewels()
	if len(crownJewels) == 0 {
		logger.Warn("[AttackPath] No crown jewels found for critical path analysis")
		return nil
	}

	logger.Info("[AttackPath] Critical path analysis", logger.Fields{
		"crown_jewels": len(crownJewels),
	})

	allNodes := ps.graph.AllNodes()
	var entryPoints []*graph.Node
	for _, n := range allNodes {
		if n.Type == graph.NodeAsset || n.Type == graph.NodeEndpoint {
			entryPoints = append(entryPoints, n)
		}
	}

	var criticalPaths []AttackPath
	seen := make(map[string]bool)

	for _, entry := range entryPoints {
		for _, jewel := range crownJewels {
			if entry.ID == jewel.Node.ID {
				continue
			}
			paths := ps.FindAllPaths(entry.ID, jewel.Node.ID)
			for _, p := range paths {
				key := fmt.Sprintf("%s->%s", p.StartAsset, p.TargetAsset)
				if !seen[key] {
					criticalPaths = append(criticalPaths, p)
					seen[key] = true
				}
			}
		}
	}

	sort.Slice(criticalPaths, func(i, j int) bool {
		return criticalPaths[i].RiskScore > criticalPaths[j].RiskScore
	})

	if len(criticalPaths) > 20 {
		criticalPaths = criticalPaths[:20]
	}

	return criticalPaths
}

func (ps *PathSimulator) ShortestPathToCrownJewels() []AttackPath {
	ps.mu.RLock()
	cfg := ps.config
	ps.mu.RUnlock()

	crownJewels := ps.identifyCrownJewels()
	if len(crownJewels) == 0 {
		return nil
	}

	allNodes := ps.graph.AllNodes()
	var entryPoints []*graph.Node
	for _, n := range allNodes {
		if n.Type == graph.NodeAsset || n.Type == graph.NodeEndpoint {
			entryPoints = append(entryPoints, n)
		}
	}

	var results []AttackPath

	if len(entryPoints) == 0 {
		logger.Warn("[AttackPath] No entry points found for shortest path analysis")
		return nil
	}

	logger.Debug("[AttackPath] Shortest path analysis", logger.Fields{
		"entry_points": len(entryPoints),
		"crown_jewels": len(crownJewels),
	})

	for _, entry := range entryPoints {
		for _, jewel := range crownJewels {
			if entry.ID == jewel.Node.ID {
				continue
			}
			chains := ps.graph.FindChains(entry.ID, jewel.Node.ID, cfg.MaxPathDepth)
			if len(chains) == 0 {
				continue
			}

			shortest := chains[0]
			for _, c := range chains[1:] {
				if len(c.Nodes) < len(shortest.Nodes) {
					shortest = c
				}
			}

			path := ps.buildAttackPath(shortest, entry.ID, jewel.Node.ID)
			results = append(results, path)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].TotalSteps != results[j].TotalSteps {
			return results[i].TotalSteps < results[j].TotalSteps
		}
		return results[i].RiskScore > results[j].RiskScore
	})

	if len(results) > 20 {
		results = results[:20]
	}

	return results
}

func (ps *PathSimulator) CalculateBlastRadius(nodeID string, maxDepth int) *BlastRadiusResult {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if maxDepth <= 0 {
		maxDepth = 3
	}

	result := &BlastRadiusResult{
		SourceNodeID: nodeID,
		Reachable:    make(map[string]ReachableNode),
		MaxDepth:     maxDepth,
	}

	visited := make(map[string]bool)
	var currentPath []string

	var dfs func(currentID string, depth int)
	dfs = func(currentID string, depth int) {
		if depth > maxDepth {
			return
		}
		if visited[currentID] {
			return
		}
		visited[currentID] = true
		currentPath = append(currentPath, currentID)

		node := ps.graph.GetNode(currentID)
		if node != nil && currentID != nodeID {
			pathCopy := make([]string, len(currentPath))
			copy(pathCopy, currentPath)

			impact := node.Score
			if depth > 0 {
				impact = impact / float64(depth)
			}

			if existing, ok := result.Reachable[currentID]; !ok || depth < existing.Depth {
				result.Reachable[currentID] = ReachableNode{
					Node:   node,
					Depth:  depth,
					Path:   pathCopy,
					Impact: impact,
				}
			}
			result.TotalImpact += impact
		}

		for _, edge := range ps.graph.GetOutgoing(currentID) {
			dfs(edge.TargetID, depth+1)
		}

		currentPath = currentPath[:len(currentPath)-1]
		visited[currentID] = false
	}

	dfs(nodeID, 0)

	return result
}

func (ps *PathSimulator) AssessPathLikelihood(path AttackPath) float64 {
	if len(path.Steps) == 0 {
		return 0
	}

	totalDifficulty := 0.0
	for _, step := range path.Steps {
		switch step.Difficulty {
		case DifficultyTrivial:
			totalDifficulty += 0.9
		case DifficultyLow:
			totalDifficulty += 0.7
		case DifficultyMedium:
			totalDifficulty += 0.5
		case DifficultyHard:
			totalDifficulty += 0.3
		case DifficultyVeryHard:
			totalDifficulty += 0.1
		default:
			totalDifficulty += 0.5
		}

		if step.Node != nil && step.Node.Score > 0 {
			totalDifficulty += step.Node.Score * 0.3
		}
	}

	rawLikelihood := totalDifficulty / (float64(len(path.Steps)) * 1.3)
	if rawLikelihood > 1.0 {
		rawLikelihood = 1.0
	}

	penalty := float64(len(path.Steps)) * 0.05
	likelihood := rawLikelihood - penalty
	if likelihood < 0 {
		likelihood = 0.01
	}

	return math.Round(likelihood*100) / 100
}

func (ps *PathSimulator) AssessBusinessImpact(path AttackPath) float64 {
	if len(path.Steps) == 0 {
		return 0
	}

	maxImpact := 0.0
	for _, step := range path.Steps {
		impact := 0.5
		if step.Node != nil {
			if v, ok := step.Node.Properties["criticality"]; ok {
				if c, ok := v.(float64); ok {
					impact = c
				}
			}
			if v, ok := step.Node.Properties["business_impact"]; ok {
				if bi, ok := v.(float64); ok && bi > impact {
					impact = bi
				}
			}
			if step.Node.Score > impact {
				impact = step.Node.Score
			}
		}
		if impact > maxImpact {
			maxImpact = impact
		}
	}

	return math.Round(maxImpact*100) / 100
}

func (ps *PathSimulator) CalculateRiskScore(likelihood, impact, blastRadiusScore float64) float64 {
	ps.mu.RLock()
	cfg := ps.config
	ps.mu.RUnlock()

	score := likelihood*cfg.LikelihoodWeight +
		impact*cfg.ImpactWeight +
		blastRadiusScore*cfg.BlastRadiusWeight

	if score > 1.0 {
		score = 1.0
	}

	return math.Round(score*1000) / 1000
}

func (ps *PathSimulator) GenerateSummary(path AttackPath) string {
	if len(path.Steps) == 0 {
		return "empty path"
	}

	var parts []string
	for i, step := range path.Steps {
		if step.Node == nil {
			continue
		}
		nodeStr := fmt.Sprintf("[%s] %s", step.Node.Type, step.Node.Label)
		parts = append(parts, nodeStr)

		if i < len(path.Steps)-1 && step.Edge != nil {
			parts = append(parts, fmt.Sprintf("--%s-->", step.Edge.Type))
		}
	}

	parts = append(parts, fmt.Sprintf("(risk=%.3f, likelihood=%.2f, impact=%.2f)",
		path.RiskScore, path.Likelihood, path.BusinessImpact))

	return strings.Join(parts, " ")
}

func (ps *PathSimulator) buildAttackPath(chain graph.AttackChain, startID, endID string) AttackPath {
	steps := make([]PathStep, 0, len(chain.Nodes))

	for i, n := range chain.Nodes {
		step := PathStep{
			Node:       n,
			Difficulty: difficultyForNode(n),
		}

		if i < len(chain.Edges) {
			step.Edge = chain.Edges[i]
		}

		if n.Type == graph.NodeVuln {
			if cves, ok := n.Properties["cve_ids"].([]string); ok {
				step.CVEIDs = cves
			} else if cveStr, ok := n.Properties["cve_id"].(string); ok && cveStr != "" {
				step.CVEIDs = []string{cveStr}
			}
		}

		if t, ok := n.Properties["technique"].(string); ok {
			step.Technique = t
		}

		steps = append(steps, step)
	}

	path := AttackPath{
		ID:          uuid.New(),
		Steps:       steps,
		TotalSteps:  len(steps),
		StartAsset:  startID,
		TargetAsset: endID,
		CreatedAt:   time.Now(),
	}

	path.Likelihood = ps.AssessPathLikelihood(path)
	path.BusinessImpact = ps.AssessBusinessImpact(path)

	blastRadius := ps.CalculateBlastRadius(endID, 2)
	blastRadiusScore := 0.0
	if blastRadius != nil {
		path.BlastRadius = len(blastRadius.Reachable)
		blastRadiusScore = math.Min(float64(path.BlastRadius)/10.0, 1.0)
	}

	path.RiskScore = ps.CalculateRiskScore(path.Likelihood, path.BusinessImpact, blastRadiusScore)
	path.Summary = ps.GenerateSummary(path)

	return path
}

func (ps *PathSimulator) identifyCrownJewels() []CrownJewel {
	ps.mu.RLock()
	cfg := ps.config
	ps.mu.RUnlock()

	allNodes := ps.graph.AllNodes()

	var jewels []CrownJewel
	for _, n := range allNodes {
		score := n.Score

		if v, ok := n.Properties["criticality"]; ok {
			if c, ok := v.(float64); ok && c > score {
				score = c
			}
		}

		if n.Type == graph.NodeAsset || n.Type == graph.NodeSecret || n.Type == graph.NodeCredential {
			score = score * 1.2
			if score > 1.0 {
				score = 1.0
			}
		}

		if score >= cfg.MinCrownJewelScore {
			jewels = append(jewels, CrownJewel{
				Node:  n,
				Label: n.Label,
				Score: score,
			})
		}
	}

	sort.Slice(jewels, func(i, j int) bool {
		return jewels[i].Score > jewels[j].Score
	})

	return jewels
}

func difficultyForNode(n *graph.Node) DifficultyLevel {
	if n == nil {
		return DifficultyMedium
	}

	if v, ok := n.Properties["difficulty"]; ok {
		if d, ok := v.(string); ok {
			return DifficultyLevel(d)
		}
	}

	score := n.Score
	switch {
	case score >= 0.8:
		return DifficultyTrivial
	case score >= 0.6:
		return DifficultyLow
	case score >= 0.4:
		return DifficultyMedium
	case score >= 0.2:
		return DifficultyHard
	default:
		return DifficultyVeryHard
	}
}
