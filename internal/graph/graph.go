package graph

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type NodeType string

const (
	NodeAsset      NodeType = "asset"
	NodeVuln       NodeType = "vulnerability"
	NodeSecret     NodeType = "secret"
	NodeEndpoint   NodeType = "endpoint"
	NodeCredential NodeType = "credential"
	NodeService    NodeType = "service"
	NodeTechnique  NodeType = "technique"
)

type EdgeType string

const (
	EdgeExploits      EdgeType = "exploits"
	EdgeLeadsTo       EdgeType = "leads_to"
	EdgeRequires      EdgeType = "requires"
	EdgeBypasses      EdgeType = "bypasses"
	EdgeMitigates     EdgeType = "mitigates"
	EdgeDiscovers     EdgeType = "discovers"
	EdgeAuthenticates EdgeType = "authenticates_to"
)

const maxTraversalDepth = 50

type Node struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Label      string                 `json:"label"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Score      float64                `json:"score"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

type Edge struct {
	ID         string                 `json:"id"`
	SourceID   string                 `json:"source_id"`
	TargetID   string                 `json:"target_id"`
	Type       EdgeType               `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Weight     float64                `json:"weight"`
	CreatedAt  time.Time              `json:"created_at"`
}

type AttackGraph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges map[string][]*Edge
}

type AttackChain struct {
	Nodes   []*Node `json:"nodes"`
	Edges   []*Edge `json:"edges"`
	Score   float64 `json:"score"`
	Summary string  `json:"summary"`
}

type PathResult struct {
	Chain      AttackChain `json:"chain"`
	Feasible   bool        `json:"feasible"`
	Difficulty string      `json:"difficulty"`
}

func New() *AttackGraph {
	return &AttackGraph{
		nodes: make(map[string]*Node),
		edges: make(map[string][]*Edge),
	}
}

var validNodeTypes = map[NodeType]bool{
	NodeAsset:      true,
	NodeVuln:       true,
	NodeSecret:     true,
	NodeEndpoint:   true,
	NodeCredential: true,
	NodeService:    true,
	NodeTechnique:  true,
}

var validEdgeTypes = map[EdgeType]bool{
	EdgeExploits:      true,
	EdgeLeadsTo:       true,
	EdgeRequires:      true,
	EdgeBypasses:      true,
	EdgeMitigates:     true,
	EdgeDiscovers:     true,
	EdgeAuthenticates: true,
}

var edgeTypeCompatibility = map[EdgeType][]NodeType{
	EdgeExploits:      {NodeVuln},
	EdgeLeadsTo:       {NodeAsset, NodeVuln, NodeService, NodeEndpoint, NodeSecret, NodeCredential, NodeTechnique},
	EdgeRequires:      {NodeVuln, NodeTechnique},
	EdgeBypasses:      {NodeVuln, NodeEndpoint},
	EdgeMitigates:     {NodeVuln},
	EdgeDiscovers:     {NodeSecret, NodeCredential, NodeVuln, NodeEndpoint, NodeService},
	EdgeAuthenticates: {NodeCredential, NodeEndpoint},
}

func (g *AttackGraph) AddNode(id string, ntype NodeType, label string) *Node {
	if !validNodeTypes[ntype] {
		return nil
	}
	if id == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.nodes[id]; exists {
		return nil
	}
	now := time.Now()
	node := &Node{
		ID:         id,
		Type:       ntype,
		Label:      label,
		Properties: make(map[string]interface{}),
		Score:      0.5,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	g.nodes[id] = node
	return node
}

func (g *AttackGraph) AddNodeWithScore(id string, ntype NodeType, label string, score float64) *Node {
	if !validNodeTypes[ntype] {
		return nil
	}
	if id == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.nodes[id]; exists {
		return nil
	}
	now := time.Now()
	node := &Node{
		ID:         id,
		Type:       ntype,
		Label:      label,
		Properties: make(map[string]interface{}),
		Score:      score,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	g.nodes[id] = node
	return node
}

func (g *AttackGraph) GetNode(id string) *Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id]
}

func (g *AttackGraph) RemoveNode(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.nodes, id)
	delete(g.edges, id)
	for src, edges := range g.edges {
		var filtered []*Edge
		for _, e := range edges {
			if e.TargetID != id {
				filtered = append(filtered, e)
			}
		}
		g.edges[src] = filtered
	}
}

func (g *AttackGraph) AddEdge(sourceID, targetID string, etype EdgeType) *Edge {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.nodes[sourceID]; !ok {
		return nil
	}
	if _, ok := g.nodes[targetID]; !ok {
		return nil
	}
	if sourceID == targetID {
		return nil
	}
	if g.wouldCreateCycle(sourceID, targetID) {
		logger.Warn("cycle prevention: edge rejected", logger.Fields{
			"source": sourceID,
			"target": targetID,
		})
		return nil
	}
	edge := &Edge{
		ID:         uuid.New(),
		SourceID:   sourceID,
		TargetID:   targetID,
		Type:       etype,
		Properties: make(map[string]interface{}),
		Weight:     0.5,
		CreatedAt:  time.Now(),
	}
	g.edges[sourceID] = append(g.edges[sourceID], edge)
	return edge
}

func (g *AttackGraph) wouldCreateCycle(sourceID, targetID string) bool {
	if sourceID == targetID {
		return true
	}
	visited := make(map[string]bool)
	var hasPath func(current string) bool
	hasPath = func(current string) bool {
		if current == sourceID {
			return true
		}
		if visited[current] {
			return false
		}
		visited[current] = true
		for _, edge := range g.edges[current] {
			if hasPath(edge.TargetID) {
				return true
			}
		}
		return false
	}
	return hasPath(targetID)
}

func (g *AttackGraph) GetOutgoing(id string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := g.edges[id]
	result := make([]*Edge, len(edges))
	copy(result, edges)
	return result
}

func (g *AttackGraph) GetIncoming(id string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var result []*Edge
	for _, edges := range g.edges {
		for _, e := range edges {
			if e.TargetID == id {
				result = append(result, e)
			}
		}
	}
	return result
}

func (g *AttackGraph) FindChains(startID, endID string, maxDepth int) []AttackChain {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if maxDepth > maxTraversalDepth {
		maxDepth = maxTraversalDepth
	}

	var chains []AttackChain
	visited := make(map[string]bool)
	var path []*Node
	var pathEdges []*Edge

	var dfs func(currentID string, depth int)
	dfs = func(currentID string, depth int) {
		if depth > maxDepth {
			return
		}
		if visited[currentID] {
			return
		}
		node, ok := g.nodes[currentID]
		if !ok {
			return
		}
		visited[currentID] = true
		path = append(path, node)

		if currentID == endID {
			chain := AttackChain{
				Nodes:   make([]*Node, len(path)),
				Edges:   make([]*Edge, len(pathEdges)),
				Summary: g.buildChainSummary(path, pathEdges),
			}
			copy(chain.Nodes, path)
			copy(chain.Edges, pathEdges)
			for _, n := range path {
				chain.Score += n.Score
			}
			if len(path) > 0 {
				chain.Score /= float64(len(path))
			}
			if chain.Score > 1.0 {
				chain.Score = 1.0
			}
			chains = append(chains, chain)
		} else {
			for _, edge := range g.edges[currentID] {
				pathEdges = append(pathEdges, edge)
				dfs(edge.TargetID, depth+1)
				pathEdges = pathEdges[:len(pathEdges)-1]
			}
		}

		path = path[:len(path)-1]
		visited[currentID] = false
	}

	dfs(startID, 0)
	return chains
}

func (g *AttackGraph) buildChainSummary(nodes []*Node, edges []*Edge) string {
	var parts []string
	for i, n := range nodes {
		parts = append(parts, fmt.Sprintf("[%s] %s", n.Type, n.Label))
		if i < len(edges) {
			parts = append(parts, fmt.Sprintf("--%s-->", edges[i].Type))
		}
	}
	return strings.Join(parts, " ")
}

func (g *AttackGraph) HighestScorePath(startID, endID string, maxDepth int) *AttackChain {
	if maxDepth > maxTraversalDepth {
		maxDepth = maxTraversalDepth
	}
	chains := g.FindChains(startID, endID, maxDepth)
	if len(chains) == 0 {
		return nil
	}
	best := &chains[0]
	for i := 1; i < len(chains); i++ {
		if chains[i].Score > best.Score {
			best = &chains[i]
		}
	}
	return best
}

func (g *AttackGraph) SuggestNextTargets(nodeID string, minScore float64) []*Node {
	g.mu.RLock()
	nodesCopy := make(map[string]*Node, len(g.nodes))
	edgesCopy := make(map[string][]*Edge, len(g.edges))
	for k, v := range g.nodes {
		n := *v
		n.Properties = make(map[string]interface{})
		for pk, pv := range v.Properties {
			n.Properties[pk] = pv
		}
		nodesCopy[k] = &n
	}
	for k, v := range g.edges {
		edgesCopy[k] = v
	}
	g.mu.RUnlock()

	scored := make(map[string]float64)
	visited := make(map[string]bool)
	var explore func(id string, depth int)
	explore = func(id string, depth int) {
		if depth > 3 {
			return
		}
		if visited[id] {
			return
		}
		visited[id] = true
		for _, edge := range edgesCopy[id] {
			if target, ok := nodesCopy[edge.TargetID]; ok {
				score := target.Score * edge.Weight
				if depth > 0 {
					score /= float64(depth)
				}
				if existing, ok := scored[edge.TargetID]; !ok || score > existing {
					scored[edge.TargetID] = score
				}
				explore(edge.TargetID, depth+1)
			}
		}
	}
	explore(nodeID, 0)

	var suggestions []*Node
	for id, score := range scored {
		if score >= minScore {
			if node, ok := nodesCopy[id]; ok {
				node.Score = score
				suggestions = append(suggestions, node)
			}
		}
	}

	for i := 0; i < len(suggestions); i++ {
		for j := i + 1; j < len(suggestions); j++ {
			if suggestions[j].Score > suggestions[i].Score {
				suggestions[i], suggestions[j] = suggestions[j], suggestions[i]
			}
		}
	}
	return suggestions
}

func (g *AttackGraph) AssessDifficulty(chain AttackChain) string {
	totalWeight := 0.0
	for _, e := range chain.Edges {
		totalWeight += e.Weight
	}
	avgWeight := totalWeight / float64(len(chain.Edges))

	switch {
	case avgWeight >= 0.8:
		return "trivial"
	case avgWeight >= 0.6:
		return "low"
	case avgWeight >= 0.4:
		return "medium"
	case avgWeight >= 0.2:
		return "hard"
	default:
		return "very_hard"
	}
}

func (g *AttackGraph) AllNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		result = append(result, n)
	}
	return result
}

func (g *AttackGraph) AllEdges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var result []*Edge
	for _, edges := range g.edges {
		result = append(result, edges...)
	}
	return result
}

func (g *AttackGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

func (g *AttackGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, edges := range g.edges {
		count += len(edges)
	}
	return count
}

func (g *AttackGraph) ToJSON() ([]byte, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	data := map[string]interface{}{
		"nodes": g.nodes,
		"edges": g.edges,
	}
	return json.MarshalIndent(data, "", "  ")
}

func (g *AttackGraph) UpdateNodeScore(id string, score float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if node, ok := g.nodes[id]; ok {
		node.Score = score
		node.UpdatedAt = time.Now()
	}
}

func (g *AttackGraph) UpdateEdgeWeight(sourceID, targetID string, weight float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, edge := range g.edges[sourceID] {
		if edge.TargetID == targetID {
			edge.Weight = weight
			return
		}
	}
}

func (g *AttackGraph) SetNodeProperty(id, key string, value interface{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if node, ok := g.nodes[id]; ok {
		node.Properties[key] = value
		node.UpdatedAt = time.Now()
	}
}

func (g *AttackGraph) HasCycle() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var hasCycle func(node string) bool
	hasCycle = func(node string) bool {
		visited[node] = true
		recStack[node] = true

		for _, edge := range g.edges[node] {
			if !visited[edge.TargetID] {
				if hasCycle(edge.TargetID) {
					return true
				}
			} else if recStack[edge.TargetID] {
				return true
			}
		}

		recStack[node] = false
		return false
	}

	for node := range g.nodes {
		if !visited[node] {
			if hasCycle(node) {
				return true
			}
		}
	}
	return false
}

type GraphExport struct {
	Nodes      []*Node       `json:"nodes"`
	Edges      []*Edge       `json:"edges"`
	Chains     []AttackChain `json:"chains,omitempty"`
	Statistics GraphStats    `json:"statistics"`
}

type GraphStats struct {
	NodeCount     int     `json:"node_count"`
	EdgeCount     int     `json:"edge_count"`
	ChainCount    int     `json:"chain_count"`
	MaxChainScore float64 `json:"max_chain_score"`
	HasCycle      bool    `json:"has_cycle"`
}

func (g *AttackGraph) Export() *GraphExport {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}

	edges := make([]*Edge, 0)
	for _, es := range g.edges {
		edges = append(edges, es...)
	}

	stats := GraphStats{
		NodeCount: len(nodes),
		EdgeCount: len(edges),
		HasCycle:  g.hasCycleLocked(),
	}

	return &GraphExport{
		Nodes:      nodes,
		Edges:      edges,
		Statistics: stats,
	}
}

func (g *AttackGraph) ExportDOT() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("digraph AttackGraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=filled];\n\n")

	colors := map[NodeType]string{
		NodeAsset:      "#4CAF50",
		NodeVuln:       "#F44336",
		NodeSecret:     "#FF9800",
		NodeEndpoint:   "#2196F3",
		NodeCredential: "#9C27B0",
		NodeService:    "#00BCD4",
		NodeTechnique:  "#607D8B",
	}

	for id, node := range g.nodes {
		color := colors[node.Type]
		if color == "" {
			color = "#9E9E9E"
		}
		label := strings.ReplaceAll(node.Label, "\"", "\\\"")
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\\n[%s]\", fillcolor=\"%s\"];\n",
			id, label, node.Type, color))
	}

	sb.WriteString("\n")

	edgeAttrs := map[EdgeType]string{
		EdgeExploits:      "color=red",
		EdgeLeadsTo:       "color=blue",
		EdgeRequires:      "color=orange, style=dashed",
		EdgeBypasses:      "color=purple",
		EdgeMitigates:     "color=green, style=dashed",
		EdgeDiscovers:     "color=teal",
		EdgeAuthenticates: "color=brown",
	}

	for _, edges := range g.edges {
		for _, e := range edges {
			attrs := edgeAttrs[e.Type]
			if attrs == "" {
				attrs = ""
			} else {
				attrs = " [" + attrs + "]"
			}
			sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\"%s;\n", e.SourceID, e.TargetID, attrs))
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

func (g *AttackGraph) ExportMermaid() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("graph LR\n")

	for id, node := range g.nodes {
		label := strings.ReplaceAll(node.Label, "\"", "'")
		sb.WriteString(fmt.Sprintf("  %s[\"%s<br/><i>%s</i>\"]\n", sanitizeMermaidID(id), label, node.Type))
	}

	sb.WriteString("\n")

	for _, edges := range g.edges {
		for _, e := range edges {
			sb.WriteString(fmt.Sprintf("  %s -->|%s| %s\n",
				sanitizeMermaidID(e.SourceID), e.Type, sanitizeMermaidID(e.TargetID)))
		}
	}

	return sb.String()
}

func (g *AttackGraph) TopAttackChains(maxChains int) []AttackChain {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var allChains []AttackChain
	for srcID := range g.nodes {
		for endID := range g.nodes {
			if srcID == endID {
				continue
			}
			chains := g.findChainsLocked(srcID, endID, 10)
			allChains = append(allChains, chains...)
		}
	}

	for i := 0; i < len(allChains); i++ {
		for j := i + 1; j < len(allChains); j++ {
			if allChains[j].Score > allChains[i].Score {
				allChains[i], allChains[j] = allChains[j], allChains[i]
			}
		}
	}

	if maxChains > 0 && len(allChains) > maxChains {
		allChains = allChains[:maxChains]
	}

	return allChains
}

func (g *AttackGraph) findChainsLocked(startID, endID string, maxDepth int) []AttackChain {
	if maxDepth > maxTraversalDepth {
		maxDepth = maxTraversalDepth
	}

	var chains []AttackChain
	visited := make(map[string]bool)
	var path []*Node
	var pathEdges []*Edge

	var dfs func(currentID string, depth int)
	dfs = func(currentID string, depth int) {
		if depth > maxDepth {
			return
		}
		if visited[currentID] {
			return
		}
		node, ok := g.nodes[currentID]
		if !ok {
			return
		}
		visited[currentID] = true
		path = append(path, node)

		if currentID == endID && len(path) > 1 {
			chain := AttackChain{
				Nodes:   make([]*Node, len(path)),
				Edges:   make([]*Edge, len(pathEdges)),
				Summary: g.buildChainSummary(path, pathEdges),
			}
			copy(chain.Nodes, path)
			copy(chain.Edges, pathEdges)
			for _, n := range path {
				chain.Score += n.Score
			}
			if len(path) > 0 {
				chain.Score /= float64(len(path))
			}
			if chain.Score > 1.0 {
				chain.Score = 1.0
			}
			chains = append(chains, chain)
		} else {
			for _, edge := range g.edges[currentID] {
				pathEdges = append(pathEdges, edge)
				dfs(edge.TargetID, depth+1)
				pathEdges = pathEdges[:len(pathEdges)-1]
			}
		}

		path = path[:len(path)-1]
		visited[currentID] = false
	}

	dfs(startID, 0)
	return chains
}

func (g *AttackGraph) hasCycleLocked() bool {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var hasCycle func(node string) bool
	hasCycle = func(node string) bool {
		visited[node] = true
		recStack[node] = true

		for _, edge := range g.edges[node] {
			if !visited[edge.TargetID] {
				if hasCycle(edge.TargetID) {
					return true
				}
			} else if recStack[edge.TargetID] {
				return true
			}
		}

		recStack[node] = false
		return false
	}

	for node := range g.nodes {
		if !visited[node] {
			if hasCycle(node) {
				return true
			}
		}
	}
	return false
}

func sanitizeMermaidID(id string) string {
	result := strings.ReplaceAll(id, "-", "_")
	result = strings.ReplaceAll(result, " ", "_")
	result = strings.ReplaceAll(result, ".", "_")
	result = strings.ReplaceAll(result, "/", "_")
	return result
}
