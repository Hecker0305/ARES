package taint

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Source int

const (
	Clean       Source = 0
	LLMOutput   Source = 1
	Network     Source = 2
	FileSystem  Source = 3
	Browser     Source = 4
	Payload     Source = 5
	ReplayInput Source = 6
	UserInput   Source = 7
)

func (s Source) String() string {
	switch s {
	case Clean:
		return "clean"
	case LLMOutput:
		return "llm"
	case Network:
		return "network"
	case FileSystem:
		return "filesystem"
	case Browser:
		return "browser"
	case Payload:
		return "payload"
	case ReplayInput:
		return "replay"
	case UserInput:
		return "user"
	default:
		return "unknown"
	}
}

type Tag struct {
	Source      Source    `json:"source"`
	Propagated  bool      `json:"propagated"`
	OriginID    string    `json:"origin_id,omitempty"`
	OriginLabel string    `json:"origin_label,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type FlowEdge struct {
	FromID     string    `json:"from_id"`
	ToID       string    `json:"to_id"`
	Source     Source    `json:"source"`
	Propagated bool      `json:"propagated"`
	Timestamp  time.Time `json:"timestamp"`
}

type FlowPath struct {
	Nodes []string `json:"nodes"`
	Tags  []Tag    `json:"tags"`
	Score float64  `json:"score"`
}

type Engine struct {
	mu          sync.RWMutex
	labels      map[string]Tag
	rules       []Rule
	flow        []FlowEdge
	maxFlows    int
	concatCache map[string][]string
}

type Rule struct {
	Name     string   `json:"name"`
	Sources  []Source `json:"sources"`
	Blocked  bool     `json:"blocked"`
	WarnOnly bool     `json:"warn_only"`
}

type Sanitizer func(value string) (sanitized string, ok bool)

var builtinSanitizers = map[string]Sanitizer{
	"html_escape": func(v string) (string, bool) {
		r := strings.NewReplacer("<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
		return r.Replace(v), true
	},
	"sql_escape": func(v string) (string, bool) {
		r := strings.NewReplacer("'", "''", "\\", "\\\\", "\x00", "")
		return r.Replace(v), true
	},
	"shell_escape": func(v string) (string, bool) {
		r := strings.NewReplacer("|", "", ";", "", "&", "", "$", "", "`", "", "\\", "")
		return r.Replace(v), true
	},
	"url_encode": func(v string) (string, bool) {
		r := strings.NewReplacer(" ", "%20", "\"", "%22", "<", "%3C", ">", "%3E")
		return r.Replace(v), true
	},
}

func New() *Engine {
	e := &Engine{
		labels:      make(map[string]Tag),
		rules:       make([]Rule, 0),
		flow:        make([]FlowEdge, 0, 1000),
		maxFlows:    10000,
		concatCache: make(map[string][]string),
	}
	e.AddBuiltinRules()
	return e
}

func (e *Engine) SetMaxFlows(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxFlows = n
}

func (e *Engine) AddBuiltinRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, []Rule{
		{Name: "llm-to-exec", Sources: []Source{LLMOutput}, Blocked: true},
		{Name: "network-to-exec", Sources: []Source{Network}, Blocked: true},
		{Name: "browser-to-exec", Sources: []Source{Browser}, Blocked: true},
		{Name: "payload-to-exec", Sources: []Source{Payload}, Blocked: true},
		{Name: "replay-to-exec", Sources: []Source{ReplayInput}, Blocked: true},
		{Name: "user-to-exec", Sources: []Source{UserInput}, Blocked: true},
	}...)
}

func (e *Engine) Tag(id string, source Source) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.labels[id] = Tag{
		Source:    source,
		OriginID:  id,
		CreatedAt: time.Now(),
	}
}

func (e *Engine) TagWithOrigin(id string, source Source, originID, originLabel string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.labels[id] = Tag{
		Source:      source,
		OriginID:    originID,
		OriginLabel: originLabel,
		CreatedAt:   time.Now(),
	}
}

func (e *Engine) Propagate(fromID, toID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	src, ok := e.labels[fromID]
	if !ok {
		return
	}

	originID := src.OriginID
	if originID == "" {
		originID = fromID
	}

	e.labels[toID] = Tag{
		Source:      src.Source,
		Propagated:  true,
		OriginID:    originID,
		OriginLabel: src.OriginLabel,
		CreatedAt:   time.Now(),
	}

	e.flow = append(e.flow, FlowEdge{
		FromID:     fromID,
		ToID:       toID,
		Source:     src.Source,
		Propagated: true,
		Timestamp:  time.Now(),
	})
	if len(e.flow) > e.maxFlows {
		e.flow = e.flow[len(e.flow)-e.maxFlows:]
	}
}

func (e *Engine) PropagateConcat(resultID string, sourceIDs []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var taintedSources []Source
	var taintedOrigins []string
	var allTainted bool
	for _, srcID := range sourceIDs {
		if tag, ok := e.labels[srcID]; ok {
			taintedSources = append(taintedSources, tag.Source)
			if tag.OriginID != "" {
				taintedOrigins = append(taintedOrigins, tag.OriginID)
			} else {
				taintedOrigins = append(taintedOrigins, srcID)
			}
			allTainted = true
		} else {
			allTainted = false
		}
	}

	if len(taintedSources) == 0 {
		return
	}

	highestSource := taintedSources[0]
	for _, s := range taintedSources {
		if s > highestSource {
			highestSource = s
		}
	}

	if !allTainted && len(taintedSources) > 0 {
		highestSource = Payload
	}

	originLabel := "concat:" + strings.Join(taintedOrigins, ",")
	e.labels[resultID] = Tag{
		Source:      highestSource,
		Propagated:  true,
		OriginID:    taintedOrigins[0],
		OriginLabel: originLabel,
		CreatedAt:   time.Now(),
	}

	for _, srcID := range sourceIDs {
		e.flow = append(e.flow, FlowEdge{
			FromID:     srcID,
			ToID:       resultID,
			Source:     highestSource,
			Propagated: true,
			Timestamp:  time.Now(),
		})
	}

	e.concatCache[resultID] = sourceIDs

	if len(e.flow) > e.maxFlows {
		e.flow = e.flow[len(e.flow)-e.maxFlows:]
	}
}

func (e *Engine) PropagateConcatPartial(resultID string, sourceIDs []string, cleanIDs []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var taintedSources []Source
	var taintedOrigins []string
	for _, srcID := range sourceIDs {
		if tag, ok := e.labels[srcID]; ok {
			taintedSources = append(taintedSources, tag.Source)
			if tag.OriginID != "" {
				taintedOrigins = append(taintedOrigins, tag.OriginID)
			} else {
				taintedOrigins = append(taintedOrigins, srcID)
			}
		}
	}

	for _, srcID := range cleanIDs {
		e.flow = append(e.flow, FlowEdge{
			FromID:     srcID,
			ToID:       resultID,
			Source:     Clean,
			Propagated: false,
			Timestamp:  time.Now(),
		})
	}

	if len(taintedSources) == 0 {
		e.labels[resultID] = Tag{
			Source:      Clean,
			Propagated:  false,
			OriginID:    resultID,
			OriginLabel: "concat:clean",
			CreatedAt:   time.Now(),
		}
		return
	}

	highestSource := taintedSources[0]
	for _, s := range taintedSources {
		if s > highestSource {
			highestSource = s
		}
	}

	originLabel := "concat:" + strings.Join(taintedOrigins, ",")
	e.labels[resultID] = Tag{
		Source:      highestSource,
		Propagated:  true,
		OriginID:    taintedOrigins[0],
		OriginLabel: originLabel,
		CreatedAt:   time.Now(),
	}

	for _, srcID := range sourceIDs {
		e.flow = append(e.flow, FlowEdge{
			FromID:     srcID,
			ToID:       resultID,
			Source:     highestSource,
			Propagated: true,
			Timestamp:  time.Now(),
		})
	}

	e.concatCache[resultID] = append(sourceIDs, cleanIDs...)

	if len(e.flow) > e.maxFlows {
		e.flow = e.flow[len(e.flow)-e.maxFlows:]
	}
}

func (e *Engine) SanitizedPropagate(fromID, toID string, sanitizerName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	src, ok := e.labels[fromID]
	if !ok {
		return
	}

	_, sanitizerExists := builtinSanitizers[sanitizerName]
	if sanitizerExists {
		e.labels[toID] = Tag{
			Source:      Clean,
			Propagated:  true,
			OriginID:    src.OriginID,
			OriginLabel: fmt.Sprintf("sanitized:%s", sanitizerName),
			CreatedAt:   time.Now(),
		}
	} else {
		e.labels[toID] = Tag{
			Source:      src.Source,
			Propagated:  true,
			OriginID:    src.OriginID,
			OriginLabel: fmt.Sprintf("sanitized_unknown:%s", sanitizerName),
			CreatedAt:   time.Now(),
		}
	}

	e.flow = append(e.flow, FlowEdge{
		FromID:     fromID,
		ToID:       toID,
		Source:     src.Source,
		Propagated: true,
		Timestamp:  time.Now(),
	})
	if len(e.flow) > e.maxFlows {
		e.flow = e.flow[len(e.flow)-e.maxFlows:]
	}
}

func (e *Engine) Check(id string) (Tag, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	tag, ok := e.labels[id]
	if ok {
		return tag, true
	}
	if sources, ok := e.concatCache[id]; ok {
		for _, srcID := range sources {
			if t, found := e.labels[srcID]; found {
				return Tag{
					Source:      t.Source,
					Propagated:  true,
					OriginID:    t.OriginID,
					OriginLabel: "concat_lookup:" + id,
					CreatedAt:   t.CreatedAt,
				}, true
			}
		}
	}
	return Tag{}, false
}

func (e *Engine) IsBlocked(id string) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	tag, ok := e.labels[id]
	if !ok {
		if sources, cok := e.concatCache[id]; cok {
			for _, srcID := range sources {
				if t, found := e.labels[srcID]; found {
					for _, rule := range e.rules {
						for _, src := range rule.Sources {
							if t.Source == src {
								return rule.Blocked, rule.Name
							}
						}
					}
				}
			}
		}
		return false, ""
	}
	for _, rule := range e.rules {
		for _, src := range rule.Sources {
			if tag.Source == src {
				return rule.Blocked, rule.Name
			}
		}
	}
	return false, ""
}

func (e *Engine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

func (e *Engine) MustFlow(id, target string) error {
	blocked, rule := e.IsBlocked(id)
	if blocked {
		path := e.TracePath(id)
		return fmt.Errorf("taint blocked: %s -> %s (rule: %s, path: %s)", id, target, rule, path)
	}
	return nil
}

func (e *Engine) TracePath(id string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tag, ok := e.labels[id]
	if !ok {
		return fmt.Sprintf("%s:untagged", id)
	}

	path := []string{fmt.Sprintf("%s[%s]", id, tag.Source)}
	if tag.OriginID != "" && tag.OriginID != id {
		if originTag, ok := e.labels[tag.OriginID]; ok {
			path = append([]string{fmt.Sprintf("%s[%s]", tag.OriginID, originTag.Source)}, path...)
		}
	}

	for _, edge := range e.flow {
		if edge.ToID == id {
			path = append([]string{fmt.Sprintf("%s[%s]", edge.FromID, edge.Source)}, path...)
		}
	}

	return strings.Join(path, " -> ")
}

func (e *Engine) FindPaths(sinkID string) FlowPath {
	e.mu.RLock()
	defer e.mu.RUnlock()

	path := FlowPath{
		Nodes: []string{sinkID},
		Score: 1.0,
	}

	tag, ok := e.labels[sinkID]
	if !ok {
		return path
	}
	path.Tags = append(path.Tags, tag)

	visited := map[string]bool{sinkID: true}
	current := sinkID
	maxDepth := 20

	for depth := 0; depth < maxDepth; depth++ {
		found := false
		for _, edge := range e.flow {
			if edge.ToID == current && !visited[edge.FromID] {
				path.Nodes = append([]string{edge.FromID}, path.Nodes...)
				if t, ok := e.labels[edge.FromID]; ok {
					path.Tags = append([]Tag{t}, path.Tags...)
				}
				visited[edge.FromID] = true
				current = edge.FromID
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	if tag.Source != Clean {
		path.Score = 1.0 - float64(len(path.Nodes))*0.1
		if path.Score < 0.1 {
			path.Score = 0.1
		}
	}

	return path
}

func (e *Engine) AllFlows() []FlowEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]FlowEdge, len(e.flow))
	copy(result, e.flow)
	return result
}

func (e *Engine) FlowsFromSource(s Source) []FlowEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []FlowEdge
	for _, f := range e.flow {
		if f.Source == s {
			result = append(result, f)
		}
	}
	return result
}

func (e *Engine) FlowsByNode(id string) []FlowEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []FlowEdge
	for _, f := range e.flow {
		if f.FromID == id || f.ToID == id {
			result = append(result, f)
		}
	}
	return result
}

func (e *Engine) ImpactAnalysis() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	bySource := make(map[Source]int)
	blockedCount := 0
	sanitizedCount := 0

	for _, t := range e.labels {
		bySource[t.Source]++
		if t.OriginLabel != "" && strings.HasPrefix(t.OriginLabel, "sanitized") {
			sanitizedCount++
		}
		for _, rule := range e.rules {
			for _, src := range rule.Sources {
				if t.Source == src && rule.Blocked {
					blockedCount++
					goto nextTag
				}
			}
		}
	nextTag:
	}

	sourceBreakdown := make(map[string]int)
	for s, c := range bySource {
		sourceBreakdown[s.String()] = c
	}

	return map[string]interface{}{
		"total_tags":       len(e.labels),
		"total_flows":      len(e.flow),
		"blocked_tags":     blockedCount,
		"santized_tags":    sanitizedCount,
		"source breakdown": sourceBreakdown,
	}
}

func (e *Engine) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.labels = make(map[string]Tag)
	e.flow = make([]FlowEdge, 0, 1000)
}

func (e *Engine) Stats() map[Source]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := make(map[Source]int)
	for _, t := range e.labels {
		stats[t.Source]++
	}
	return stats
}

func (e *Engine) StringsBySource(source Source) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var ids []string
	for id, t := range e.labels {
		if t.Source == source {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (e *Engine) VulnerableFlows() []FlowPath {
	candidateIDs := func() []string {
		e.mu.RLock()
		defer e.mu.RUnlock()
		var ids []string
		for id, t := range e.labels {
			for _, rule := range e.rules {
				for _, src := range rule.Sources {
					if t.Source == src && rule.Blocked {
						ids = append(ids, id)
						goto nextLabel
					}
				}
			}
		nextLabel:
		}
		return ids
	}()

	var paths []FlowPath
	for _, id := range candidateIDs {
		p := e.FindPaths(id)
		if p.Score > 0 {
			paths = append(paths, p)
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Score > paths[j].Score
	})
	if len(paths) > 20 {
		paths = paths[:20]
	}
	return paths
}
