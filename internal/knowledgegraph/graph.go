package knowledgegraph

import (
	"github.com/ares/engine/internal/uuid"
	"fmt"
	"sync"
	"time"
)

type EntityType string

const (
	EntityAsset      EntityType = "asset"
	EntityVuln       EntityType = "vulnerability"
	EntityCredential EntityType = "credential"
	EntityService    EntityType = "service"
	EntityIdentity   EntityType = "identity"
	EntityEndpoint   EntityType = "endpoint"
	EntitySecret     EntityType = "secret"
	EntityFinding    EntityType = "finding"
)

type RelationshipType string

const (
	RelHasVuln         RelationshipType = "has_vulnerability"
	RelUsesCredential  RelationshipType = "uses_credential"
	RelRunsService     RelationshipType = "runs_service"
	RelHasIdentity     RelationshipType = "has_identity"
	RelExploits        RelationshipType = "exploits"
	RelConnectsTo      RelationshipType = "connects_to"
	RelDependsOn       RelationshipType = "depends_on"
	RelAuthenticatesAs RelationshipType = "authenticates_as"
	RelContains        RelationshipType = "contains"
)

type Entity struct {
	ID          string                 `json:"id"`
	Type        EntityType             `json:"type"`
	Name        string                 `json:"name"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
	RiskScore   float64                `json:"risk_score,omitempty"`
	Criticality string                 `json:"criticality,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type Relationship struct {
	ID         string                 `json:"id"`
	SourceID   string                 `json:"source_id"`
	TargetID   string                 `json:"target_id"`
	Type       RelationshipType       `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Weight     float64                `json:"weight,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type AttackPath struct {
	Path          []Entity       `json:"path"`
	Relationships []Relationship `json:"relationships"`
	TotalRisk     float64        `json:"total_risk"`
	Steps         int            `json:"steps"`
	Description   string         `json:"description"`
}

type KnowledgeGraph struct {
	mu            sync.RWMutex
	entities      map[string]*Entity
	relationships map[string][]*Relationship
	entityIndex   map[EntityType][]string
}

func New() *KnowledgeGraph {
	return &KnowledgeGraph{
		entities:      make(map[string]*Entity),
		relationships: make(map[string][]*Relationship),
		entityIndex:   make(map[EntityType][]string),
	}
}

func (kg *KnowledgeGraph) AddEntity(entity Entity) string {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	if entity.ID == "" {
		entity.ID = uuid.New()
	}
	entity.CreatedAt = time.Now()
	entity.UpdatedAt = time.Now()

	kg.entities[entity.ID] = &entity
	kg.entityIndex[entity.Type] = append(kg.entityIndex[entity.Type], entity.ID)

	return entity.ID
}

func (kg *KnowledgeGraph) GetEntity(id string) *Entity {
	kg.mu.RLock()
	defer kg.mu.RUnlock()
	if e, ok := kg.entities[id]; ok {
		return e
	}
	return nil
}

func (kg *KnowledgeGraph) UpdateEntity(id string, props map[string]interface{}) bool {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	if e, ok := kg.entities[id]; ok {
		for k, v := range props {
			e.Properties[k] = v
		}
		e.UpdatedAt = time.Now()
		return true
	}
	return false
}

func (kg *KnowledgeGraph) RemoveEntity(id string) bool {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	entity, ok := kg.entities[id]
	if !ok {
		return false
	}

	idx := -1
	for i, eid := range kg.entityIndex[entity.Type] {
		if eid == id {
			idx = i
			break
		}
	}
	if idx >= 0 {
		kg.entityIndex[entity.Type] = append(
			kg.entityIndex[entity.Type][:idx],
			kg.entityIndex[entity.Type][idx+1:]...,
		)
	}

	delete(kg.entities, id)
	delete(kg.relationships, id)

	for sourceID, rels := range kg.relationships {
		var filtered []*Relationship
		for _, rel := range rels {
			if rel.TargetID != id {
				filtered = append(filtered, rel)
			}
		}
		kg.relationships[sourceID] = filtered
	}

	return true
}

func (kg *KnowledgeGraph) GetEntitiesByType(t EntityType) []*Entity {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	var result []*Entity
	for _, id := range kg.entityIndex[t] {
		if e, ok := kg.entities[id]; ok {
			result = append(result, e)
		}
	}
	return result
}

func (kg *KnowledgeGraph) AllEntities() []*Entity {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	result := make([]*Entity, 0, len(kg.entities))
	for _, e := range kg.entities {
		result = append(result, e)
	}
	return result
}

func (kg *KnowledgeGraph) AddRelationship(rel Relationship) string {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	if rel.ID == "" {
		rel.ID = uuid.New()
	}
	rel.CreatedAt = time.Now()

	kg.relationships[rel.SourceID] = append(kg.relationships[rel.SourceID], &rel)

	reverseRel := Relationship{
		ID:       uuid.New(),
		SourceID: rel.TargetID,
		TargetID: rel.SourceID,
		Type:     rel.Type,
		Weight:   rel.Weight,
	}
	kg.relationships[reverseRel.SourceID] = append(kg.relationships[reverseRel.SourceID], &reverseRel)

	return rel.ID
}

func (kg *KnowledgeGraph) GetRelationships(entityID string) []*Relationship {
	kg.mu.RLock()
	defer kg.mu.RUnlock()
	rels := kg.relationships[entityID]
	if rels == nil {
		return nil
	}
	result := make([]*Relationship, len(rels))
	copy(result, rels)
	return result
}

func (kg *KnowledgeGraph) FindPaths(startID, endID string, maxDepth int) []AttackPath {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	var paths []AttackPath
	visited := make(map[string]bool)
	currentPath := []string{}

	kg.dfs(startID, endID, maxDepth, 0, visited, currentPath, &paths)

	return paths
}

func (kg *KnowledgeGraph) dfs(current, target string, maxDepth, depth int, visited map[string]bool, path []string, paths *[]AttackPath) {
	if depth > maxDepth {
		return
	}

	if visited[current] {
		return
	}

	visited[current] = true
	path = append(path, current)

	if current == target {
		attackPath := kg.buildPath(path)
		if attackPath != nil {
			*paths = append(*paths, *attackPath)
		}
		visited[current] = false
		return
	}

	for _, rel := range kg.relationships[current] {
		kg.dfs(rel.TargetID, target, maxDepth, depth+1, visited, path, paths)
	}

	visited[current] = false
}

func (kg *KnowledgeGraph) buildPath(entityIDs []string) *AttackPath {
	if len(entityIDs) < 2 {
		return nil
	}

	var entities []Entity
	var rels []Relationship
	totalRisk := 0.0

	for _, id := range entityIDs {
		if e, ok := kg.entities[id]; ok {
			entities = append(entities, *e)
			totalRisk += e.RiskScore
		}
	}

	for i := 0; i < len(entityIDs)-1; i++ {
		for _, rel := range kg.relationships[entityIDs[i]] {
			if rel.TargetID == entityIDs[i+1] {
				rels = append(rels, *rel)
				break
			}
		}
	}

	desc := fmt.Sprintf("Attack path from %s to %s (%d steps)", entities[0].Name, entities[len(entities)-1].Name, len(entities)-1)

	return &AttackPath{
		Path:          entities,
		Relationships: rels,
		TotalRisk:     totalRisk,
		Steps:         len(rels),
		Description:   desc,
	}
}

func (kg *KnowledgeGraph) GetStats() map[string]interface{} {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	entityCount := make(map[EntityType]int)
	for _, e := range kg.entities {
		entityCount[e.Type]++
	}

	relCount := 0
	for _, rels := range kg.relationships {
		relCount += len(rels)
	}

	var avgRisk float64
	if len(kg.entities) > 0 {
		var totalRisk float64
		for _, e := range kg.entities {
			totalRisk += e.RiskScore
		}
		avgRisk = totalRisk / float64(len(kg.entities))
	}

	return map[string]interface{}{
		"total_entities":      len(kg.entities),
		"total_relationships": relCount / 2,
		"entities_by_type":    entityCount,
		"average_risk_score":  avgRisk,
	}
}

func (kg *KnowledgeGraph) FindAssetsByCredential(credentialID string) []*Entity {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	var assets []*Entity
	for _, rels := range kg.relationships {
		for _, rel := range rels {
			if rel.TargetID == credentialID && rel.Type == RelUsesCredential {
				if entity, ok := kg.entities[rel.SourceID]; ok {
					assets = append(assets, entity)
				}
			}
		}
	}
	return assets
}

func (kg *KnowledgeGraph) GetExposurePath(assetID string) []AttackPath {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	var paths []AttackPath
	visited := make(map[string]bool)

	var findExposed func(current string, path []string, depth int)
	findExposed = func(current string, path []string, depth int) {
		if depth > 10 || visited[current] {
			return
		}
		visited[current] = true
		path = append(path, current)

		entity := kg.entities[current]
		if entity != nil {
			if entity.Type == EntityCredential || entity.Type == EntitySecret {
				attackPath := kg.buildPath(path)
				if attackPath != nil {
					paths = append(paths, *attackPath)
				}
			}
		}

		for _, rel := range kg.relationships[current] {
			findExposed(rel.TargetID, path, depth+1)
		}
		visited[current] = false
	}

	findExposed(assetID, []string{}, 0)
	return paths
}
