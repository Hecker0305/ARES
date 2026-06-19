package memory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type PersistentStrategicMemory struct {
	store    map[string]float64
	mu       sync.RWMutex
	filePath string
}

func NewPersistentStrategicMemory() *PersistentStrategicMemory {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = os.TempDir()
	}
	dbPath := filepath.Join(homeDir, ".ares", "strategic.json")
	os.MkdirAll(filepath.Dir(dbPath), 0750)

	psm := &PersistentStrategicMemory{
		store:    make(map[string]float64),
		filePath: dbPath,
	}
	psm.Load()
	return psm
}

func (psm *PersistentStrategicMemory) key(framework, vulnType string) string {
	return framework + ":" + vulnType
}

func (psm *PersistentStrategicMemory) GetSuccessProbability(framework, vulnType string) float64 {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	k := psm.key(framework, vulnType)
	if v, ok := psm.store[k]; ok {
		return v
	}
	return 0.3
}

func (psm *PersistentStrategicMemory) RecordOutcome(framework, vulnType, payload, targetHash string, success bool) {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	k := psm.key(framework, vulnType)
	current := psm.store[k]
	if success {
		psm.store[k] = min(current+0.1, 1.0)
	} else {
		psm.store[k] = max(current-0.05, 0.0)
	}
	psm.saveToFile()
}

func (psm *PersistentStrategicMemory) TopPayloads(framework, vulnType string, limit int) []string {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	if limit <= 0 {
		limit = 10
	}
	k := psm.key(framework, vulnType)
	v := psm.store[k]
	return []string{fmt.Sprintf("top_payload_%s_%d", framework, int(v*100))}
}

func (psm *PersistentStrategicMemory) saveToFile() {
	data, err := json.MarshalIndent(psm.store, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(psm.filePath, data, 0600)
}

func (psm *PersistentStrategicMemory) Load() {
	data, err := os.ReadFile(psm.filePath)
	if err != nil {
		return
	}
	var store map[string]float64
	if err := json.Unmarshal(data, &store); err != nil {
		return
	}
	psm.store = store
}

func (psm *PersistentStrategicMemory) Close() {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	psm.saveToFile()
}

type Skill struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	PreConditions   []string `json:"pre_conditions,omitempty"`
	SuccessCriteria []string `json:"success_criteria,omitempty"`
	TargetServices  []string `json:"target_services,omitempty"`
	FilePath        string   `json:"file_path,omitempty"`
}

type SkillManager struct {
	Skills map[string]*Skill
	mu     sync.RWMutex
}

func NewSkillManager(baseDir string) (*SkillManager, error) {
	sm := &SkillManager{
		Skills: make(map[string]*Skill),
	}
	if baseDir != "" {
		sm.loadSkills(baseDir)
	}
	return sm, nil
}

func (sm *SkillManager) loadSkills(baseDir string) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".skill") {
			continue
		}
		path := filepath.Join(baseDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		skill := Skill{FilePath: path}
		if strings.HasSuffix(name, ".json") {
			if err := json.Unmarshal(data, &skill); err != nil {
				continue
			}
		} else {
			skill.Name = strings.TrimSuffix(name, ".skill")
			skill.Description = string(data)
			if len(data) > 120 {
				skill.Description = strings.TrimSpace(string(data[:120]))
			}
		}
		if skill.Name == "" {
			skill.Name = strings.TrimSuffix(name, ".json")
			skill.Name = strings.TrimSuffix(skill.Name, ".skill")
		}
		sm.Skills[skill.Name] = &skill
	}
}

func (sm *SkillManager) FindMatchingSkill(service string) *Skill {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, skill := range sm.Skills {
		for _, svc := range skill.TargetServices {
			if svc == service {
				return skill
			}
		}
	}
	return nil
}

type FederatedIntelligence struct {
	mu   sync.RWMutex
	data map[string]interface{}
}

func NewFederatedIntelligence() *FederatedIntelligence {
	return &FederatedIntelligence{
		data: make(map[string]interface{}),
	}
}

func (fi *FederatedIntelligence) RecordOutcome(framework, vulnType, payload, targetHash string, success bool) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	key := framework + ":" + vulnType + ":" + targetHash
	fi.data[key] = map[string]interface{}{
		"framework":   framework,
		"vuln_type":   vulnType,
		"payload":     payload,
		"target_hash": targetHash,
		"success":     success,
		"timestamp":   time.Now().Format(time.RFC3339),
	}
}

func (fi *FederatedIntelligence) GetOutcomes() map[string]interface{} {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	result := make(map[string]interface{})
	for k, v := range fi.data {
		result[k] = v
	}
	return result
}
