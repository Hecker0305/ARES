package engine

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/memory"
)

type MemoryBridge struct {
	store     *memory.MemoryStore
	strategic *memory.StrategicMemory
	inMemory  *sync.Map
	enabled   atomic.Bool
}

type MemoryPayload struct {
	Target    string
	VulnType  string
	Payload   string
	Success   bool
	Timestamp time.Time
}

func NewMemoryBridge(cfg memory.Config) *MemoryBridge {
	bridge := &MemoryBridge{
		inMemory: &sync.Map{},
	}
	bridge.enabled.Store(false)

	if cfg.Host != "" {
		store, err := memory.NewMemoryStore(cfg)
		if err != nil {
			logger.Warn(fmt.Sprintf("[MemoryBridge] PostgreSQL unavailable: %v, using in-memory fallback", err))
			bridge.enabled.Store(true)
			return bridge
		}

		bridge.store = store
		bridge.strategic = memory.NewStrategicMemory(store)
		bridge.enabled.Store(true)

		logger.Info("[MemoryBridge] Connected to PostgreSQL")
	} else {
		bridge.enabled.Store(true)
		logger.Info("[MemoryBridge] Using in-memory storage")
	}

	return bridge
}

func (m *MemoryBridge) UpdateMemory(target, vulnType, payload string, success bool) {
	if m.enabled.Load() {
		if m.strategic != nil {
			m.strategic.Update(target, vulnType, success)
		} else {
			m.updateInMemory(target, vulnType, payload, success)
		}
	} else {
		m.updateInMemory(target, vulnType, payload, success)
	}

	logger.Info(fmt.Sprintf("[MemoryBridge] Updated: target=%s, vuln=%s, payload=%s, success=%v",
		target, vulnType, payload, success))
}

func (m *MemoryBridge) updateInMemory(target, vulnType, payload string, success bool) {
	key := fmt.Sprintf("%s:%s", target, vulnType)

	// Store immutable snapshots to prevent data races on struct fields
	mp := &MemoryPayload{
		Target:    target,
		VulnType:  vulnType,
		Payload:   payload,
		Success:   success,
		Timestamp: time.Now(),
	}
	m.inMemory.Store(key, mp)
}

func (m *MemoryBridge) GetTopPayloads(target, vulnType string) []string {
	if m.strategic != nil {
		return m.getFromPostgres(target, vulnType)
	}

	return m.getFromInMemory(target, vulnType)
}

func (m *MemoryBridge) getFromPostgres(target, vulnType string) []string {
	if m.store == nil {
		return nil
	}

	outcomes, err := m.store.GetPayloadHistory(target, vulnType)
	if err != nil {
		logger.Error(fmt.Sprintf("[MemoryBridge] GetPayloadHistory error: %v", err))
		return nil
	}

	var payloads []string
	successCount := make(map[string]int)

	for _, o := range outcomes {
		if o.Success {
			successCount[o.Payload]++
		}
	}

	type payloadScore struct {
		payload string
		score   int
	}

	var scored []payloadScore
	for p, count := range successCount {
		scored = append(scored, payloadScore{payload: p, score: count})
	}

	for i := 0; i < len(scored); i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[j].score > scored[i].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	for _, s := range scored {
		payloads = append(payloads, s.payload)
		if len(payloads) >= 10 {
			break
		}
	}

	return payloads
}

func (m *MemoryBridge) getFromInMemory(target, vulnType string) []string {
	key := fmt.Sprintf("%s:%s", target, vulnType)

	val, exists := m.inMemory.Load(key)
	if !exists {
		return nil
	}

	mp, ok := val.(*MemoryPayload)
	if !ok {
		logger.Error(fmt.Sprintf("[MemoryBridge] unexpected type in memory: %T", val))
		return nil
	}
	return []string{mp.Payload}
}

func (m *MemoryBridge) RecordFinding(target, vulnType, payload, severity string, confidence float64, rawResp string) {
	if m.store != nil {
		finding := memory.Finding{
			Target:     target,
			VulnType:   vulnType,
			Payload:    payload,
			Severity:   severity,
			Confidence: confidence,
			RawResp:    rawResp,
			CreatedAt:  time.Now(),
		}

		if err := m.store.SaveFinding(finding); err != nil {
			logger.Error(fmt.Sprintf("[MemoryBridge] SaveFinding error: %v", err))
		}
	}
}

func (m *MemoryBridge) RecordPayloadOutcome(target, vulnType, payload string, success bool) {
	if m.store != nil {
		outcome := memory.PayloadOutcome{
			Target:    target,
			VulnType:  vulnType,
			Payload:   payload,
			Success:   success,
			CreatedAt: time.Now(),
		}

		if err := m.store.RecordPayloadOutcome(outcome); err != nil {
			logger.Error(fmt.Sprintf("[MemoryBridge] RecordPayloadOutcome error: %v", err))
		}
	}
}

func (m *MemoryBridge) GetProbSuccess(target, vulnType string) float64 {
	if m.strategic != nil {
		return m.strategic.GetProb(target, vulnType)
	}

	key := fmt.Sprintf("%s:%s", target, vulnType)
	val, exists := m.inMemory.Load(key)
	if !exists {
		return 0.5
	}

	mp, ok := val.(*MemoryPayload)
	if !ok {
		logger.Error(fmt.Sprintf("[MemoryBridge] unexpected type in getConfidence: %T", val))
		return 0.5
	}
	if mp.Success {
		return 0.7
	}

	return 0.3
}

func (m *MemoryBridge) Close() error {
	if m.store != nil {
		return m.store.Close()
	}

	return nil
}

func (m *MemoryBridge) IsEnabled() bool {
	return m.enabled.Load()
}

func (m *MemoryBridge) InjectStrategicContext(targets []string) string {
	if m.store != nil {
		recall := memory.NewRecallTool(m.store)
		return recall.InjectInitial(targets)
	}

	var lines []string
	m.inMemory.Range(func(key, value interface{}) bool {
		mp, ok := value.(*MemoryPayload)
		if !ok {
			return true
		}
		for _, target := range targets {
			if target == mp.Target {
				lines = append(lines, fmt.Sprintf("Memory: %s - %s (success=%v)",
					mp.Target, mp.Payload, mp.Success))
			}
		}
		return true
	})

	if len(lines) == 0 {
		return ""
	}

	return "STRATEGIC MEMORY:\n" + joinLines(lines, 5)
}

func joinLines(lines []string, max int) string {
	if len(lines) == 0 {
		return ""
	}

	count := len(lines)
	if count > max {
		count = max
	}

	result := ""
	for i := 0; i < count; i++ {
		if i > 0 {
			result += "\n"
		}
		result += lines[i]
	}

	if len(lines) > max {
		result += fmt.Sprintf("\n... and %d more", len(lines)-max)
	}

	return result
}
