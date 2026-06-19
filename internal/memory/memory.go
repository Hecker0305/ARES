package memory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	DSN      string
	DBPath   string
}

type MemoryStore struct {
	mu       sync.RWMutex
	data     map[string]interface{}
	filePath string
	dirty    bool
	flushCh  chan struct{}
	stopCh   chan struct{}
	saveWg   sync.WaitGroup
}

func NewMemoryStore(cfg Config) (*MemoryStore, error) {
	store := &MemoryStore{
		data:    make(map[string]interface{}),
		flushCh: make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
	}
	if cfg.DBPath != "" {
		store.filePath = cfg.DBPath
		if err := os.MkdirAll(filepath.Dir(store.filePath), 0750); err != nil {
			return nil, fmt.Errorf("failed to create data directory: %w", err)
		}
		store.loadFromFile()
		store.saveWg.Add(1)
		go store.backgroundSave()
	}
	return store, nil
}

func (m *MemoryStore) backgroundSave() {
	defer m.saveWg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			m.flush()
			return
		case <-ticker.C:
			m.flush()
		case <-m.flushCh:
			m.flush()
		}
	}
}

func (m *MemoryStore) flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dirty {
		m.saveToFileLocked()
		m.dirty = false
	}
}

func (m *MemoryStore) markDirty() {
	m.dirty = true
	select {
	case m.flushCh <- struct{}{}:
	default:
	}
}

func (m *MemoryStore) GetPayloadHistory(target, vulnType string) ([]PayloadOutcome, error) {
	if target == "" || vulnType == "" {
		return nil, fmt.Errorf("target and vulnType are required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	key := "outcome:" + target + ":" + vulnType
	if raw, ok := m.data[key]; ok {
		if outcomes, ok := raw.([]PayloadOutcome); ok {
			return outcomes, nil
		}
	}
	return []PayloadOutcome{}, nil
}

func (m *MemoryStore) SaveFinding(finding Finding) error {
	if finding.Target == "" {
		return fmt.Errorf("finding target is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := "finding:" + finding.Target + ":" + finding.VulnType
	m.data[key] = finding
	m.markDirty()
	return nil
}

func (m *MemoryStore) RecordPayloadOutcome(outcome PayloadOutcome) error {
	if outcome.Target == "" || outcome.Payload == "" {
		return fmt.Errorf("target and payload are required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := "outcome:" + outcome.Target + ":" + outcome.VulnType
	var outcomes []PayloadOutcome
	if raw, ok := m.data[key]; ok {
		if os, ok := raw.([]PayloadOutcome); ok {
			outcomes = os
		}
	}
	outcomes = append(outcomes, outcome)
	m.data[key] = outcomes
	m.markDirty()
	return nil
}

func (m *MemoryStore) WithKeyPrefix(prefix string, fn func(key string, val interface{})) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.data {
		if strings.HasPrefix(k, prefix) {
			fn(k, v)
		}
	}
}

func (m *MemoryStore) Close() error {
	m.mu.Lock()
	if m.data == nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	select {
	case <-m.stopCh:
		return nil
	default:
		close(m.stopCh)
	}
	m.saveWg.Wait()
	m.mu.Lock()
	m.data = nil
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) loadFromFile() {
	info, err := os.Stat(m.filePath)
	if err != nil {
		return
	}
	const maxMemoryFileSize = 100 << 20
	if info.Size() > maxMemoryFileSize || info.Size() == 0 {
		return
	}
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		return
	}
	var store map[string][]PayloadOutcome
	if err := json.Unmarshal(data, &store); err != nil {
		var genericStore map[string]interface{}
		if err2 := json.Unmarshal(data, &genericStore); err2 != nil {
			return
		}
		m.data = genericStore
		return
	}
	result := make(map[string]interface{}, len(store))
	for k, v := range store {
		result[k] = v
	}
	m.data = result
}

func (m *MemoryStore) saveToFileLocked() {
	if m.filePath == "" {
		return
	}
	data, err := json.MarshalIndent(m.data, "", "  ")
	if err != nil {
		logger.Error(fmt.Sprintf("[MemoryStore] Failed to marshal data: %v", err))
		return
	}
	tmpPath := m.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		logger.Error(fmt.Sprintf("[MemoryStore] Failed to write temp file: %v", err))
		return
	}
	if err := os.Rename(tmpPath, m.filePath); err != nil {
		logger.Error(fmt.Sprintf("[MemoryStore] Failed to rename temp file: %v", err))
		if removeErr := os.Remove(tmpPath); removeErr != nil {
			logger.Error(fmt.Sprintf("[MemoryStore] Failed to remove temp file %s: %v", tmpPath, removeErr))
		}
	}
}

type Finding struct {
	Target     string
	VulnType   string
	Payload    string
	Severity   string
	Confidence float64
	RawResp    string
	CreatedAt  time.Time
}

type PayloadOutcome struct {
	Target    string
	VulnType  string
	Payload   string
	Success   bool
	CreatedAt time.Time
}

type StrategicMemory struct {
	mu      sync.RWMutex
	store   map[string]float64
	storeDB *MemoryStore
}

func NewStrategicMemory(store *MemoryStore) *StrategicMemory {
	if store == nil {
		var err error
		store, err = NewMemoryStore(Config{})
		if err != nil {
			logger.Error(fmt.Sprintf("[Memory] Failed to create store: %v", err))
			return nil
		}
	}
	return &StrategicMemory{
		store:   make(map[string]float64),
		storeDB: store,
	}
}

func (s *StrategicMemory) Update(target, vulnType string, success bool) {
	if target == "" || vulnType == "" {
		return
	}
	key := target + ":" + vulnType
	s.mu.Lock()
	defer s.mu.Unlock()
	if success {
		s.store[key] += 0.1
		if s.store[key] > 1.0 {
			s.store[key] = 1.0
		}
	} else {
		s.store[key] -= 0.05
		if s.store[key] < 0.0 {
			s.store[key] = 0.0
		}
	}
}

func (s *StrategicMemory) GetProb(target, vulnType string) float64 {
	if target == "" || vulnType == "" {
		return 0.5
	}
	key := target + ":" + vulnType
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.store[key]; ok {
		return p
	}
	return 0.5
}

func (s *StrategicMemory) GetAll() map[string]float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]float64, len(s.store))
	for k, v := range s.store {
		result[k] = v
	}
	return result
}

type RecallTool struct {
	store *MemoryStore
}

func NewRecallTool(store *MemoryStore) *RecallTool {
	return &RecallTool{store: store}
}

func (r *RecallTool) InjectInitial(targets []string) string {
	if r.store == nil || len(targets) == 0 {
		return ""
	}
	var lines []string
	for _, t := range targets {
		key := "outcome:" + t + ":"
		r.store.WithKeyPrefix(key, func(k string, v interface{}) {
			if po, ok := v.(PayloadOutcome); ok {
				status := "fail"
				if po.Success {
					status = "success"
				}
				lines = append(lines, fmt.Sprintf("Memory[%s]: %s -> %s (%s)", t, po.VulnType, po.Payload, status))
			}
		})
	}
	if len(lines) == 0 {
		return ""
	}
	limit := 10
	if len(lines) > limit {
		lines = lines[:limit]
	}
	return "PREVIOUS FINDINGS:\n" + strings.Join(lines, "\n")
}

var (
	globalMu            sync.RWMutex
	globalStrategic     *StrategicMemory
	globalStrategicOnce sync.Once
)

func GetGlobal() *StrategicMemory {
	globalStrategicOnce.Do(func() {
		store, err := NewMemoryStore(Config{})
		if err != nil {
			logger.Error(fmt.Sprintf("[Memory] Failed to create global store: %v", err))
			return
		}
		globalMu.Lock()
		globalStrategic = NewStrategicMemory(store)
		globalMu.Unlock()
	})
	globalMu.RLock()
	got := globalStrategic
	globalMu.RUnlock()
	return got
}

func ResetGlobal() {
	globalMu.Lock()
	globalStrategic = nil
	globalMu.Unlock()
	globalStrategicOnce = sync.Once{}
}

func (s *StrategicMemory) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.store)
}

func (s *StrategicMemory) UnmarshalJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result map[string]float64
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	s.store = result
	return nil
}

type ProcessMemoryReader struct{}

func NewProcessMemoryReader(maxReads int, timeout time.Duration) *ProcessMemoryReader {
	return nil
}

func (r *ProcessMemoryReader) ReadProcessMemory(pid int, addr uint64, size int) ([]byte, error) {
	return nil, fmt.Errorf("process memory reading disabled: requires explicit authorization and elevated privileges")
}

func (r *ProcessMemoryReader) SafeReadProcesses(pids []int, addr uint64, size int) map[int][]byte {
	logger.Info("[Memory] Process memory reading disabled for security")
	return make(map[int][]byte)
}
