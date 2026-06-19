package memory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ares/engine/internal/logger"
)

const maxMemoryFileSize = 100 << 20 // 100 MB

type JSONMemoryStore struct {
	mu       sync.RWMutex
	filePath string
	data     map[string]jsonMemoryEntry
}

type jsonMemoryEntry struct {
	SuccessCount int      `json:"success_count"`
	AttemptCount int      `json:"attempt_count"`
	Probability  float64  `json:"probability"`
	TopPayloads  []string `json:"top_payloads,omitempty"`
}

func NewJSONMemoryStore(path string) *JSONMemoryStore {
	if path == "" {
		path = filepath.Join(os.TempDir(), "ares_memory.json")
	}
	s := &JSONMemoryStore{
		filePath: path,
		data:     make(map[string]jsonMemoryEntry),
	}
	s.load()
	return s
}

func (s *JSONMemoryStore) RecordOutcome(framework, vulnType, payload string, success bool) {
	key := framework + "|" + vulnType
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.data[key]
	entry.AttemptCount++
	if success {
		entry.SuccessCount++
	}
	if entry.AttemptCount > 0 {
		entry.Probability = float64(entry.SuccessCount) / float64(entry.AttemptCount)
	}
	if success && payload != "" {
		exists := false
		for _, p := range entry.TopPayloads {
			if p == payload {
				exists = true
				break
			}
		}
		if !exists {
			entry.TopPayloads = append([]string{payload}, entry.TopPayloads...)
			if len(entry.TopPayloads) > 20 {
				entry.TopPayloads = entry.TopPayloads[:20]
			}
		}
	}
	s.data[key] = entry
	s.save()
}

func (s *JSONMemoryStore) GetProbability(framework, vulnType string) float64 {
	key := framework + "|" + vulnType
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.data[key]
	if !ok || entry.AttemptCount == 0 {
		return 0.3
	}
	return entry.Probability
}

func (s *JSONMemoryStore) GetTopPayloads(framework, vulnType string, limit int) []string {
	key := framework + "|" + vulnType
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.data[key]
	if !ok {
		return nil
	}
	if limit <= 0 || limit > len(entry.TopPayloads) {
		limit = len(entry.TopPayloads)
	}
	return entry.TopPayloads[:limit]
}

func (s *JSONMemoryStore) load() {
	info, err := os.Stat(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error(fmt.Sprintf("[JSONMemory] Failed to stat %s: %v", s.filePath, err))
		}
		return
	}
	if info.Size() > maxMemoryFileSize {
		logger.Info(fmt.Sprintf("[JSONMemory] File %s is too large (%d bytes, max %d)", s.filePath, info.Size(), maxMemoryFileSize))
		return
	}
	if info.Size() == 0 {
		return
	}
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		logger.Error(fmt.Sprintf("[JSONMemory] Failed to read %s: %v", s.filePath, err))
		return
	}
	if err := json.Unmarshal(data, &s.data); err != nil {
		logger.Error(fmt.Sprintf("[JSONMemory] Failed to parse %s: %v", s.filePath, err))
		return
	}
	logger.Info(fmt.Sprintf("[JSONMemory] Loaded %d entries from %s (%d bytes)", len(s.data), s.filePath, info.Size()))
}

func (s *JSONMemoryStore) save() {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		logger.Error(fmt.Sprintf("[JSONMemory] Failed to marshal: %v", err))
		return
	}
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Error(fmt.Sprintf("[JSONMemory] Failed to create dir %s: %v", dir, err))
		return
	}
	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		logger.Error(fmt.Sprintf("[JSONMemory] Failed to write %s: %v", s.filePath, err))
	}
}
