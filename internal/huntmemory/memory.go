package huntmemory

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

const (
	MaxMemoryBytes = 10 * 1024 * 1024
	MaxBackups     = 3
)

type Technique struct {
	Pattern   string    `json:"pattern"`
	Technique string    `json:"technique"`
	Success   bool      `json:"success"`
	Timestamp time.Time `json:"timestamp"`
	Target    string    `json:"target,omitempty"`
	VulnType  string    `json:"vuln_type,omitempty"`
}

type Session struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Findings  int       `json:"findings"`
}

type HuntMemory struct {
	mu         sync.RWMutex
	techniques []Technique
	findings   []Technique
	sessions   map[string]*Session
	memoryPath string
	bytesUsed  int
	closed     bool
}

func New(memoryPath string) (*HuntMemory, error) {
	absPath, err := filepath.Abs(memoryPath)
	if err != nil {
		return nil, fmt.Errorf("invalid memory path: %w", err)
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create memory directory: %w", err)
	}

	hm := &HuntMemory{
		techniques: make([]Technique, 0),
		findings:   make([]Technique, 0),
		sessions:   make(map[string]*Session),
		memoryPath: absPath,
	}

	if err := hm.Load(); err != nil {
		logger.Warn("Failed to load hunt memory, starting fresh", logger.Fields{"path": absPath, "error": err.Error()})
	}

	return hm, nil
}

func (hm *HuntMemory) Remember(pattern string, technique string, success bool) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	t := Technique{
		Pattern:   pattern,
		Technique: technique,
		Success:   success,
		Timestamp: time.Now(),
	}

	hm.techniques = append(hm.techniques, t)

	entry, _ := json.Marshal(t)
	hm.bytesUsed += len(entry)

	logger.Debug("Hunt memory updated", logger.Fields{"pattern": pattern, "success": success})

	if hm.bytesUsed >= MaxMemoryBytes {
		hm.rotateLocked()
	}
}

func (hm *HuntMemory) RememberFinding(f Technique) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	f.Timestamp = time.Now()
	hm.findings = append(hm.findings, f)

	entry, _ := json.Marshal(f)
	hm.bytesUsed += len(entry)

	logger.Debug("Finding logged to hunt memory", logger.Fields{"target": f.Target, "vuln_type": f.VulnType})

	if hm.bytesUsed >= MaxMemoryBytes {
		hm.rotateLocked()
	}
}

func (hm *HuntMemory) Recall(target string, vulnType string) []Technique {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var results []Technique
	lowerTarget := strings.ToLower(target)
	lowerVulnType := strings.ToLower(vulnType)

	for _, t := range hm.techniques {
		matchTarget := lowerTarget == "" || strings.Contains(strings.ToLower(t.Target), lowerTarget)
		matchVuln := lowerVulnType == "" || strings.EqualFold(t.VulnType, lowerVulnType)
		if matchTarget && matchVuln {
			results = append(results, t)
		}
	}

	for _, f := range hm.findings {
		matchTarget := lowerTarget == "" || strings.Contains(strings.ToLower(f.Target), lowerTarget)
		matchVuln := lowerVulnType == "" || strings.EqualFold(f.VulnType, lowerVulnType)
		if matchTarget && matchVuln {
			results = append(results, f)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	return results
}

func (hm *HuntMemory) GetAll() struct {
	Techniques []Technique
	Findings   []Technique
	Sessions   []*Session
} {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	sessions := make([]*Session, 0, len(hm.sessions))
	for _, s := range hm.sessions {
		sessions = append(sessions, s)
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartTime.After(sessions[j].StartTime)
	})

	techCopy := make([]Technique, len(hm.techniques))
	copy(techCopy, hm.techniques)

	findCopy := make([]Technique, len(hm.findings))
	copy(findCopy, hm.findings)

	return struct {
		Techniques []Technique
		Findings   []Technique
		Sessions   []*Session
	}{
		Techniques: techCopy,
		Findings:   findCopy,
		Sessions:   sessions,
	}
}

func (hm *HuntMemory) Load() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if hm.closed {
		return fmt.Errorf("hunt memory is closed")
	}

	f, err := os.Open(hm.memoryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to open memory file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var t Technique
		if err := json.Unmarshal([]byte(line), &t); err != nil {
			logger.Debug("Skipping malformed memory entry", logger.Fields{"error": err.Error()})
			continue
		}

		hm.techniques = append(hm.techniques, t)
		hm.bytesUsed += len(line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading memory file: %w", err)
	}

	logger.Info("Hunt memory loaded", logger.Fields{"path": hm.memoryPath, "entries": len(hm.techniques), "bytes": hm.bytesUsed})
	return nil
}

func (hm *HuntMemory) Save() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	return hm.saveLocked()
}

func (hm *HuntMemory) saveLocked() error {
	if hm.closed {
		return fmt.Errorf("hunt memory is closed")
	}

	tmpPath := hm.memoryPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temp memory file: %w", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, t := range hm.techniques {
		data, err := json.Marshal(t)
		if err != nil {
			logger.Debug("Failed to marshal technique", logger.Fields{"error": err.Error()})
			continue
		}
		if _, err := writer.Write(data); err != nil {
			return fmt.Errorf("failed to write memory entry: %w", err)
		}
		if _, err := writer.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}

	for _, f := range hm.findings {
		data, err := json.Marshal(f)
		if err != nil {
			continue
		}
		if _, err := writer.Write(data); err != nil {
			return fmt.Errorf("failed to write finding entry: %w", err)
		}
		if _, err := writer.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, hm.memoryPath); err != nil {
		return fmt.Errorf("failed to rename memory file: %w", err)
	}

	return nil
}

func (hm *HuntMemory) rotateLocked() {
	logger.Warn("Hunt memory capacity reached, rotating", logger.Fields{"bytes": hm.bytesUsed})

	backupDir := filepath.Dir(hm.memoryPath)
	baseName := filepath.Base(hm.memoryPath)

	for i := MaxBackups - 1; i >= 1; i-- {
		oldPath := filepath.Join(backupDir, fmt.Sprintf("%s.bak.%d", baseName, i))
		newPath := filepath.Join(backupDir, fmt.Sprintf("%s.bak.%d", baseName, i+1))

		if _, err := os.Stat(oldPath); err == nil {
			if err := os.Rename(oldPath, newPath); err != nil {
				logger.Error("Failed to rotate backup", logger.Fields{"from": oldPath, "to": newPath, "error": err.Error()})
			}
		}
	}

	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s.bak.1", baseName))
	if err := os.Rename(hm.memoryPath, backupPath); err != nil {
		logger.Error("Failed to create backup", logger.Fields{"error": err.Error()})
	}

	hm.techniques = nil
	hm.findings = nil
	hm.bytesUsed = 0

	logger.Info("Hunt memory rotated", logger.Fields{"backup": backupPath})
}

func (hm *HuntMemory) Close() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if hm.closed {
		return
	}

	if err := hm.saveLocked(); err != nil {
		logger.Error("Failed to save hunt memory on close", logger.Fields{"error": err.Error()})
	}

	hm.closed = true
	logger.Info("Hunt memory closed", logger.Fields{"path": hm.memoryPath})
}

func (hm *HuntMemory) Stats() map[string]interface{} {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	return map[string]interface{}{
		"techniques":   len(hm.techniques),
		"findings":     len(hm.findings),
		"sessions":     len(hm.sessions),
		"bytes_used":   hm.bytesUsed,
		"bytes_max":    MaxMemoryBytes,
		"memory_path":  hm.memoryPath,
		"backup_count": MaxBackups,
	}
}

func (hm *HuntMemory) StartSession(id string, target string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.sessions[id] = &Session{
		ID:        id,
		Target:    target,
		StartTime: time.Now(),
	}
}

func (hm *HuntMemory) EndSession(id string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if s, ok := hm.sessions[id]; ok {
		s.EndTime = time.Now()
		s.Findings = len(hm.findings)
	}
}
