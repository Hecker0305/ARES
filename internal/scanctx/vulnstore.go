package scanctx

import (
	"sync"
	"time"
)

type Verdict string

const (
	VerdictVerified      Verdict = "verified"
	VerdictSuspected     Verdict = "suspected"
	VerdictFalsePositive Verdict = "false_positive"
)

type VulnEntry struct {
	ID              string
	Title           string
	Severity        Severity
	Endpoint        string
	Description     string
	Impact          string
	CVSSScore       float64
	PoCSteps        []string
	PoCCode         string
	ExtractionProof string
	EvidencePath    string
	MITRETactic     string
	MITRETechnique  string
	Confidence      float64
	Confirmed       bool
	Timestamp       time.Time
	Verdict         Verdict
}

type VulnStore struct {
	mu      sync.RWMutex
	entries map[string]*VulnEntry
}

func NewVulnStore() *VulnStore {
	return &VulnStore{
		entries: make(map[string]*VulnEntry),
	}
}

func (vs *VulnStore) Add(entry *VulnEntry) {
	if entry == nil {
		return
	}
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.entries[entry.ID] = entry
}

func (vs *VulnStore) Get(id string) *VulnEntry {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	e := vs.entries[id]
	if e == nil {
		return nil
	}
	cp := *e
	cp.PoCSteps = make([]string, len(e.PoCSteps))
	copy(cp.PoCSteps, e.PoCSteps)
	return &cp
}

func (vs *VulnStore) All() []VulnEntry {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	result := make([]VulnEntry, 0, len(vs.entries))
	for _, e := range vs.entries {
		cp := *e
		cp.PoCSteps = make([]string, len(e.PoCSteps))
		copy(cp.PoCSteps, e.PoCSteps)
		result = append(result, cp)
	}
	return result
}

func (vs *VulnStore) BySeverity(severity string) []VulnEntry {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	result := make([]VulnEntry, 0)
	for _, e := range vs.entries {
		if string(e.Severity) == severity {
			cp := *e
			cp.PoCSteps = make([]string, len(e.PoCSteps))
			copy(cp.PoCSteps, e.PoCSteps)
			result = append(result, cp)
		}
	}
	return result
}

func (vs *VulnStore) ByVerdict(verdict string) []VulnEntry {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	result := make([]VulnEntry, 0)
	for _, e := range vs.entries {
		if string(e.Verdict) == verdict {
			cp := *e
			cp.PoCSteps = make([]string, len(e.PoCSteps))
			copy(cp.PoCSteps, e.PoCSteps)
			result = append(result, cp)
		}
	}
	return result
}

func (vs *VulnStore) Count() int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return len(vs.entries)
}

func (vs *VulnStore) Remove(id string) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	delete(vs.entries, id)
}

func (vs *VulnStore) VerdictStats() map[string]int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	stats := make(map[string]int)
	for _, e := range vs.entries {
		stats[string(e.Verdict)]++
	}
	return stats
}
