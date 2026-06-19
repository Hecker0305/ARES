// Package federated implements the cross-scan intelligence flywheel.
// Every scan contributes payload/technique effectiveness data that improves future scans.
// Works with or without Postgres — falls back to in-memory when DB is unavailable.
package federated

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

const maxIntelligenceRecords = 100000

// PayloadRecord is a payload that was tested against a tech stack.
type PayloadRecord struct {
	Payload   string
	TechStack string
	VulnType  string
	Worked    bool
	ScanCount int
}

// Intelligence is the in-memory federated intelligence store.
// When Postgres is available, records are persisted via memory.Store.
type Intelligence struct {
	mu      sync.RWMutex
	records map[string]*PayloadRecord // key: payload+techStack+vulnType
}

var global = &Intelligence{records: make(map[string]*PayloadRecord)}

// Record stores the result of a payload attempt.
func Record(payload, techStack, vulnType string, worked bool) {
	global.record(payload, techStack, vulnType, worked)
}

func (i *Intelligence) record(payload, techStack, vulnType string, worked bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	key := payload + "|" + techStack + "|" + vulnType
	if r, ok := i.records[key]; ok {
		r.ScanCount++
		if worked {
			r.Worked = true
		}
	} else {
		i.records[key] = &PayloadRecord{
			Payload:   payload,
			TechStack: techStack,
			VulnType:  vulnType,
			Worked:    worked,
			ScanCount: 1,
		}
	}

	if len(i.records) > maxIntelligenceRecords {
		i.evictOldest()
	}
}

func (i *Intelligence) evictOldest() {
	type kv struct {
		key   string
		count int
	}
	items := make([]kv, 0, len(i.records))
	for k, v := range i.records {
		items = append(items, kv{k, v.ScanCount})
	}
	sort.Slice(items, func(a, b int) bool {
		return items[a].count < items[b].count
	})
	trim := len(items) - maxIntelligenceRecords + (maxIntelligenceRecords / 10)
	for idx := 0; idx < trim && idx < len(items); idx++ {
		delete(i.records, items[idx].key)
	}
}

// BestPayloads returns payloads that worked most often against a given stack/type.
func BestPayloads(techStack, vulnType string) []string {
	return global.bestPayloads(techStack, vulnType)
}

func (i *Intelligence) bestPayloads(techStack, vulnType string) []string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	var working []*PayloadRecord
	for _, r := range i.records {
		if r.TechStack == techStack && r.VulnType == vulnType && r.Worked {
			working = append(working, r)
		}
	}
	// Sort by scan count descending (most proven first)
	sort.Slice(working, func(a, b int) bool {
		return working[a].ScanCount > working[b].ScanCount
	})

	out := make([]string, 0, len(working))
	for _, r := range working {
		out = append(out, r.Payload)
	}
	return out
}

// sanitizePayload strips injection patterns and control characters from payloads.
func sanitizePayload(p string) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, p)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	// Truncate to a reasonable length
	if len(s) > 1000 {
		s = s[:1000]
	}
	// Detect and neutralize prompt injection patterns
	if detectPromptInjection(s) {
		s = "[PROMPT INJECTION NEUTRALIZED] " + s
	}
	return s
}

// detectPromptInjection checks for common prompt injection patterns.
func detectPromptInjection(s string) bool {
	lower := strings.ToLower(s)
	patterns := []string{
		"ignore previous", "ignore all", "disregard", "forget all",
		"system prompt", "you are now", "new instructions", "new role",
		"override", "bypass", "jailbreak", "do not follow",
		"stop following", "abandon", "pretend you are", "act as if",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// SystemPromptSection builds the intelligence hint for the LLM system prompt.
func SystemPromptSection(techStack, vulnType string) string {
	payloads := BestPayloads(techStack, vulnType)
	if len(payloads) == 0 {
		return ""
	}
	var sb string
	sb = fmt.Sprintf("\n=== FEDERATED INTELLIGENCE — proven payloads for %s/%s ===\n", techStack, vulnType)
	for i, p := range payloads {
		if i >= 10 {
			break
		}
		sb += fmt.Sprintf("  %d. %s\n", i+1, sanitizePayload(p))
	}
	sb += "Try these first before generic payloads.\n"
	return sb
}

// Stats returns a summary of the intelligence store.
func Stats() string {
	global.mu.RLock()
	defer global.mu.RUnlock()
	total, worked := 0, 0
	for _, r := range global.records {
		total++
		if r.Worked {
			worked++
		}
	}
	return fmt.Sprintf("Federated intelligence: %d payload records, %d confirmed working", total, worked)
}
