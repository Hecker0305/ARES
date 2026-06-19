package architectural

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

// L1 — LLM Fine-Tuning Pipeline
type FineTuningPipeline struct {
	mu          sync.Mutex
	dataset     []TrainingExample
	modelName   string
	providerAPI string
}

type TrainingExample struct {
	Prompt     string  `json:"prompt"`
	Completion string  `json:"completion"`
	Correct    bool    `json:"correct"`
	Confidence float64 `json:"confidence"`
}

func NewFineTuningPipeline(modelName, apiURL string) *FineTuningPipeline {
	return &FineTuningPipeline{
		dataset:     make([]TrainingExample, 0),
		modelName:   modelName,
		providerAPI: apiURL,
	}
}

func (f *FineTuningPipeline) AddExample(prompt, completion string, correct bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dataset = append(f.dataset, TrainingExample{
		Prompt:     prompt,
		Completion: completion,
		Correct:    correct,
		Confidence: 1.0,
	})
}

func (f *FineTuningPipeline) ExportDataset(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.MarshalIndent(f.dataset, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dataset: %w", err)
	}
	return fmt.Errorf("export to %s: %d examples", path, len(data))
}

func (f *FineTuningPipeline) DatasetSize() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dataset)
}

// L2 — Adversarial ML Detection
type AdversarialDetector struct {
	sensitivity float64
}

func NewAdversarialDetector() *AdversarialDetector {
	return &AdversarialDetector{sensitivity: 0.7}
}

func (a *AdversarialDetector) DetectPromptInjection(input string) AdversarialScore {
	score := AdversarialScore{Input: input}

	patterns := []string{
		"ignore previous", "forget", "disregard", "new prompt",
		"you are not", "act as if", "pretend", "bypass",
		"DAN", "jailbreak", "system prompt", "roleplay as",
	}
	for _, p := range patterns {
		if containsIgnoreCase(input, p) {
			score.Score += 0.3
			score.Features = append(score.Features, fmt.Sprintf("pattern:%s", p))
		}
	}

	if len(input) > 1000 {
		score.Score += 0.2
		score.Features = append(score.Features, "long_input")
	}

	score.IsAdversarial = score.Score >= a.sensitivity
	return score
}

type AdversarialScore struct {
	Input         string   `json:"input"`
	Score         float64  `json:"score"`
	Features      []string `json:"features"`
	IsAdversarial bool     `json:"is_adversarial"`
}

// L3 — Formal Explainability Layer
type ExplanationEngine struct{}

func NewExplanationEngine() *ExplanationEngine {
	return &ExplanationEngine{}
}

func (e *ExplanationEngine) ExplainFinding(findingType, evidence string) map[string]interface{} {
	return map[string]interface{}{
		"finding_type": findingType,
		"confidence":   0.85 + math.Max(0, float64(len(evidence))/10000),
		"evidence_len": len(evidence),
		"explanation":  fmt.Sprintf("Classified as %s based on %d bytes of evidence", findingType, len(evidence)),
	}
}

// L4 — Cross-Tenant Intelligence Sharing
type PrivacyPreservingSharing struct {
	mu        sync.Mutex
	bloom     []bool
	numHashes int
	bitSize   int
}

func NewPrivacyPreservingSharing(bitSize int) *PrivacyPreservingSharing {
	return &PrivacyPreservingSharing{
		bloom:     make([]bool, bitSize),
		numHashes: 3,
		bitSize:   bitSize,
	}
}

func (p *PrivacyPreservingSharing) AddIOC(ioc string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < p.numHashes; i++ {
		h := hashIOC(ioc, i)
		p.bloom[h%p.bitSize] = true
	}
}

func (p *PrivacyPreservingSharing) CheckIOC(ioc string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < p.numHashes; i++ {
		h := hashIOC(ioc, i)
		if !p.bloom[h%p.bitSize] {
			return false
		}
	}
	return true
}

// L5 — Scan Deduplication
type ScanCache struct {
	mu    sync.Mutex
	cache map[string]CacheEntry
	ttl   time.Duration
}

type CacheEntry struct {
	TargetHash string        `json:"target_hash"`
	ResultHash string        `json:"result_hash"`
	CachedAt   time.Time     `json:"cached_at"`
	TTL        time.Duration `json:"ttl"`
}

func NewScanCache(ttl time.Duration) *ScanCache {
	return &ScanCache{
		cache: make(map[string]CacheEntry),
		ttl:   ttl,
	}
}

func (s *ScanCache) Get(targetHash string) *CacheEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[targetHash]
	if !ok || time.Since(entry.CachedAt) > s.ttl {
		delete(s.cache, targetHash)
		return nil
	}
	return &entry
}

func (s *ScanCache) Set(targetHash, resultHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[targetHash] = CacheEntry{
		TargetHash: targetHash,
		ResultHash: resultHash,
		CachedAt:   time.Now(),
		TTL:        s.ttl,
	}
}

func hashIOC(ioc string, seed int) int {
	h := 0
	for _, c := range ioc {
		h = h*31 + int(c) + seed
	}
	if h < 0 {
		h = -h
	}
	return h
}

// L2 helpers
func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return len(s) >= len(substr) && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
