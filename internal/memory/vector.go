package memory

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type VectorFinding struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	VulnType    string    `json:"vuln_type"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
	Embedding   []float32 `json:"embedding"`
}

type VectorMemory struct {
	mu       sync.RWMutex
	findings []VectorFinding
	vocab    map[string]int
	idf      map[string]float64
	docCount int
	filePath string
	dirty    bool
}

func NewVectorMemory(dbPath string) *VectorMemory {
	vm := &VectorMemory{
		vocab:    make(map[string]int),
		idf:      make(map[string]float64),
		filePath: dbPath,
	}
	if dbPath != "" {
		os.MkdirAll(filepath.Dir(dbPath), 0750)
		vm.load()
	}
	return vm
}

func (vm *VectorMemory) Store(finding VectorFinding) error {
	if finding.Target == "" || finding.Description == "" {
		return fmt.Errorf("target and description are required")
	}
	if finding.ID == "" {
		finding.ID = uuid.New()
	}
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = time.Now()
	}

	finding.Embedding = vm.embed(finding.Description + " " + finding.Evidence + " " + strings.Join(finding.Tags, " "))

	vm.mu.Lock()
	vm.findings = append(vm.findings, finding)
	vm.docCount++
	vm.updateVocabulary(finding.Description + " " + finding.Evidence)
	vm.dirty = true
	vm.mu.Unlock()

	vm.persist()
	return nil
}

func (vm *VectorMemory) Recall(query string, topK int, vulnTypeFilter string) []VectorFinding {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if len(vm.findings) == 0 {
		return nil
	}

	queryEmbed := vm.embed(query)
	type scored struct {
		finding VectorFinding
		score   float64
	}

	var scoredFindings []scored
	for _, f := range vm.findings {
		if vulnTypeFilter != "" && !strings.EqualFold(f.VulnType, vulnTypeFilter) {
			continue
		}
		sim := cosineSimilarity(queryEmbed, f.Embedding)
		scoredFindings = append(scoredFindings, scored{f, sim})
	}

	for i := 0; i < len(scoredFindings); i++ {
		for j := i + 1; j < len(scoredFindings); j++ {
			if scoredFindings[j].score > scoredFindings[i].score {
				scoredFindings[i], scoredFindings[j] = scoredFindings[j], scoredFindings[i]
			}
		}
	}

	if topK <= 0 || topK > len(scoredFindings) {
		topK = len(scoredFindings)
	}

	result := make([]VectorFinding, topK)
	for i := 0; i < topK; i++ {
		result[i] = scoredFindings[i].finding
	}
	return result
}

func (vm *VectorMemory) RecallByVulnType(vulnType string, topK int) []VectorFinding {
	return vm.Recall(vulnType, topK, vulnType)
}

func (vm *VectorMemory) RecallByTarget(target string, topK int) []VectorFinding {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	var matched []VectorFinding
	for _, f := range vm.findings {
		if strings.Contains(strings.ToLower(f.Target), strings.ToLower(target)) {
			matched = append(matched, f)
		}
	}

	if topK > 0 && len(matched) > topK {
		matched = matched[len(matched)-topK:]
	}
	return matched
}

func (vm *VectorMemory) Count() int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return len(vm.findings)
}

func (vm *VectorMemory) SystemPromptSection(query string, topK int) string {
	findings := vm.Recall(query, topK, "")
	if len(findings) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n=== RELEVANT PAST FINDINGS (from vector memory) ===\n")
	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s on %s (confidence: %.2f)\n",
			i+1, f.Severity, f.VulnType, f.Target, f.Confidence))
		if f.Description != "" {
			sb.WriteString(fmt.Sprintf("   Description: %s\n", f.Description))
		}
		if len(f.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("   Tags: %s\n", strings.Join(f.Tags, ", ")))
		}
	}
	sb.WriteString("\nUse these past findings to inform your testing strategy.\n")
	return sb.String()
}

func (vm *VectorMemory) embed(text string) []float32 {
	tokens := tokenize(text)
	vector := make([]float32, len(vm.vocab))
	for _, token := range tokens {
		if idx, ok := vm.vocab[token]; ok {
			tf := float64(1) / float64(len(tokens))
			idf := vm.idf[token]
			vector[idx] = float32(tf * idf)
		}
	}
	return normalizeVector(vector)
}

func (vm *VectorMemory) updateVocabulary(text string) {
	tokens := tokenize(text)
	for _, token := range tokens {
		if _, ok := vm.vocab[token]; !ok {
			vm.vocab[token] = len(vm.vocab)
		}
	}
	for _, token := range tokens {
		vm.idf[token] += 1.0
	}
	for token := range vm.idf {
		vm.idf[token] = math.Log(float64(vm.docCount+1)/(vm.idf[token]+1)) + 1
	}
}

func (vm *VectorMemory) persist() {
	if vm.filePath == "" {
		return
	}
	vm.mu.RLock()
	data, err := json.MarshalIndent(vm.findings, "", "  ")
	vm.mu.RUnlock()
	if err != nil {
		logger.Error(fmt.Sprintf("[VectorMemory] Failed to marshal: %v", err))
		return
	}
	tmpPath := vm.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		logger.Error(fmt.Sprintf("[VectorMemory] Failed to write: %v", err))
		return
	}
	os.Rename(tmpPath, vm.filePath)
}

func (vm *VectorMemory) load() {
	data, err := os.ReadFile(vm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		logger.Error(fmt.Sprintf("[VectorMemory] Failed to read: %v", err))
		return
	}
	vm.mu.Lock()
	if err := json.Unmarshal(data, &vm.findings); err != nil {
		logger.Error(fmt.Sprintf("[VectorMemory] Failed to parse: %v", err))
		vm.mu.Unlock()
		return
	}
	vm.docCount = len(vm.findings)
	for _, f := range vm.findings {
		vm.updateVocabulary(f.Description + " " + f.Evidence)
	}
	vm.mu.Unlock()
}

func tokenize(text string) []string {
	text = strings.ToLower(text)
	text = strings.ReplaceAll(text, "-", " ")
	text = strings.ReplaceAll(text, "_", " ")
	text = strings.ReplaceAll(text, "/", " ")
	text = strings.ReplaceAll(text, ".", " ")

	var tokens []string
	for _, word := range strings.Fields(text) {
		cleaned := strings.Trim(word, ".,;:!?\"'()[]{}<>")
		if len(cleaned) > 2 && !isStopWord(cleaned) {
			tokens = append(tokens, cleaned)
		}
	}
	return tokens
}

func isStopWord(word string) bool {
	stopWords := map[string]bool{
		"the": true, "and": true, "for": true, "are": true, "but": true,
		"not": true, "you": true, "all": true, "can": true, "had": true,
		"her": true, "was": true, "one": true, "our": true, "out": true,
		"has": true, "have": true, "been": true, "from": true, "this": true,
		"that": true, "with": true, "will": true, "each": true, "make": true,
		"like": true, "just": true, "over": true, "such": true, "than": true,
		"them": true, "very": true, "when": true, "come": true, "here": true,
		"also": true, "into": true, "more": true, "some": true, "what": true,
		"which": true, "their": true, "there": true, "about": true, "after": true,
	}
	return stopWords[word]
}

func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

func normalizeVector(v []float32) []float32 {
	var norm float64
	for _, val := range v {
		norm += float64(val) * float64(val)
	}
	if norm == 0 {
		return v
	}
	norm = math.Sqrt(norm)
	result := make([]float32, len(v))
	for i, val := range v {
		result[i] = float32(float64(val) / norm)
	}
	return result
}
