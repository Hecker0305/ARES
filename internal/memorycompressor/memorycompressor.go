package memorycompressor

import (
	"github.com/ares/engine/internal/uuid"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Compressor struct {
	mu        sync.Mutex
	maxTokens int
	history   []MemoryBlock
	locked    bool
}

type MemoryBlock struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	Content   []byte    `json:"-"`
	Summary   string    `json:"summary"`
	Tokens    int       `json:"tokens"`
	CreatedAt time.Time `json:"created_at"`
	sensitive bool
}

func New(maxTokens int) *Compressor {
	if maxTokens <= 0 {
		maxTokens = 100000
	}
	return &Compressor{maxTokens: maxTokens}
}

func estimateTokens(content string) int {
	runes := []rune(content)
	if len(runes) == 0 {
		return 0
	}
	nonASCII := 0
	for _, r := range runes {
		if r > 127 {
			nonASCII++
		}
	}
	ascii := len(runes) - nonASCII
	return (ascii / 4) + (nonASCII / 2) + 2
}

func (mc *Compressor) Add(source, content string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	block := MemoryBlock{
		ID:        uuid.New(),
		Source:    source,
		Content:   []byte(content),
		Tokens:    estimateTokens(content),
		CreatedAt: time.Now(),
		sensitive: isSensitiveContent(content),
	}

	if block.sensitive {
		lockMemory(block.Content)
	}

	mc.history = append(mc.history, block)
}

func (mc *Compressor) Compress() string {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	total := 0
	for _, b := range mc.history {
		total += b.Tokens
	}

	if total <= mc.maxTokens {
		return mc.joinAll()
	}

	mc.summarizeOldBlocks()
	return mc.joinAll()
}

func (mc *Compressor) summarizeOldBlocks() {
	const targetBlocks = 5
	if len(mc.history) <= targetBlocks {
		return
	}

	keep := mc.history[len(mc.history)-targetBlocks:]
	summarize := mc.history[:len(mc.history)-targetBlocks]

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[COMPRESSED: %d earlier events summarized]\n", len(summarize)))
	for _, b := range summarize {
		content := string(b.Content)
		summary := content
		if len(summary) > 100 {
			summary = summary[:100] + "..."
		}
		sb.WriteString(fmt.Sprintf("- [%s] %s\n", b.Source, summary))
		secureClear(b.Content)
	}

	summaryContent := sb.String()
	summaryBlock := MemoryBlock{
		ID:        uuid.New(),
		Source:    "compressor",
		Content:   []byte(summaryContent),
		Tokens:    estimateTokens(summaryContent),
		CreatedAt: time.Now(),
	}

	mc.history = append([]MemoryBlock{summaryBlock}, keep...)
}

func (mc *Compressor) joinAll() string {
	var sb strings.Builder
	sb.WriteString("## COMPRESSED CONTEXT\n\n")
	for _, b := range mc.history {
		sb.WriteString(fmt.Sprintf("### [%s] %s\n", b.Source, b.CreatedAt.Format(time.RFC3339)))
		sb.Write(b.Content)
		sb.WriteString("\n\n")
	}
	return sb.String()
}

func (mc *Compressor) CompressTo(maxTokens int, input string) string {
	estimated := estimateTokens(input)
	if estimated <= maxTokens {
		return input
	}
	ratio := float64(maxTokens) / float64(estimated)
	runes := []rune(input)
	keepLen := int(float64(len(runes)) * ratio)
	if keepLen > len(runes) {
		keepLen = len(runes)
	}
	if keepLen < 10 {
		keepLen = 10
	}
	return string(runes[:keepLen]) + "\n...[compressed]"
}

func (mc *Compressor) Stats() map[string]interface{} {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	totalTokens := 0
	for _, b := range mc.history {
		totalTokens += b.Tokens
	}
	return map[string]interface{}{
		"blocks":       len(mc.history),
		"total_tokens": totalTokens,
		"max_tokens":   mc.maxTokens,
		"locked":       mc.locked,
	}
}

func (mc *Compressor) Clear() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	for i := range mc.history {
		if mc.history[i].sensitive {
			secureClear(mc.history[i].Content)
			unlockMemory(mc.history[i].Content)
		}
		mc.history[i].Content = nil
	}
	mc.history = nil
}

func (mc *Compressor) LockSensitiveBlocks() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	for i := range mc.history {
		if mc.history[i].sensitive && len(mc.history[i].Content) > 0 {
			if !lockMemory(mc.history[i].Content) {
				return fmt.Errorf("failed to lock memory for block %s", mc.history[i].ID)
			}
		}
	}
	mc.locked = true
	return nil
}

func (mc *Compressor) UnlockSensitiveBlocks() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	for i := range mc.history {
		if mc.history[i].sensitive && len(mc.history[i].Content) > 0 {
			unlockMemory(mc.history[i].Content)
		}
	}
	mc.locked = false
}

func isSensitiveContent(content string) bool {
	sensitivePatterns := []string{
		"password", "secret", "token", "api_key", "apikey",
		"access_key", "secret_key", "private_key", "credential",
		"session_id", "session_token", "auth_token", "jwt",
		"cookie", "authorization", "bearer", "aws_access",
		"aws_secret", "ssh-rsa", "ssh-ed25519", "-----BEGIN",
	}
	lower := strings.ToLower(content)
	for _, pat := range sensitivePatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func secureClear(data []byte) {
	if len(data) == 0 {
		return
	}
	for i := range data {
		data[i] = 0
	}
	subtle.XORBytes(data, data, make([]byte, len(data)))
}
