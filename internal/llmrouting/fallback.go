package llmrouting

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/llm/safety"
	"github.com/ares/engine/internal/logger"
)

type FallbackClient struct {
	mu       sync.Mutex
	primary  llm.LLMClient
	fallback llm.LLMClient
	local    llm.LLMClient
	router   *Router
	model    string
}

func NewFallbackClient(primary, fallback, local llm.LLMClient, router *Router) *FallbackClient {
	return &FallbackClient{
		primary:  primary,
		fallback: fallback,
		local:    local,
		router:   router,
	}
}

func (f *FallbackClient) isRateLimited(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, "429") ||
		strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "quota exceeded") ||
		strings.Contains(msg, "insufficient_quota")
}

func (f *FallbackClient) isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return f.isRateLimited(err) ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "service unavailable") ||
		strings.Contains(msg, "internal server error") ||
		strings.Contains(msg, "502") ||
		strings.Contains(msg, "503")
}

func (f *FallbackClient) Complete(ctx context.Context, messages []llm.Message, systemPrompt string) (string, error) {
	start := time.Now()

	f.mu.Lock()
	primary := f.primary
	fallback := f.fallback
	f.mu.Unlock()

	resp, err := primary.Complete(ctx, messages, systemPrompt)
	latency := time.Since(start)

	if err == nil {
		tokens := primary.CountTokens(resp)
		f.router.TrackCost(primary.Model(), tokens, "primary")
		f.router.RecordLatency(primary.Model(), latency)
		f.router.RecordAccuracy(primary.Model(), true)
		f.mu.Lock()
		f.model = primary.Model()
		f.mu.Unlock()
		return resp, nil
	}

	if !f.isRetryable(err) {
		f.router.RecordAccuracy(primary.Model(), false)
		return resp, err
	}

	logger.Warn(fmt.Sprintf("[LLM Router] Primary failed (%v), trying fallback", err))
	f.router.RecordAccuracy(primary.Model(), false)

	if fallback != nil {
		start2 := time.Now()
		resp2, err2 := fallback.Complete(ctx, messages, systemPrompt)
		latency2 := time.Since(start2)

		if err2 == nil {
			tokens := fallback.CountTokens(resp2)
			f.router.TrackCost(fallback.Model(), tokens, "fallback")
			f.router.RecordLatency(fallback.Model(), latency2)
			f.router.RecordAccuracy(fallback.Model(), true)
			f.mu.Lock()
			f.model = fallback.Model()
			f.mu.Unlock()
			return resp2, nil
		}

		if !f.isRetryable(err2) {
			f.router.RecordAccuracy(fallback.Model(), false)
			return resp2, err2
		}

		logger.Warn(fmt.Sprintf("[LLM Router] Fallback also failed (%v), trying local", err2))
		f.router.RecordAccuracy(fallback.Model(), false)
	}

	if f.local != nil {
		resp3, err3 := f.local.Complete(ctx, messages, systemPrompt)
		if err3 == nil {
			tokens := f.local.CountTokens(resp3)
			f.router.TrackCost(f.local.Model(), tokens, "local")
			f.router.RecordAccuracy(f.local.Model(), true)
			f.mu.Lock()
			f.model = f.local.Model()
			f.mu.Unlock()
			return resp3, nil
		}
		f.router.RecordAccuracy(f.local.Model(), false)
	}

	return "", fmt.Errorf("all LLM backends failed: primary=%v fallback=%v", err, "")
}

func (f *FallbackClient) ChatStream(ctx context.Context, messages []llm.Message, systemPrompt string) <-chan llm.StreamChunk {
	f.mu.Lock()
	primary := f.primary
	f.mu.Unlock()
	return primary.ChatStream(ctx, messages, systemPrompt)
}

func (f *FallbackClient) CountTokens(content string) int {
	f.mu.Lock()
	primary := f.primary
	f.mu.Unlock()
	return primary.CountTokens(content)
}

func (f *FallbackClient) ShouldSummarize(tokenCount int) bool {
	f.mu.Lock()
	primary := f.primary
	f.mu.Unlock()
	return primary.ShouldSummarize(tokenCount)
}

func (f *FallbackClient) Model() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.model != "" {
		return f.model
	}
	return f.primary.Model()
}

func (f *FallbackClient) SetModel(model string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.model = model
}

func (f *FallbackClient) SetTools(tools []any) {
	f.mu.Lock()
	primary := f.primary
	fallback := f.fallback
	local := f.local
	f.mu.Unlock()
	primary.SetTools(tools)
	if fallback != nil {
		fallback.SetTools(tools)
	}
	if local != nil {
		local.SetTools(tools)
	}
}

func (f *FallbackClient) GetTokens() (promptTokens, completionTokens, totalTokens int) {
	f.mu.Lock()
	primary := f.primary
	f.mu.Unlock()
	return primary.GetTokens()
}

func (f *FallbackClient) WipeCredentials() {
	f.mu.Lock()
	primary := f.primary
	fallback := f.fallback
	local := f.local
	f.mu.Unlock()
	primary.WipeCredentials()
	if fallback != nil {
		fallback.WipeCredentials()
	}
	if local != nil {
		local.WipeCredentials()
	}
}

func (f *FallbackClient) SafetyGuard() *safety.ScanSafetyGuard {
	f.mu.Lock()
	primary := f.primary
	f.mu.Unlock()
	return primary.SafetyGuard()
}

func (f *FallbackClient) SetSafetyGuard(guard *safety.ScanSafetyGuard) {
	f.mu.Lock()
	primary := f.primary
	fallback := f.fallback
	local := f.local
	f.mu.Unlock()
	primary.SetSafetyGuard(guard)
	if fallback != nil {
		fallback.SetSafetyGuard(guard)
	}
	if local != nil {
		local.SetSafetyGuard(guard)
	}
}
