package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/llm/safety"
)

// ollamaChatMessage represents a message in the Ollama chat API format
type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ollamaChatRequest is the request body for Ollama /api/chat
type ollamaChatRequest struct {
	Model    string                 `json:"model"`
	Messages []ollamaChatMessage    `json:"messages"`
	Stream   bool                   `json:"stream"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

// ollamaChatResponse is a single response from Ollama /api/chat (non-streaming)
type ollamaChatResponse struct {
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	Message   struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	DoneReason string `json:"done_reason,omitempty"`
	Done       bool   `json:"done"`
	EvalCount  int    `json:"eval_count,omitempty"`
	EvalDuration int64 `json:"eval_duration,omitempty"`
}

// OllamaClient is a dedicated Ollama client using the /api/chat endpoint.
// It implements the LLMClient interface and provides proper chat-formatted requests
// with streaming support via Ollama's native API (not the OpenAI-compatible endpoint).
type OllamaClient struct {
	baseURL     string
	model       string
	httpClient  *http.Client
	mu          sync.Mutex
	totalIn     int
	totalOut    int
	safetyGuard *safety.ScanSafetyGuard
}

func NewOllamaClient(baseURL, model string) *OllamaClient {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	// Strip OpenAI-compatible /v1 path prefix — Ollama's native API is at /api/chat, not /v1/api/chat
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/v1")
	baseURL = strings.TrimRight(baseURL, "/")
	if model == "" {
		model = "qwen2.5-coder:14b"
	}
	return &OllamaClient{
		baseURL:    baseURL,
		model:      model,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *OllamaClient) buildChatMessages(messages []Message, systemPrompt string) []ollamaChatMessage {
	var chatMsgs []ollamaChatMessage
	if systemPrompt != "" {
		chatMsgs = append(chatMsgs, ollamaChatMessage{Role: "system", Content: systemPrompt})
	}
	for _, m := range messages {
		role := m.Role
		if role == "system" {
			continue
		}
		chatMsgs = append(chatMsgs, ollamaChatMessage{Role: role, Content: m.Content})
	}
	return chatMsgs
}

func (c *OllamaClient) Complete(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	chatMsgs := c.buildChatMessages(messages, systemPrompt)

	body := ollamaChatRequest{
		Model:    c.model,
		Messages: chatMsgs,
		Stream:   false,
		Options: map[string]interface{}{
			"temperature": 0.1,
			"num_predict": 4096,
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("ollama marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("ollama HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var oResp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&oResp); err != nil {
		return "", fmt.Errorf("ollama decode: %w", err)
	}

	c.mu.Lock()
	c.totalIn += len(payload)
	c.totalOut += len(oResp.Message.Content)
	c.mu.Unlock()

	return oResp.Message.Content, nil
}

func (c *OllamaClient) ChatStream(ctx context.Context, messages []Message, systemPrompt string) <-chan StreamChunk {
	ch := make(chan StreamChunk, 64)
	chatMsgs := c.buildChatMessages(messages, systemPrompt)

	body := ollamaChatRequest{
		Model:    c.model,
		Messages: chatMsgs,
		Stream:   true,
		Options: map[string]interface{}{
			"temperature": 0.1,
			"num_predict": 4096,
		},
	}

	go func() {
		defer close(ch)

		payload, err := json.Marshal(body)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("ollama marshal: %w", err)}
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/chat", bytes.NewReader(payload))
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("ollama request: %w", err)}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/x-ndjson")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("ollama stream: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			ch <- StreamChunk{Err: fmt.Errorf("ollama HTTP %d: %s", resp.StatusCode, string(bodyBytes))}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}

			line := scanner.Text()
			if line == "" {
				continue
			}

			var streamResp struct {
				Model     string `json:"model"`
				CreatedAt string `json:"created_at"`
				Message   struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
				Done bool `json:"done"`
			}
			if err := json.Unmarshal([]byte(line), &streamResp); err != nil {
				continue
			}

			if streamResp.Message.Content != "" {
				select {
				case ch <- StreamChunk{Content: streamResp.Message.Content}:
				case <-ctx.Done():
					return
				}
			}

			if streamResp.Done {
				return
			}
		}

		if err := scanner.Err(); err != nil {
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("ollama stream read error: %w", err)}:
			case <-ctx.Done():
			}
		}
	}()

	return ch
}

func (c *OllamaClient) CountTokens(content string) int {
	tokens := len(content) / 4
	if tokens < 1 {
		tokens = 1
	}
	return tokens
}

func (c *OllamaClient) ShouldSummarize(tokenCount int) bool {
	return tokenCount > 6000
}

func (c *OllamaClient) Model() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.model
}

func (c *OllamaClient) SetModel(model string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.model = model
}

func (c *OllamaClient) SetTools(tools []any) {}

func (c *OllamaClient) GetTokens() (int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalIn, c.totalOut, c.totalIn + c.totalOut
}

func (c *OllamaClient) WipeCredentials() {}

func (c *OllamaClient) SafetyGuard() *safety.ScanSafetyGuard {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.safetyGuard
}

func (c *OllamaClient) SetSafetyGuard(guard *safety.ScanSafetyGuard) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.safetyGuard = guard
}
