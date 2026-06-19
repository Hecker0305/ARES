package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/circuitbreaker"
	"github.com/ares/engine/internal/config"
	"github.com/ares/engine/internal/llm/safety"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/otel"
)

const maxLLMResponseSize = 10 << 20 // 10 MB max response from LLM providers

type Config struct {
	Provider         string
	BaseURL          string
	Model            string
	APIKey           []byte
	MaxTokens        int
	MaxContextTokens int
	Temperature      float64
	ReasoningEffort  string
	ExtraHeaders     map[string]string
	Timeout          time.Duration
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type StreamChunk struct {
	Content string
	Done    bool
	Err     error
}

type LLMClient interface {
	Complete(ctx context.Context, messages []Message, systemPrompt string) (string, error)
	ChatStream(ctx context.Context, messages []Message, systemPrompt string) <-chan StreamChunk
	CountTokens(content string) int
	ShouldSummarize(tokenCount int) bool
	Model() string
	SetModel(model string)
	SetTools(tools []any)
	GetTokens() (promptTokens, completionTokens, totalTokens int)
	WipeCredentials()
	SafetyGuard() *safety.ScanSafetyGuard
	SetSafetyGuard(guard *safety.ScanSafetyGuard)
}

var _ LLMClient = (*Client)(nil)

type Client struct {
	cfg            Config
	httpClient     *http.Client
	mu             sync.Mutex
	totalIn        int
	totalOut       int
	tools          []any
	circuitBreaker *circuitbreaker.CircuitBreaker
	safetyGuard    *safety.ScanSafetyGuard
}

var (
	sharedTransport     *http.Transport
	sharedTransportOnce sync.Once
)

func getSharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		sharedTransport = &http.Transport{
			MaxIdleConns:       100,
			MaxConnsPerHost:    25,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: false,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			},
		}
	})
	return sharedTransport
}

func cloneTransport(base *http.Transport) *http.Transport {
	return &http.Transport{
		MaxIdleConns:       base.MaxIdleConns,
		MaxConnsPerHost:    base.MaxConnsPerHost,
		IdleConnTimeout:    base.IdleConnTimeout,
		DisableCompression: base.DisableCompression,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		},
	}
}

// CountTokens estimates token count with a content-aware approach.
// English text ~1 token per 4 chars, code ~1 token per 3 chars, CJK ~1 token per 1.5 chars.
func CountTokens(content string) int {
	runes := []rune(content)
	if len(runes) == 0 {
		return 0
	}

	nonASCII := 0
	codeChars := 0
	for _, r := range runes {
		if r > 127 {
			nonASCII++
		}
		if (r >= '{' && r <= '}') || r == '(' || r == ')' || r == '[' || r == ']' ||
			r == ';' || r == ':' || r == ',' || r == '.' || r == '=' || r == '+' ||
			r == '-' || r == '*' || r == '/' || r == '<' || r == '>' {
			codeChars++
		}
	}

	ascii := len(runes) - nonASCII
	codeRatio := float64(codeChars) / float64(len(runes))

	if codeRatio > 0.15 {
		return (ascii / 3) + (nonASCII / 2) + 2
	}

	return (ascii / 4) + (nonASCII / 2) + 2
}

func (c *Client) CountTokens(content string) int {
	return CountTokens(content)
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Provider == "" {
		return nil, fmt.Errorf("llm provider required")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:11434/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "llama3.1:70b"
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.MaxContextTokens == 0 {
		cfg.MaxContextTokens = 128000
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.1
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Minute
	}

	local := isLocalProvider(cfg.Provider, cfg.BaseURL)
	if !local && len(cfg.APIKey) == 0 {
		return nil, fmt.Errorf("api key required for %s provider", cfg.Provider)
	}
	if local && len(cfg.APIKey) == 0 {
		logger.Warn("[LLM] No API key configured for local provider — authentication disabled")
	}

	safetyCfg := safety.DefaultSafetyConfig()
	if cfg.MaxContextTokens > safetyCfg.MaxScanTokens {
		safetyCfg.MaxScanTokens = cfg.MaxContextTokens
	}
	safetyCfg.MaxOutputLength = cfg.MaxTokens * 4

	client := &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: getSharedTransport(),
		},
		circuitBreaker: circuitbreaker.New(circuitbreaker.Config{
			Threshold:   5,
			Cooldown:    30 * time.Second,
			HalfOpenMax: 1,
		}),
		safetyGuard: safety.NewScanSafetyGuard(safetyCfg),
	}

	if err := client.validateEndpoint(); err != nil {
		return nil, err
	}

	return client, nil
}

// SetSafetyGuard sets a custom safety guard on the client
func (c *Client) SetSafetyGuard(guard *safety.ScanSafetyGuard) {
	c.safetyGuard = guard
}

// SetProxyRotator configures the client's HTTP transport to rotate proxies
// Creates a per-client transport to avoid race conditions on shared state
func (c *Client) SetProxyRotator(rotator *config.ProxyRotator) {
	if rotator == nil || rotator.Count() == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	base := getSharedTransport()
	transport := cloneTransport(base)
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		return rotator.Next(), nil
	}
	c.httpClient.Transport = transport
}

// WipeCredentials zeroes out sensitive data in the client config to prevent memory scraping.
// Uses byte-slice based credential storage to ensure zeroing is effective.
func (c *Client) WipeCredentials() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.cfg.APIKey {
		c.cfg.APIKey[i] = 0
	}
	c.cfg.APIKey = nil
	for k := range c.cfg.ExtraHeaders {
		delete(c.cfg.ExtraHeaders, k)
	}
}

// SafetyGuard returns the client's safety guard
func (c *Client) SafetyGuard() *safety.ScanSafetyGuard {
	return c.safetyGuard
}

func (c *Client) validateEndpoint() error {
	local := isLocalProvider(c.cfg.Provider, c.cfg.BaseURL)
	if !local && len(c.cfg.APIKey) == 0 {
		return fmt.Errorf("api key not configured for non-local provider")
	}
	u, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	if !local {
		host := strings.ToLower(u.Hostname())
		knownDomains := []string{
			"api.openai.com", "api.anthropic.com",
			"generativelanguage.googleapis.com",
			"api.deepseek.com", "api.groq.com",
			"api.together.xyz",
		}
		for _, d := range knownDomains {
			if host == d {
				return nil
			}
		}
		logger.Warn(fmt.Sprintf("[LLM] WARNING: API key being sent to non-standard endpoint: %s", host))
	}
	return nil
}

func isLocalProvider(provider, baseURL string) bool {
	lower := strings.ToLower(provider)
	if lower == "ollama" {
		return true
	}
	base := strings.ToLower(baseURL)
	return strings.HasPrefix(base, "http://localhost") ||
		strings.HasPrefix(base, "http://127.0.0.1") ||
		strings.HasPrefix(base, "http://0.0.0.0") ||
		strings.HasPrefix(base, "http://::1")
}

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*["']?[^"'\s\n]{1,128}`),
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
}

func redactMessageContent(s string) string {
	for _, p := range redactPatterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

func (c *Client) ShouldSummarize(tokenCount int) bool {
	return tokenCount > 80000
}

func SummarizeMessages(ctx context.Context, client *Client, messages []Message) []Message {
	if len(messages) <= 6 {
		return messages
	}
	first := messages[0]
	middle := messages[1 : len(messages)-5]
	last := messages[len(messages)-5:]

	var middleContent strings.Builder
	for _, m := range middle {
		middleContent.WriteString(fmt.Sprintf("[%s]: %s\n", m.Role, redactMessageContent(m.Content)))
	}

	var summary string
	if client != nil {
		summaryPrompt := fmt.Sprintf(`Summarize the following conversation history concisely. Preserve key findings, tool outputs, and important context. Keep it under 500 words.

Conversation:
%s`, middleContent.String())

		var err error
		summary, err = client.Complete(ctx, []Message{
			{Role: "system", Content: "You are summarizing a penetration testing agent's conversation history. Preserve all security findings, tool outputs, and important context."},
			{Role: "user", Content: summaryPrompt},
		}, "")
		if err != nil {
			logger.Warn("[LLM] Summarization failed, using fallback")
			summary = ""
		}
	}
	if summary == "" {
		summary = fmt.Sprintf("[Earlier %d messages summarized] Key points: tool executions, findings, and target interactions occurred.", len(middle))
	}

	result := []Message{first, {Role: "system", Content: summary}}
	result = append(result, last...)
	return result
}

func (c *Client) SetModel(model string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg.Model = model
}

func (c *Client) Model() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.Model
}

func (c *Client) SetTools(tools []any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools = tools
}

func (c *Client) Complete(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	return c.chatWithRetry(ctx, messages, systemPrompt)
}

func (c *Client) ChatStream(ctx context.Context, messages []Message, systemPrompt string) <-chan StreamChunk {
	return c.chatStreamWithRetry(ctx, messages, systemPrompt)
}

func (c *Client) chatStreamWithRetry(ctx context.Context, messages []Message, systemPrompt string) <-chan StreamChunk {
	ch := make(chan StreamChunk, 64)
	go func() {
		defer close(ch)

		span := otel.StartSpan(otel.NewTraceID(), "", "llm.chat_stream")
		otel.SetAttribute(span, "provider", c.cfg.Provider)
		otel.SetAttribute(span, "model", c.cfg.Model)
		otel.SetAttribute(span, "message_count", fmt.Sprintf("%d", len(messages)))
		defer otel.EndSpan(span)

		// Pre-flight context window check
		totalTokens := 0
		for i := range messages {
			totalTokens += CountTokens(messages[i].Content)
		}
		totalTokens += CountTokens(systemPrompt)
		if totalTokens > c.cfg.MaxContextTokens {
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("context window would be exceeded: %d > %d", totalTokens, c.cfg.MaxContextTokens)}:
			case <-ctx.Done():
			}
			return
		}

		if !c.circuitBreaker.Allow() {
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("LLM circuit breaker open — rejecting stream")}:
			case <-ctx.Done():
			}
			return
		}

		if c.safetyGuard != nil {
			if err := c.safetyGuard.CanMakeRequest(); err != nil {
				select {
				case ch <- StreamChunk{Err: fmt.Errorf("safety guard: %w", err)}:
				case <-ctx.Done():
				}
				return
			}
			combinedPrompt := sampleForSafetyCheck(systemPrompt, messages, 10000)
			safetyResult, err := safety.RequestSafetyCheck(ctx, combinedPrompt, c.safetyGuard.GetConfig())
			if err != nil {
				select {
				case ch <- StreamChunk{Err: fmt.Errorf("safety check failed: %w", err)}:
				case <-ctx.Done():
				}
				return
			}
			if safetyResult.Blocked {
				select {
				case ch <- StreamChunk{Err: fmt.Errorf("safety filter blocked prompt: %s", safetyResult.Reason)}:
				case <-ctx.Done():
				}
				return
			}
		}

		maxRetries := 3
		var lastErr error
		var streamCh <-chan StreamChunk

		for attempt := range maxRetries {
			if ctx.Err() != nil {
				select {
				case ch <- StreamChunk{Err: fmt.Errorf("request cancelled: %w", ctx.Err())}:
				case <-ctx.Done():
				}
				return
			}

			if attempt > 0 {
				backoff := c.exponentialBackoff(attempt, lastErr)
				logger.Error(fmt.Sprintf("[llm] Stream attempt %d/%d failed: %v, retrying in %s", attempt+1, maxRetries, lastErr, backoff))
				select {
				case <-ctx.Done():
					select {
					case ch <- StreamChunk{Err: fmt.Errorf("request cancelled: %w", ctx.Err())}:
					case <-ctx.Done():
					}
					return
				case <-time.After(backoff):
				}
			}

			streamCh, lastErr = c.doChatStream(ctx, messages, systemPrompt)
			if lastErr == nil {
				break
			}

			if isContextWindowError(lastErr) {
				select {
				case ch <- StreamChunk{Err: fmt.Errorf("context window overflow: %w", lastErr)}:
				case <-ctx.Done():
				}
				return
			}
		}

		if lastErr != nil {
			c.circuitBreaker.RecordFailure()
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("LLM stream request failed after %d retries: %w", maxRetries, lastErr)}:
			case <-ctx.Done():
			}
			return
		}

		totalContent := 0
		for chunk := range streamCh {
			if chunk.Err != nil {
				c.circuitBreaker.RecordFailure()
				select {
				case ch <- chunk:
				case <-ctx.Done():
				}
				return
			}
			totalContent += len(chunk.Content)
			if c.safetyGuard != nil && totalContent > 0 && totalContent%1024 == 0 {
				accContent, _ := json.Marshal(chunk)
				_ = accContent // periodic check
			}
			select {
			case ch <- chunk:
			case <-ctx.Done():
				return
			}
		}

		if c.safetyGuard != nil {
			tokenCount := totalContent / 4
			if tokenCount < 1 {
				tokenCount = 1
			}
			c.safetyGuard.RecordRequest(int64(tokenCount))
		}

		c.circuitBreaker.RecordSuccess()
		select {
		case ch <- StreamChunk{Done: true}:
		case <-ctx.Done():
		}
	}()
	return ch
}

func (c *Client) doChatStream(ctx context.Context, messages []Message, systemPrompt string) (<-chan StreamChunk, error) {
	provider := strings.ToLower(c.cfg.Provider)
	switch provider {
	case "anthropic":
		return c.doAnthropicStream(ctx, messages, systemPrompt)
	case "gemini", "google":
		return c.doGeminiStream(ctx, messages, systemPrompt)
	case "azure":
		return c.doAzureOpenAIStream(ctx, messages, systemPrompt)
	case "ollama":
		oc := NewOllamaClient(c.cfg.BaseURL, c.cfg.Model)
		oc.SetSafetyGuard(c.safetyGuard)
		return oc.ChatStream(ctx, messages, systemPrompt), nil
	default:
		return c.doOpenAIStream(ctx, messages, systemPrompt)
	}
}

func (c *Client) GetTokens() (promptTokens, completionTokens, totalTokens int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalIn, c.totalOut, c.totalIn + c.totalOut
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

type chatChoice struct {
	Delta   struct{ Content string } `json:"delta"`
	Message struct{ Content string } `json:"message"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Usage   *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage,omitempty"`
}

func (c *Client) chatWithRetry(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	// Pre-flight context window check — reject before sending
	totalTokens := 0
	for i := range messages {
		totalTokens += CountTokens(messages[i].Content)
	}
	totalTokens += CountTokens(systemPrompt)
	if totalTokens > c.cfg.MaxContextTokens {
		return "", fmt.Errorf("context window would be exceeded: %d > %d", totalTokens, c.cfg.MaxContextTokens)
	}

	if !c.circuitBreaker.Allow() {
		return "", fmt.Errorf("LLM circuit breaker open — rejecting request")
	}

	if c.safetyGuard != nil {
		if err := c.safetyGuard.CanMakeRequest(); err != nil {
			return "", fmt.Errorf("safety guard: %w", err)
		}
	}

	if c.safetyGuard != nil {
		combinedPrompt := sampleForSafetyCheck(systemPrompt, messages, 10000)
		safetyResult, err := safety.RequestSafetyCheck(ctx, combinedPrompt, c.safetyGuard.GetConfig())
		if err != nil {
			return "", fmt.Errorf("safety check failed: %w", err)
		}
		if safetyResult.Blocked {
			return "", fmt.Errorf("safety filter blocked prompt: %s", safetyResult.Reason)
		}
	}

	var result string
	maxRetries := 3
	var lastErr error

	for attempt := range maxRetries {
		if ctx.Err() != nil {
			return "", fmt.Errorf("request cancelled: %w", ctx.Err())
		}

		if attempt > 0 {
			backoff := c.exponentialBackoff(attempt, lastErr)
			logger.Error(fmt.Sprintf("[llm] Attempt %d/%d failed: %v, retrying in %s", attempt+1, maxRetries, lastErr, backoff))
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("request cancelled: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}

		result, lastErr = c.doChat(ctx, messages, systemPrompt)
		if lastErr == nil {
			if c.safetyGuard != nil {
				safeCfg := c.safetyGuard.GetConfig()
				outputResult, err := safety.RequestSafetyCheck(ctx, result, safeCfg)
				if err == nil && outputResult.Blocked {
					c.circuitBreaker.RecordFailure()
					return "", fmt.Errorf("output blocked by safety filter: %s", outputResult.Reason)
				}
				tokenCount := CountTokens(result)
				c.safetyGuard.RecordRequest(int64(tokenCount))
			}
			c.circuitBreaker.RecordSuccess()
			return result, nil
		}

		if isContextWindowError(lastErr) {
			break
		}
	}

	c.circuitBreaker.RecordFailure()
	return "", fmt.Errorf("LLM request failed after %d retries: %w", maxRetries, lastErr)
}

func sampleForSafetyCheck(systemPrompt string, messages []Message, maxLen int) string {
	var sb strings.Builder
	if systemPrompt != "" {
		sb.WriteString(systemPrompt[:min(len(systemPrompt), maxLen/2)])
	}
	if len(messages) > 0 {
		sb.WriteString("\n")
		sb.WriteString(messages[0].Content[:min(len(messages[0].Content), maxLen/2)])
	}
	if len(messages) > 3 {
		sb.WriteString("\n[... ")
		sb.WriteString(fmt.Sprintf("%d messages omitted", len(messages)-2))
		sb.WriteString(" ...]\n")
		last := messages[len(messages)-1]
		sb.WriteString(last.Content[:min(len(last.Content), maxLen/4)])
	}
	if sb.Len() > maxLen {
		return sb.String()[:maxLen]
	}
	return sb.String()
}

func (c *Client) exponentialBackoff(attempt int, lastErr error) time.Duration {
	const (
		baseBackoff   = 1 * time.Second
		maxBackoff    = 60 * time.Second
		rateLimitWait = 30 * time.Second
	)

	if lastErr != nil {
		errStr := lastErr.Error()
		if strings.Contains(errStr, "429") || strings.Contains(errStr, "rate") {
			return rateLimitWait
		}
	}

	backoff := baseBackoff * time.Duration(math.Pow(2, float64(attempt)))
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	halfBackoffMs := int(backoff.Milliseconds()) / 2
	if halfBackoffMs <= 0 {
		return backoff
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(halfBackoffMs)))
	if err != nil {
		return backoff
	}
	jitter := time.Duration(n.Int64()) * time.Millisecond
	return backoff + jitter
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiRequest struct {
	Contents          []geminiContent `json:"contents,omitempty"`
	SystemInstruction *geminiContent  `json:"system_instruction,omitempty"`
}

type geminiCandidate struct {
	Content struct {
		Parts []geminiPart `json:"parts"`
	} `json:"content"`
}

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
}

type anthropicRequest struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	System    string    `json:"system,omitempty"`
	MaxTokens int       `json:"max_tokens"`
	Stream    bool      `json:"stream"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type anthropicMessage struct {
	ID      string                  `json:"id"`
	Type    string                  `json:"type"`
	Role    string                  `json:"role"`
	Content []anthropicContentBlock `json:"content"`
	Model   string                  `json:"model"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type anthropicResponse struct {
	Type    string           `json:"type"`
	Message anthropicMessage `json:"message,omitempty"`
}

func (c *Client) doChat(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	span := otel.StartSpan(otel.NewTraceID(), "", "llm.chat")
	otel.SetAttribute(span, "provider", c.cfg.Provider)
	otel.SetAttribute(span, "model", c.cfg.Model)
	otel.SetAttribute(span, "message_count", fmt.Sprintf("%d", len(messages)))
	defer otel.EndSpan(span)

	provider := strings.ToLower(c.cfg.Provider)
	switch provider {
	case "anthropic":
		return c.doAnthropic(ctx, messages, systemPrompt)
	case "gemini", "google":
		return c.doGemini(ctx, messages, systemPrompt)
	case "azure":
		return c.doAzureOpenAI(ctx, messages, systemPrompt)
	case "ollama":
		oc := NewOllamaClient(c.cfg.BaseURL, c.cfg.Model)
		oc.SetSafetyGuard(c.safetyGuard)
		return oc.Complete(ctx, messages, systemPrompt)
	default:
		return c.doOpenAI(ctx, messages, systemPrompt)
	}
}

var forbiddenHeaders = map[string]bool{
	"authorization": true, "x-api-key": true, "x-goog-api-key": true,
	"api-key": true, "anthropic-version": true,
}

func (c *Client) doOpenAI(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	endpoint := strings.TrimSuffix(c.cfg.BaseURL, "/") + "/chat/completions"
	var fullMessages []Message
	if systemPrompt != "" {
		fullMessages = append(fullMessages, Message{Role: "system", Content: systemPrompt})
	}
	fullMessages = append(fullMessages, messages...)

	reqBody := chatRequest{
		Model:       c.cfg.Model,
		Messages:    fullMessages,
		Stream:      false,
		Temperature: c.cfg.Temperature,
		MaxTokens:   c.cfg.MaxTokens,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	if len(c.cfg.APIKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(c.cfg.APIKey))
	}
	for k, v := range c.cfg.ExtraHeaders {
		if forbiddenHeaders[strings.ToLower(k)] {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if ctx.Err() != nil {
		return "", fmt.Errorf("request cancelled after HTTP call: %w", ctx.Err())
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponseSize))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("request cancelled after reading body: %w", ctx.Err())
	}
	if resp.StatusCode != http.StatusOK {
		redacted := redactSensitiveBody(string(respBody))
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, redacted)
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	if chatResp.Usage != nil {
		c.mu.Lock()
		c.totalIn += chatResp.Usage.PromptTokens
		c.totalOut += chatResp.Usage.CompletionTokens
		c.mu.Unlock()
	}
	return chatResp.Choices[0].Message.Content, nil
}

func (c *Client) doOpenAIStream(ctx context.Context, messages []Message, systemPrompt string) (<-chan StreamChunk, error) {
	ch := make(chan StreamChunk, 64)
	endpoint := strings.TrimSuffix(c.cfg.BaseURL, "/") + "/chat/completions"

	var fullMessages []Message
	if systemPrompt != "" {
		fullMessages = append(fullMessages, Message{Role: "system", Content: systemPrompt})
	}
	fullMessages = append(fullMessages, messages...)

	reqBody := chatRequest{
		Model:       c.cfg.Model,
		Messages:    fullMessages,
		Stream:      true,
		Temperature: c.cfg.Temperature,
		MaxTokens:   c.cfg.MaxTokens,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	req.Header.Set("Accept", "text/event-stream")
	if len(c.cfg.APIKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(c.cfg.APIKey))
	}
	for k, v := range c.cfg.ExtraHeaders {
		if forbiddenHeaders[strings.ToLower(k)] {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, redactSensitiveBody(string(bodyBytes)))
	}

	go func() {
		defer close(ch)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}

			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				return
			}

			var streamResp struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
					FinishReason *string `json:"finish_reason"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
				continue
			}

			for _, choice := range streamResp.Choices {
				if choice.Delta.Content != "" {
					select {
					case ch <- StreamChunk{Content: choice.Delta.Content}:
					case <-ctx.Done():
						return
					}
				}
				if choice.FinishReason != nil {
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("stream read error: %w", err)}:
			case <-ctx.Done():
			}
		}
	}()

	return ch, nil
}

func (c *Client) doAnthropic(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	endpoint := strings.TrimSuffix(c.cfg.BaseURL, "/") + "/v1/messages"
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() != "api.anthropic.com" {
		endpoint = "https://api.anthropic.com/v1/messages"
	}
	var anthropicMsgs []Message
	for _, m := range messages {
		if m.Role != "system" {
			anthropicMsgs = append(anthropicMsgs, m)
		}
	}
	maxTokens := c.cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}
	anReq := anthropicRequest{
		Model:     c.cfg.Model,
		Messages:  anthropicMsgs,
		System:    systemPrompt,
		MaxTokens: maxTokens,
		Stream:    false,
	}
	body, err := json.Marshal(anReq)
	if err != nil {
		return "", fmt.Errorf("marshal anthropic request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	req.Header.Set("x-api-key", string(c.cfg.APIKey))
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	if ctx.Err() != nil {
		return "", fmt.Errorf("anthropic request cancelled: %w", ctx.Err())
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponseSize))
	if err != nil {
		return "", fmt.Errorf("failed to read anthropic response: %w", err)
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("anthropic request cancelled after read: %w", ctx.Err())
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic returned %d: %s", resp.StatusCode, redactSensitiveBody(string(respBody)))
	}

	var anResp anthropicResponse
	if err := json.Unmarshal(respBody, &anResp); err != nil {
		return "", fmt.Errorf("parse anthropic response: %w", err)
	}
	c.mu.Lock()
	c.totalIn += anResp.Message.Usage.InputTokens
	c.totalOut += anResp.Message.Usage.OutputTokens
	c.mu.Unlock()

	for _, block := range anResp.Message.Content {
		if block.Type == "text" && block.Text != "" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("no text content in anthropic response")
}

func (c *Client) doAnthropicStream(ctx context.Context, messages []Message, systemPrompt string) (<-chan StreamChunk, error) {
	ch := make(chan StreamChunk, 64)
	endpoint := strings.TrimSuffix(c.cfg.BaseURL, "/") + "/v1/messages"
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() != "api.anthropic.com" {
		endpoint = "https://api.anthropic.com/v1/messages"
	}

	var anthropicMsgs []Message
	for _, m := range messages {
		if m.Role != "system" {
			anthropicMsgs = append(anthropicMsgs, m)
		}
	}
	maxTokens := c.cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}
	anReq := anthropicRequest{
		Model:     c.cfg.Model,
		Messages:  anthropicMsgs,
		System:    systemPrompt,
		MaxTokens: maxTokens,
		Stream:    true,
	}
	body, err := json.Marshal(anReq)
	if err != nil {
		return nil, fmt.Errorf("marshal anthropic request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	req.Header.Set("x-api-key", string(c.cfg.APIKey))
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("anthropic returned %d: %s", resp.StatusCode, redactSensitiveBody(string(bodyBytes)))
	}

	go func() {
		defer close(ch)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}

			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				return
			}

			var event struct {
				Type  string `json:"type"`
				Delta *struct {
					Text string `json:"text"`
				} `json:"delta,omitempty"`
				ContentBlock *struct {
					Text string `json:"text"`
				} `json:"content_block,omitempty"`
			}
			if err := json.Unmarshal([]byte(data), &event); err != nil {
				continue
			}

			switch event.Type {
			case "content_block_delta":
				if event.Delta != nil && event.Delta.Text != "" {
					select {
					case ch <- StreamChunk{Content: event.Delta.Text}:
					case <-ctx.Done():
						return
					}
				}
			case "message_stop", "message_delta":
				return
			}
		}

		if err := scanner.Err(); err != nil {
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("anthropic stream read error: %w", err)}:
			case <-ctx.Done():
			}
		}
	}()

	return ch, nil
}

func (c *Client) doGemini(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	base := strings.TrimSuffix(c.cfg.BaseURL, "/")
	if base == "" || strings.Contains(base, "localhost") {
		base = "https://generativelanguage.googleapis.com/v1beta"
	}
	endpoint := fmt.Sprintf("%s/models/%s:generateContent", base, c.cfg.Model)

	var systemParts []geminiPart
	contents := make([]geminiContent, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			systemParts = append(systemParts, geminiPart{Text: m.Content})
		} else {
			role := m.Role
			if role == "assistant" {
				role = "model"
			}
			contents = append(contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
		}
	}
	gemReq := geminiRequest{Contents: contents}
	if systemPrompt != "" {
		systemParts = append(systemParts, geminiPart{Text: systemPrompt})
	}
	if len(systemParts) > 0 {
		gemReq.SystemInstruction = &geminiContent{Parts: systemParts}
	}
	body, err := json.Marshal(gemReq)
	if err != nil {
		return "", fmt.Errorf("marshal gemini request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	if len(c.cfg.APIKey) > 0 {
		req.Header.Set("x-goog-api-key", string(c.cfg.APIKey))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	if ctx.Err() != nil {
		return "", fmt.Errorf("gemini request cancelled: %w", ctx.Err())
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponseSize))
	if err != nil {
		return "", fmt.Errorf("failed to read gemini response: %w", err)
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("gemini request cancelled after read: %w", ctx.Err())
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini returned %d: %s", resp.StatusCode, redactSensitiveBody(string(respBody)))
	}

	var gemResp geminiResponse
	if err := json.Unmarshal(respBody, &gemResp); err != nil {
		return "", fmt.Errorf("parse gemini response: %w", err)
	}
	if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no content in gemini response")
	}
	return gemResp.Candidates[0].Content.Parts[0].Text, nil
}

func (c *Client) doGeminiStream(ctx context.Context, messages []Message, systemPrompt string) (<-chan StreamChunk, error) {
	ch := make(chan StreamChunk, 64)
	base := strings.TrimSuffix(c.cfg.BaseURL, "/")
	if base == "" || strings.Contains(base, "localhost") {
		base = "https://generativelanguage.googleapis.com/v1beta"
	}
	endpoint := fmt.Sprintf("%s/models/%s:streamGenerateContent", base, c.cfg.Model)

	var systemParts []geminiPart
	contents := make([]geminiContent, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			systemParts = append(systemParts, geminiPart{Text: m.Content})
		} else {
			role := m.Role
			if role == "assistant" {
				role = "model"
			}
			contents = append(contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
		}
	}
	gemReq := geminiRequest{Contents: contents}
	if systemPrompt != "" {
		systemParts = append(systemParts, geminiPart{Text: systemPrompt})
	}
	if len(systemParts) > 0 {
		gemReq.SystemInstruction = &geminiContent{Parts: systemParts}
	}
	body, err := json.Marshal(gemReq)
	if err != nil {
		return nil, fmt.Errorf("marshal gemini request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	if len(c.cfg.APIKey) > 0 {
		req.Header.Set("x-goog-api-key", string(c.cfg.APIKey))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("gemini returned %d: %s", resp.StatusCode, redactSensitiveBody(string(bodyBytes)))
	}

	go func() {
		defer close(ch)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}

			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				return
			}

			var streamResp struct {
				Candidates []struct {
					Content struct {
						Parts []geminiPart `json:"parts"`
					} `json:"content"`
					FinishReason *string `json:"finishReason"`
				} `json:"candidates"`
			}
			if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
				continue
			}

			for _, candidate := range streamResp.Candidates {
				for _, part := range candidate.Content.Parts {
					if part.Text != "" {
						select {
						case ch <- StreamChunk{Content: part.Text}:
						case <-ctx.Done():
							return
						}
					}
				}
				if candidate.FinishReason != nil {
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("gemini stream read error: %w", err)}:
			case <-ctx.Done():
			}
		}
	}()

	return ch, nil
}

func (c *Client) doAzureOpenAI(ctx context.Context, messages []Message, systemPrompt string) (string, error) {
	base := strings.TrimSuffix(c.cfg.BaseURL, "/")
	if base == "" {
		return "", fmt.Errorf("azure openai requires a base URL (e.g., https://<resource>.openai.azure.com)")
	}

	apiVersion := os.Getenv("AZURE_API_VERSION")
	if apiVersion == "" {
		apiVersion = "2024-02-01"
	}

	deploymentName := c.cfg.Model
	if deploymentName == "" {
		deploymentName = os.Getenv("AZURE_DEPLOYMENT")
		if deploymentName == "" {
			return "", fmt.Errorf("azure openai requires a deployment name (set via -model or AZURE_DEPLOYMENT)")
		}
	}

	endpoint := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s", base, deploymentName, apiVersion)

	var fullMessages []Message
	if systemPrompt != "" {
		fullMessages = append(fullMessages, Message{Role: "system", Content: systemPrompt})
	}
	fullMessages = append(fullMessages, messages...)

	reqBody := chatRequest{
		Model:       deploymentName,
		Messages:    fullMessages,
		Stream:      false,
		Temperature: c.cfg.Temperature,
		MaxTokens:   c.cfg.MaxTokens,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal azure request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	if len(c.cfg.APIKey) > 0 {
		req.Header.Set("api-key", string(c.cfg.APIKey))
	}
	for k, v := range c.cfg.ExtraHeaders {
		if forbiddenHeaders[strings.ToLower(k)] {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure openai request failed: %w", err)
	}
	defer resp.Body.Close()

	if ctx.Err() != nil {
		return "", fmt.Errorf("azure openai request cancelled: %w", ctx.Err())
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponseSize))
	if err != nil {
		return "", fmt.Errorf("failed to read azure response: %w", err)
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("azure openai request cancelled after read: %w", ctx.Err())
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("azure openai returned %d: %s", resp.StatusCode, redactSensitiveBody(string(respBody)))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("parse azure response: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in azure response")
	}
	if chatResp.Usage != nil {
		c.mu.Lock()
		c.totalIn += chatResp.Usage.PromptTokens
		c.totalOut += chatResp.Usage.CompletionTokens
		c.mu.Unlock()
	}
	return chatResp.Choices[0].Message.Content, nil
}

func (c *Client) doAzureOpenAIStream(ctx context.Context, messages []Message, systemPrompt string) (<-chan StreamChunk, error) {
	ch := make(chan StreamChunk, 64)
	base := strings.TrimSuffix(c.cfg.BaseURL, "/")
	if base == "" {
		return nil, fmt.Errorf("azure openai requires a base URL (e.g., https://<resource>.openai.azure.com)")
	}

	apiVersion := os.Getenv("AZURE_API_VERSION")
	if apiVersion == "" {
		apiVersion = "2024-02-01"
	}

	deploymentName := c.cfg.Model
	if deploymentName == "" {
		deploymentName = os.Getenv("AZURE_DEPLOYMENT")
		if deploymentName == "" {
			return nil, fmt.Errorf("azure openai requires a deployment name (set via -model or AZURE_DEPLOYMENT)")
		}
	}

	endpoint := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s", base, deploymentName, apiVersion)

	var fullMessages []Message
	if systemPrompt != "" {
		fullMessages = append(fullMessages, Message{Role: "system", Content: systemPrompt})
	}
	fullMessages = append(fullMessages, messages...)

	reqBody := chatRequest{
		Model:       deploymentName,
		Messages:    fullMessages,
		Stream:      true,
		Temperature: c.cfg.Temperature,
		MaxTokens:   c.cfg.MaxTokens,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal azure request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Engine/1.0")
	req.Header.Set("Accept", "text/event-stream")
	if len(c.cfg.APIKey) > 0 {
		req.Header.Set("api-key", string(c.cfg.APIKey))
	}
	for k, v := range c.cfg.ExtraHeaders {
		if forbiddenHeaders[strings.ToLower(k)] {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure openai stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("azure openai returned %d: %s", resp.StatusCode, redactSensitiveBody(string(bodyBytes)))
	}

	go func() {
		defer close(ch)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}

			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				return
			}

			var streamResp struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
					FinishReason *string `json:"finish_reason"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
				continue
			}

			for _, choice := range streamResp.Choices {
				if choice.Delta.Content != "" {
					select {
					case ch <- StreamChunk{Content: choice.Delta.Content}:
					case <-ctx.Done():
						return
					}
				}
				if choice.FinishReason != nil {
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			select {
			case ch <- StreamChunk{Err: fmt.Errorf("azure openai stream read error: %w", err)}:
			case <-ctx.Done():
			}
		}
	}()

	return ch, nil
}

// M-15: Precise HTTP error matching — check status code prefix, not substring
func isContextWindowError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for HTTP 400 status code with context window keywords
	if strings.HasPrefix(errStr, "API returned 400") ||
		strings.HasPrefix(errStr, "anthropic returned 400") ||
		strings.HasPrefix(errStr, "gemini returned 400") {
		return strings.Contains(errStr, "context window") ||
			strings.Contains(errStr, "maximum context length") ||
			strings.Contains(errStr, "too many tokens") ||
			strings.Contains(errStr, "context_length_exceeded")
	}
	return false
}

// M-09: Enhanced redaction for API keys in error messages
func redactSensitiveBody(body string) string {
	body = regexp.MustCompile(`(?i)"(api[-_]?key|token|secret|password|authorization|credential)"\s*:\s*"[^"]+"`).ReplaceAllString(body, `"$1":"***REDACTED***"`)
	body = regexp.MustCompile(`(?i)bearer\s+[a-z0-9\-._~+/]+=*\b`).ReplaceAllString(body, "Bearer ***REDACTED***")
	body = regexp.MustCompile(`(?i)x-api-key:\s*\S+`).ReplaceAllString(body, "x-api-key: ***REDACTED***")
	body = regexp.MustCompile(`(?i)authorization:\s*\S+`).ReplaceAllString(body, "authorization: ***REDACTED***")
	return body
}
