package llm

import (
	"context"
	"testing"
)

func TestNewClient_OpenAI(t *testing.T) {
	client, err := NewClient(Config{
		Provider: "openai",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "gpt-4",
		APIKey:   []byte("test-key"),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
	if client.circuitBreaker == nil {
		t.Fatal("circuit breaker should be initialized")
	}
}

func TestNewClient_Ollama(t *testing.T) {
	client, err := NewClient(Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestNewClient_MissingProvider(t *testing.T) {
	_, err := NewClient(Config{})
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestSummarizeMessages(t *testing.T) {
	messages := make([]Message, 10)
	for i := 0; i < 10; i++ {
		messages[i] = Message{Role: "user", Content: "test"}
	}
	summarized := SummarizeMessages(context.Background(), nil, messages)
	if len(summarized) >= len(messages) {
		t.Fatalf("expected fewer messages after summarization, got %d", len(summarized))
	}
}

func TestSummarizeMessages_Short(t *testing.T) {
	messages := []Message{
		{Role: "system", Content: "test"},
		{Role: "user", Content: "hello"},
	}
	summarized := SummarizeMessages(context.Background(), nil, messages)
	if len(summarized) != 2 {
		t.Fatalf("expected no summarization for short list, got %d", len(summarized))
	}
}

func TestClient_CountTokens(t *testing.T) {
	c := &Client{}
	count := c.CountTokens("hello world")
	if count <= 0 {
		t.Fatal("expected positive token count")
	}
}

func TestClient_ShouldSummarize(t *testing.T) {
	c := &Client{}
	if c.ShouldSummarize(100) {
		t.Fatal("should not summarize at 100 tokens")
	}
	if !c.ShouldSummarize(80001) {
		t.Fatal("should summarize at 80001 tokens")
	}
}

func TestConfigDefaults(t *testing.T) {
	client, err := NewClient(Config{
		Provider: "ollama",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client.cfg.MaxTokens == 0 {
		t.Fatal("MaxTokens should default")
	}
	if client.cfg.MaxContextTokens == 0 {
		t.Fatal("MaxContextTokens should default")
	}
}
