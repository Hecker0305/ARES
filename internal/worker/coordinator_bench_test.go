package worker_test

import (
	"testing"

	aresconfig "github.com/ares/engine/internal/config"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/webhook"
	"github.com/ares/engine/internal/worker"
)

func BenchmarkNewCoordinator(b *testing.B) {
	cfg := aresconfig.Default()
	client, err := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	if err != nil {
		b.Skip("llm client creation failed:", err)
	}
	whMgr := webhook.NewWebhookManager("")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := worker.NewCoordinator(3, client, "report.txt", "text", nil, nil, &cfg, whMgr)
		if c == nil {
			b.Fatal("coordinator is nil")
		}
	}
}

func BenchmarkExecuteScanPlan(b *testing.B) {
	cfg := aresconfig.Default()
	client, err := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	if err != nil {
		b.Skip("llm client creation failed:", err)
	}
	whMgr := webhook.NewWebhookManager("")
	c := worker.NewCoordinator(3, client, "report.txt", "text", nil, nil, &cfg, whMgr)
	if c == nil {
		b.Fatal("coordinator is nil")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c
	}
}
