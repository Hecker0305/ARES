package agent_test

import (
	"context"
	"testing"

	"github.com/ares/engine/internal/agent"
	"github.com/ares/engine/internal/llm"
)

func BenchmarkRunWithContext(b *testing.B) {
	client, err := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	if err != nil {
		b.Skip("llm client creation failed:", err)
	}
	a := agent.NewAgent("bench-scan", "benchmark.test", client)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.RunWithContext(ctx, 1)
	}
}

func BenchmarkExecuteTool(b *testing.B) {
	client, err := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	if err != nil {
		b.Skip("llm client creation failed:", err)
	}
	a := agent.NewAgent("bench-tool", "bench.target", client)
	finding := agent.Finding{
		ID:              "BENCH-001",
		Title:           "SQL Injection",
		Description:     "SQL injection in login parameter",
		Endpoint:        "/api/login",
		CVSSScore:       9.8,
		Confidence:      0.95,
		PoCCode:         "' OR '1'='1' -- ",
		ExtractionProof: "admin|*|admin|*|",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.AddVulnerability(finding)
		_ = a.GetVulnerabilities()
		_ = a.GetSkill("sqli-auth-bypass")
	}
}
