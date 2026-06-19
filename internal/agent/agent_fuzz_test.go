package agent_test

import (
	"context"
	"testing"

	"github.com/ares/engine/internal/agent"
	"github.com/ares/engine/internal/llm"
)

func FuzzRunWithContext(f *testing.F) {
	seeds := []struct {
		target  string
		maxIter int
	}{
		{"example.com", 1},
		{"http://example.com", 10},
		{"'; DROP TABLE users; --", 5},
		{"<script>alert(1)</script>", 3},
		{"$(cat /etc/passwd)", 2},
		{"", 0},
		{"-1", -1},
		{string([]byte{0xff, 0xfe, 0x00}), 100},
	}
	for _, s := range seeds {
		f.Add(s.target, s.maxIter)
	}

	f.Fuzz(func(t *testing.T, target string, maxIter int) {
		client, err := llm.NewClient(llm.Config{
			Provider: "ollama",
			BaseURL:  "http://localhost:11434/v1",
			Model:    "llama3.1:70b",
		})
		if err != nil {
			t.Skip("llm client creation failed:", err)
		}
		a := agent.NewAgent("fuzz-scan", target, client)
		if a == nil {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = a.RunWithContext(ctx, maxIter)
	})
}

func FuzzExecuteTool(f *testing.F) {
	seeds := []struct {
		toolName string
		params   string
	}{
		{"finish", `{}`},
		{"terminal_execute", `{"command":"ls"}`},
		{"nonexistent", `{}`},
		{"read", `{"path":"/etc/passwd"}`},
		{"write", `{"path":"/tmp/test","content":"hello"}`},
		{"", ``},
		{"<script>", `{"x":"<script>alert(1)</script>"}`},
		{"; DROP TABLE", `{"y":"' OR '1'='1"}`},
	}
	for _, s := range seeds {
		f.Add(s.toolName, s.params)
	}

	f.Fuzz(func(t *testing.T, toolName string, params string) {
		client, err := llm.NewClient(llm.Config{
			Provider: "ollama",
			BaseURL:  "http://localhost:11434/v1",
			Model:    "llama3.1:70b",
		})
		if err != nil {
			t.Skip("llm client creation failed:", err)
		}
		a := agent.NewAgent("fuzz-tool", "target.test", client)
		if a == nil {
			return
		}

		vuln := agent.Finding{
			ID:              toolName,
			Title:           params,
			Description:     params,
			Endpoint:        toolName,
			PoCCode:         params,
			ExtractionProof: params,
		}
		a.AddVulnerability(vuln)
		_ = a.GetVulnerabilities()
		_ = a.GetSkill(toolName)
	})
}
