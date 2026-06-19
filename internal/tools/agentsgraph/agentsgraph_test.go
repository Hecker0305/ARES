package agentsgraph

import (
	"encoding/json"
	"testing"

	"github.com/ares/engine/internal/tools"
)

func TestNewToolHandler(t *testing.T) {
	h := NewToolHandler(nil)
	if h == nil {
		t.Fatal("NewToolHandler(nil) returned nil")
	}
	if h.llm != nil {
		t.Fatal("expected nil llm client")
	}
}

func TestToolHandler_RunSubAgents_NilReceiver(t *testing.T) {
	var h *ToolHandler
	result := h.RunSubAgents(nil, nil)
	if result.Error != "nil ToolHandler" {
		t.Errorf("expected nil ToolHandler error, got %q", result.Error)
	}
}

func TestToolHandler_RunSubAgents_Success(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`{"name":"scanner","targets":["a.com","b.com"],"task":"scan for vulns"}`)
	result := h.RunSubAgents(params, nil)
	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.Output == "" {
		t.Fatal("expected non-empty output")
	}
}

func TestToolHandler_RunSubAgents_BadParams(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`invalid json`)
	result := h.RunSubAgents(params, nil)
	if result.Error == "" {
		t.Fatal("expected error for bad params")
	}
}

func TestToolHandler_RunSubAgents_MissingFields(t *testing.T) {
	h := NewToolHandler(nil)
	tests := []struct {
		name   string
		params json.RawMessage
	}{
		{"empty name", json.RawMessage(`{"name":"","targets":["x"],"task":"t"}`)},
		{"empty task", json.RawMessage(`{"name":"n","targets":["x"],"task":""}`)},
		{"empty name and empty task", json.RawMessage(`{"name":"","targets":["x"],"task":""}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := h.RunSubAgents(tc.params, nil)
			if result.Error == "" {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestToolHandler_RunSubAgents_StoresAgent(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`{"name":"agent-1","targets":["x.com"],"task":"test"}`)
	h.RunSubAgents(params, nil)
	key := "agent-1-0"
	val, ok := h.agents.Load(key)
	if !ok {
		t.Fatal("expected agent to be stored")
	}
	result := val.(*SubAgentResult)
	if result.Status != "running" {
		t.Errorf("expected 'running', got %v", result.Status)
	}
}

func TestToolHandler_RunSubAgents_NilParams(t *testing.T) {
	h := NewToolHandler(nil)
	result := h.RunSubAgents(nil, nil)
	if result.Error == "" {
		t.Fatal("expected error for nil params")
	}
}

func TestToolHandler_RunSubAgents_ToolResultType(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`{"name":"n","targets":["x"],"task":"t"}`)
	result := h.RunSubAgents(params, nil)
	var tr tools.ToolResult = result
	if tr.Output == "" && tr.Error != "" {
		t.Fatal("expected ToolResult with output")
	}
	if tr.Done {
		t.Fatal("expected Done to be false")
	}
}

func TestToolHandler_CombineResults_NilReceiver(t *testing.T) {
	var h *ToolHandler
	result := h.CombineResults(nil, nil)
	if result.Error != "nil ToolHandler" {
		t.Errorf("expected nil ToolHandler error, got %q", result.Error)
	}
}

func TestToolHandler_CombineResults_Success(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`{"results":["result1","result2","result3"]}`)
	result := h.CombineResults(params, nil)
	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	expected := "result1\nresult2\nresult3"
	if result.Output != expected {
		t.Errorf("expected %q, got %q", expected, result.Output)
	}
}

func TestToolHandler_CombineResults_EmptyResults(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`{"results":[]}`)
	result := h.CombineResults(params, nil)
	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.Output != "" {
		t.Errorf("expected empty output, got %q", result.Output)
	}
}

func TestToolHandler_CombineResults_BadParams(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`not json`)
	result := h.CombineResults(params, nil)
	if result.Error == "" {
		t.Fatal("expected error for bad params")
	}
}

func TestToolHandler_CombineResults_NilParams(t *testing.T) {
	h := NewToolHandler(nil)
	result := h.CombineResults(nil, nil)
	if result.Error == "" {
		t.Fatal("expected error for nil params")
	}
}

func TestToolHandler_CombineResults_SingleResult(t *testing.T) {
	h := NewToolHandler(nil)
	params := json.RawMessage(`{"results":["only"]}`)
	result := h.CombineResults(params, nil)
	if result.Output != "only" {
		t.Errorf("expected 'only', got %q", result.Output)
	}
}

func TestToolHandler_EmptySyncMap(t *testing.T) {
	h := NewToolHandler(nil)
	count := 0
	h.agents.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected empty agents map, got %d entries", count)
	}
}
