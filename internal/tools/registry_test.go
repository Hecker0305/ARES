package tools

import (
	"encoding/json"
	"testing"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
}

func TestRegisterAndDispatch(t *testing.T) {
	r := NewRegistry()
	r.Register("test_tool", func(params json.RawMessage, sc interface{}) ToolResult {
		return ToolResult{Output: "ok"}
	})
	result := r.Dispatch(ToolCall{Name: "test_tool"}, nil)
	if result.Error != "" {
		t.Errorf("expected no error, got: %s", result.Error)
	}
	if result.Output != "ok" {
		t.Errorf("expected 'ok', got: %s", result.Output)
	}
}

func TestDispatchUnknown(t *testing.T) {
	r := NewRegistry()
	result := r.Dispatch(ToolCall{Name: "nonexistent"}, nil)
	if result.Error == "" {
		t.Error("expected error for unknown tool")
	}
}

func TestToolDefs(t *testing.T) {
	r := NewRegistry()
	defs := r.ToolDefs()
	if defs == nil {
		defs = []ToolDef{}
	}
	_ = defs
}

func TestSchemaWithRecall(t *testing.T) {
	s := SchemaWithRecall()
	if s == "" {
		t.Error("SchemaWithRecall returned empty")
	}
}
