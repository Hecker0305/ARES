package tools

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

func TestRegistry_RegisterAndDispatch(t *testing.T) {
	r := NewRegistry()
	var mu sync.Mutex
	called := false

	r.Register("test_tool", func(params json.RawMessage, sc interface{}) ToolResult {
		mu.Lock()
		called = true
		mu.Unlock()
		return ToolResult{Output: "success"}
	})

	result := r.Dispatch(ToolCall{Name: "test_tool"}, nil)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.Output != "success" {
		t.Fatalf("expected 'success', got '%s'", result.Output)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestRegistry_DispatchUnknown(t *testing.T) {
	r := NewRegistry()
	result := r.Dispatch(ToolCall{Name: "nonexistent"}, nil)
	if result.Error == "" {
		t.Fatal("expected error for unknown tool")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := "tool"
			r.Register(name, func(params json.RawMessage, sc interface{}) ToolResult {
				return ToolResult{Output: "ok"}
			})
			r.Dispatch(ToolCall{Name: name}, nil)
		}(i)
	}
	wg.Wait()
}

func TestSchemaWithRecall_NotEmpty(t *testing.T) {
	got := SchemaWithRecall()
	if got == "" {
		t.Fatal("expected non-empty schema string")
	}
}

func TestReadSkillNotEmpty(t *testing.T) {
	result := ReadSkill(json.RawMessage(`{"skill_name":"test"}`), nil)
	if result.Output == "" {
		t.Fatal("expected non-empty result")
	}
}

func TestRecallNotEmpty(t *testing.T) {
	result := Recall(json.RawMessage(`{"query":"test","vuln_type":"xss"}`), nil)
	if result.Output == "" {
		t.Fatal("expected non-empty recall result")
	}
}

func TestRunCommandValidation(t *testing.T) {
	// RunCommand now validates through security kernel - test with disallowed binary
	_, err := RunCommand(context.Background(), "nonexistent_binary", "arg1")
	if err == nil {
		t.Fatal("expected error for disallowed binary")
	}
}
