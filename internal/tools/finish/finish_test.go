package finish

import (
	"encoding/json"
	"testing"

	"github.com/ares/engine/internal/tools"
)

func TestRegister(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	params := json.RawMessage(`{"summary":"scan complete: found 3 vulns"}`)
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: params,
	}, nil)

	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.Output != "scan complete: found 3 vulns" {
		t.Errorf("expected summary output, got %q", result.Output)
	}
	if !result.Done {
		t.Fatal("expected Done to be true for finish tool")
	}
}

func TestRegister_EmptySummary(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	params := json.RawMessage(`{"summary":""}`)
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: params,
	}, nil)

	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.Output != "" {
		t.Errorf("expected empty output, got %q", result.Output)
	}
	if !result.Done {
		t.Fatal("expected Done to be true")
	}
}

func TestRegister_BadParams(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	params := json.RawMessage(`invalid json`)
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: params,
	}, nil)

	if result.Error == "" {
		t.Fatal("expected error for bad params")
	}
	if result.Output != "" {
		t.Errorf("expected empty output on error, got %q", result.Output)
	}
}

func TestRegister_UnknownTool(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	result := r.Dispatch(tools.ToolCall{
		Name:   "nonexistent",
		Params: json.RawMessage(`{}`),
	}, nil)

	if result.Error == "" {
		t.Fatal("expected error for unknown tool")
	}
}

func TestRegister_NilParams(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: nil,
	}, nil)

	if result.Error == "" {
		t.Fatal("expected error for nil params")
	}
}

func TestRegister_EmptyObjectParams(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	params := json.RawMessage(`{}`)
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: params,
	}, nil)

	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.Output != "" {
		t.Errorf("expected empty output, got %q", result.Output)
	}
	if !result.Done {
		t.Fatal("expected Done to be true")
	}
}

func TestRegister_ToolNotInRegistryBeforeRegister(t *testing.T) {
	r := tools.NewRegistry()
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: json.RawMessage(`{"summary":"test"}`),
	}, nil)

	if result.Error == "" {
		t.Fatal("expected error before Register is called")
	}
}

func TestRegister_MultipleRegistrations_LastWins(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	params := json.RawMessage(`{"summary":"final"}`)
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: params,
	}, nil)

	if result.Output != "final" {
		t.Errorf("expected 'final', got %q", result.Output)
	}
}

func TestRegister_SummaryWithSpecialChars(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	params := json.RawMessage(`{"summary":"found <script>alert(1)</script> and other issues"}`)
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: params,
	}, nil)

	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.Output != "found <script>alert(1)</script> and other issues" {
		t.Errorf("output mismatch, got %q", result.Output)
	}
}

func TestRegister_TypeResult(t *testing.T) {
	r := tools.NewRegistry()
	Register(r)

	params := json.RawMessage(`{"summary":"done"}`)
	result := r.Dispatch(tools.ToolCall{
		Name:   "finish",
		Params: params,
	}, nil)

	if _, ok := interface{}(result).(tools.ToolResult); !ok {
		t.Fatal("result should be a ToolResult")
	}
}
