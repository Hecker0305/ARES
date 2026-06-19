package scanner

import "testing"

func TestSystemPromptHints(t *testing.T) {
	hints := SystemPromptHints("example.com", "http://oob.local/test")
	if hints == "" {
		t.Error("expected non-empty hints")
	}
}

func TestSystemPromptHintsWithoutOOB(t *testing.T) {
	hints := SystemPromptHints("example.com", "")
	if hints == "" {
		t.Error("expected non-empty hints even without OOB")
	}
}
