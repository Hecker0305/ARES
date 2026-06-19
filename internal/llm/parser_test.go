package llm

import (
	"testing"
)

func TestParseToolCallsBasic(t *testing.T) {
	content := `<function=terminal_execute>
<parameter=command>nmap -sV target.com</parameter>
</function>`
	calls := ParseToolCalls(content)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Name != "terminal_execute" {
		t.Errorf("name = %q, want %q", calls[0].Name, "terminal_execute")
	}
	if calls[0].Args["command"] != "nmap -sV target.com" {
		t.Errorf("command = %q, want %q", calls[0].Args["command"], "nmap -sV target.com")
	}
}

func TestParseToolCallsMultiple(t *testing.T) {
	content := `<function=curl>
<parameter=url>http://test.com</parameter>
</function>
<function=nmap>
<parameter=target>test.com</parameter>
</function>`
	calls := ParseToolCalls(content)
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
}

func TestParseToolCallsInvokeFormat(t *testing.T) {
	content := `<invoke name="terminal_execute">
<parameter name="command">echo test</parameter>
</invoke>`
	calls := ParseToolCalls(content)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Name != "terminal_execute" {
		t.Errorf("name = %q, want %q", calls[0].Name, "terminal_execute")
	}
}

func TestParseToolCallsEmpty(t *testing.T) {
	calls := ParseToolCalls("")
	if len(calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(calls))
	}
}

func TestParseToolCallsNoCalls(t *testing.T) {
	calls := ParseToolCalls("Hello, this is a response without any tool calls.")
	if len(calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(calls))
	}
}

func TestFormatToolCall(t *testing.T) {
	args := map[string]string{"command": "ls -la"}
	result := FormatToolCall("terminal_execute", args)
	if !contains(result, "terminal_execute") {
		t.Errorf("result should contain tool name")
	}
	if !contains(result, "ls -la") {
		t.Errorf("result should contain argument value")
	}
}

func TestCleanContent(t *testing.T) {
	content := `Some text before
<function=terminal_execute>
<parameter=command>echo test</parameter>
</function>
Some text after`
	cleaned := CleanContent(content)
	if contains(cleaned, "<function") {
		t.Errorf("cleaned content should not contain XML tags")
	}
	if !contains(cleaned, "Some text") {
		t.Errorf("cleaned content should preserve non-XML text")
	}
}

func TestFixIncomplete(t *testing.T) {
	content := `<function=terminal_execute>
<parameter=command>nmap`
	fixed := fixIncomplete(content)
	if !contains(fixed, "</function>") {
		t.Errorf("fixed content should have closing tag")
	}
}

func TestParseToolCallsLenient(t *testing.T) {
	content := `<function=terminal_execute>\n<parameter=command>nmap -sV target.com</parameter>\n</function>`
	calls := ParseToolCalls(content)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Name != "terminal_execute" {
		t.Errorf("name = %q, want %q", calls[0].Name, "terminal_execute")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
