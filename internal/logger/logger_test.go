package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestInit(t *testing.T) {
	l := Init("test-service", "1.0", "test", DebugLevel)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	if l.service != "test-service" {
		t.Errorf("expected test-service, got %s", l.service)
	}
	if l.version != "1.0" {
		t.Errorf("expected 1.0, got %s", l.version)
	}
	if l.level != DebugLevel {
		t.Errorf("expected DebugLevel, got %v", l.level)
	}
}

func TestGetInit(t *testing.T) {
	l := Get()
	if l == nil {
		t.Fatal("expected non-nil logger from Get()")
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{DebugLevel, "debug"},
		{InfoLevel, "info"},
		{WarnLevel, "warn"},
		{ErrorLevel, "error"},
		{FatalLevel, "fatal"},
		{Level(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.level.String()
		if got != tt.want {
			t.Errorf("Level(%d).String() = %s, want %s", tt.level, got, tt.want)
		}
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		level:  DebugLevel,
		output: &buf,
	}

	l.Debug("debug msg", nil)
	l.Info("info msg", nil)
	l.Warn("warn msg", nil)
	l.Error("error msg", nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Errorf("expected 4 log lines, got %d", len(lines))
	}

	levels := []string{"debug", "info", "warn", "error"}
	for i, line := range lines {
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("failed to parse log line %d: %v", i, err)
			continue
		}
		if entry.Level != levels[i] {
			t.Errorf("line %d: expected level %s, got %s", i, levels[i], entry.Level)
		}
	}
}

func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		level:  WarnLevel,
		output: &buf,
	}

	l.Debug("should not appear", nil)
	l.Info("should not appear", nil)
	l.Warn("should appear", nil)
	l.Error("should appear", nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 log lines, got %d", len(lines))
	}
}

func TestLogWithFields(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		level:  InfoLevel,
		output: &buf,
	}

	l.Info("test with fields", Fields{"key1": "value1", "key2": 42})

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log: %v", err)
	}
	if entry.Fields["key1"] != "value1" {
		t.Errorf("expected value1, got %v", entry.Fields["key1"])
	}
}

func TestRedactFields(t *testing.T) {
	fields := Fields{
		"username":    "admin",
		"password":    "supersecret",
		"api_key":     "sk-123456",
		"description": "normal field",
	}
	redacted := RedactFields(fields)
	if redacted["password"] != "***REDACTED***" {
		t.Errorf("expected REDACTED for password, got %v", redacted["password"])
	}
	if redacted["username"] != "admin" {
		t.Errorf("expected admin, got %v", redacted["username"])
	}
	if redacted["description"] != "normal field" {
		t.Errorf("expected normal field, got %v", redacted["description"])
	}
}

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"sk-abcdef1234567890", true},
		{"AKIA1234567890ABCD", true},
		{"short", false},
		{"normal-string-with-no-pattern", false},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", true},
		{"xoxb-1234567890-abcdefghijklm", true},
	}
	for _, tt := range tests {
		got := looksLikeSecret(tt.s)
		if got != tt.want {
			t.Errorf("looksLikeSecret(%q) = %v, want %v", tt.s[:min(len(tt.s), 20)], got, tt.want)
		}
	}
}

func TestSetLevel(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{level: ErrorLevel, output: &buf}
	l.SetLevel(DebugLevel)
	if l.level != DebugLevel {
		t.Errorf("expected DebugLevel, got %v", l.level)
	}
}

func TestGenerateTraceID(t *testing.T) {
	id1 := GenerateTraceID()
	id2 := GenerateTraceID()
	if id1 == id2 {
		t.Error("expected unique trace IDs")
	}
	if len(id1) < 10 {
		t.Errorf("expected trace ID length >= 10, got %d", len(id1))
	}
}

func TestGenerateSpanID(t *testing.T) {
	id1 := GenerateSpanID()
	id2 := GenerateSpanID()
	if id1 == id2 {
		t.Error("expected unique span IDs")
	}
}

func TestWithFields(t *testing.T) {
	l := &Logger{}
	fields := l.WithFields(Fields{"a": 1})
	if fields["a"] != 1 {
		t.Errorf("expected 1, got %v", fields["a"])
	}
}

func TestRedactAPIKeyField(t *testing.T) {
	fields := Fields{
		"ARES_LLM_API_KEY": "sk-test-key-value",
	}
	redacted := RedactFields(fields)
	if redacted["ARES_LLM_API_KEY"] != "***REDACTED***" {
		t.Errorf("expected REDACTED, got %v", redacted["ARES_LLM_API_KEY"])
	}
}

func TestLogConcurrency(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		level:  DebugLevel,
		output: &buf,
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			l.Info("concurrent test", Fields{"iter": n})
		}(i)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 20 {
		t.Errorf("expected 20 log lines, got %d", len(lines))
	}
}
