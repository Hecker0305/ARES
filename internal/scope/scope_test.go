package scope

import (
	"testing"
)

func TestExtractHost(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"http://example.com", "example.com"},
		{"https://test.com", "test.com"},
		{"example.com", "example.com"},
	}
	for _, tt := range tests {
		got := extractHost(tt.command)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.command, got, tt.want)
		}
	}
}
