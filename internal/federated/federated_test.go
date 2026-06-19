package federated

import (
	"testing"
)

func TestRecord(t *testing.T) {
	Record("test-payload", "target.com", "high", true)
}

func TestSystemPromptSection(t *testing.T) {
	section := SystemPromptSection("target.com", "web")
	t.Logf("SystemPromptSection returned: %q", section)
}
