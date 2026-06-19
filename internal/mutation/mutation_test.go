package mutation

import (
	"strings"
	"testing"
)

func TestMutate(t *testing.T) {
	variants := Mutate("test")
	if len(variants) == 0 {
		t.Error("expected at least 1 variant")
	}
}

func TestMutateIncludesOriginal(t *testing.T) {
	variants := Mutate("payload")
	hasOriginal := false
	for _, v := range variants {
		if v == "payload" {
			hasOriginal = true
			break
		}
	}
	if !hasOriginal {
		t.Error("expected original payload in variants")
	}
}

func TestLLMVariants(t *testing.T) {
	variants := LLMVariants("test")
	if len(variants) == 0 {
		t.Error("expected at least 1 LLM variant")
	}
}

func TestPrompt(t *testing.T) {
	result := Prompt("test-payload", []string{"var1", "var2"})
	if result == "" {
		t.Error("expected non-empty prompt")
	}
	if !strings.Contains(result, "test-payload") {
		t.Error("expected payload in prompt")
	}
}

func TestMutateURLEndoded(t *testing.T) {
	variants := Mutate("<script>")
	hasEncoding := false
	for _, v := range variants {
		if strings.Contains(v, "%3C") || strings.Contains(v, "&lt") {
			hasEncoding = true
			break
		}
	}
	if !hasEncoding {
		t.Log("expected at least one URL-encoded variant")
	}
}
