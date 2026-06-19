package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ares/engine/internal/security"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.LLM.Provider != "" {
		t.Errorf("expected empty provider, got %s", cfg.LLM.Provider)
	}
	if cfg.LLM.BaseURL != "" {
		t.Errorf("expected empty base url, got %s", cfg.LLM.BaseURL)
	}
	if cfg.LLM.Model != "" {
		t.Errorf("expected empty model, got %s", cfg.LLM.Model)
	}
	if cfg.Scan.MaxWorkers != 3 {
		t.Errorf("expected 3, got %d", cfg.Scan.MaxWorkers)
	}
	if cfg.Scan.MaxIterations != 200 {
		t.Errorf("expected 200, got %d", cfg.Scan.MaxIterations)
	}
	if cfg.Output.ReportPath != "report.txt" {
		t.Errorf("expected report.txt, got %s", cfg.Output.ReportPath)
	}
	if cfg.Web.HTTPPort != 8080 {
		t.Errorf("expected 8080, got %d", cfg.Web.HTTPPort)
	}
}

func TestValidateValid(t *testing.T) {
	cfg := Default()
	cfg.Scan.MaxWorkers = 1
	cfg.LLM.Provider = "openai"
	cfg.LLM.BaseURL = "https://api.openai.com/v1"
	cfg.LLM.Model = "gpt-4o"
	cfg.LLM.APIKey = security.NewSecret("sk-test123")
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestValidateMissingProvider(t *testing.T) {
	cfg := Default()
	cfg.LLM.Provider = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for missing provider")
	}
}

func TestValidateMissingModel(t *testing.T) {
	cfg := Default()
	cfg.LLM.Model = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for missing model")
	}
}

func TestValidateMissingBaseURL(t *testing.T) {
	cfg := Default()
	cfg.LLM.BaseURL = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for missing base URL")
	}
}

func TestValidateNegativeIterations(t *testing.T) {
	cfg := Default()
	cfg.Scan.MaxIterations = 0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for zero iterations")
	}
}

func TestValidateEmptyWorkers(t *testing.T) {
	cfg := Default()
	cfg.Scan.MaxWorkers = 0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for zero workers")
	}
}

func TestValidateConfidenceGate(t *testing.T) {
	cfg := Default()
	cfg.Scan.ConfidenceGate = 1.5
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for confidence gate > 1")
	}
}

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".ares.env")
	content := "LLM_PROVIDER=anthropic\nLLM_MODEL=claude-3-5-sonnet\n"
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write env file: %v", err)
	}

	cfg, err := LoadDotEnv(envFile)
	if err != nil {
		t.Fatalf("LoadDotEnv error: %v", err)
	}
	if cfg.LLM.Provider != "anthropic" {
		t.Errorf("expected anthropic, got %s", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "claude-3-5-sonnet" {
		t.Errorf("expected claude-3-5-sonnet, got %s", cfg.LLM.Model)
	}
}

func TestLoadDotEnvEmptyLines(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".ares.env")
	content := "\n# comment\n\nLLM_PROVIDER=openai\n"
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write env file: %v", err)
	}
	cfg, err := LoadDotEnv(envFile)
	if err != nil {
		t.Fatalf("LoadDotEnv error: %v", err)
	}
	if cfg.LLM.Provider != "openai" {
		t.Errorf("expected openai, got %s", cfg.LLM.Provider)
	}
}

func TestLoadDotEnvFileTooLarge(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".ares.env")
	data := make([]byte, 2<<20)
	if err := os.WriteFile(envFile, data, 0644); err != nil {
		t.Fatalf("failed to write large env file: %v", err)
	}
	_, err := LoadDotEnv(envFile)
	if err == nil {
		t.Error("expected error for oversized env file")
	}
}

func TestLoadEnvFromOS(t *testing.T) {
	os.Setenv("ARES_SCAN_MAX_WORKERS", "7")
	defer os.Unsetenv("ARES_SCAN_MAX_WORKERS")

	cfg := LoadEnv()
	if cfg.Scan.MaxWorkers != 7 {
		t.Errorf("expected 7, got %d", cfg.Scan.MaxWorkers)
	}
}

func TestLoadEnvWithOverlay(t *testing.T) {
	envMu.Lock()
	overlay := getEnvOverlay()
	overlay["ARES_LLM_PROVIDER"] = "overlay-provider"
	overlay["ARES_LLM_MODEL"] = "overlay-model"
	envMu.Unlock()

	cfg := LoadEnv()
	if cfg.LLM.Provider != "overlay-provider" {
		t.Errorf("expected overlay-provider, got %s", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "overlay-model" {
		t.Errorf("expected overlay-model, got %s", cfg.LLM.Model)
	}

	envMu.Lock()
	delete(overlay, "ARES_LLM_PROVIDER")
	delete(overlay, "ARES_LLM_MODEL")
	envMu.Unlock()
}

func TestValidatePivotRequired(t *testing.T) {
	cfg := Default()
	cfg.Pivot.Enabled = true
	cfg.Pivot.Host = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for pivot enabled without host")
	}
}

func TestValidateSliverRequired(t *testing.T) {
	cfg := Default()
	cfg.Sliver.Enabled = true
	cfg.Sliver.Host = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for sliver enabled without host")
	}
}

func TestZeroize(t *testing.T) {
	cfg := Default()
	cfg.LLM.APIKey = security.NewSecret("test-key")
	cfg.AttackLLM.APIKey = security.NewSecret("attack-key")
	cfg.Zeroize()
	if cfg.LLM.APIKey.Plain() != "" {
		t.Error("expected API key cleared")
	}
	if cfg.AttackLLM.APIKey.Plain() != "" {
		t.Error("expected attack API key cleared")
	}
}
