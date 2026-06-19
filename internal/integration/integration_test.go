package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ares/engine/internal/config"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/scheduler"
	"github.com/ares/engine/internal/webhook"
)

func TestIntegration_LLMClient(t *testing.T) {
	if os.Getenv("ARES_RUN_INTEGRATION") != "true" {
		t.Skip("Skipping integration test. Set ARES_RUN_INTEGRATION=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := llm.NewClient(llm.Config{
		Provider: "ollama",
		BaseURL:  "http://localhost:11434/v1",
		Model:    "llama3.1:70b",
	})
	if err != nil {
		t.Skipf("LLM not available: %v", err)
	}

	resp, err := client.Complete(ctx, []llm.Message{
		{Role: "user", Content: "Say hello"},
	}, "")
	if err != nil {
		t.Fatalf("LLM complete failed: %v", err)
	}

	if resp == "" {
		t.Fatal("LLM response is empty")
	}

	t.Logf("LLM response: %s", resp[:min(100, len(resp))])
}

func TestIntegration_SchedulerPersistence(t *testing.T) {
	if os.Getenv("ARES_RUN_INTEGRATION") != "true" {
		t.Skip("Skipping integration test. Set ARES_RUN_INTEGRATION=true to run.")
	}

	tmpFile := "test-schedules.json"
	defer os.Remove(tmpFile)

	sched := scheduler.New(tmpFile, func(target string) {})

	schedule := &scheduler.Schedule{
		ID:       "test-sched-1",
		Name:     "Integration Test Schedule",
		Target:   "http://localhost:8888",
		CronExpr: "0 9 * * 1",
		Enabled:  true,
	}

	sched.AddSchedule(schedule)

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Schedule file not created: %v", err)
	}

	var schedules map[string]*scheduler.Schedule
	if err := json.Unmarshal(data, &schedules); err != nil {
		t.Fatalf("Invalid schedule file format: %v", err)
	}

	if schedules["test-sched-1"] == nil {
		t.Fatal("Schedule not persisted")
	}

	sched.Stop()
}

func TestIntegration_WebhookManager(t *testing.T) {
	if os.Getenv("ARES_RUN_INTEGRATION") != "true" {
		t.Skip("Skipping integration test. Set ARES_RUN_INTEGRATION=true to run.")
	}

	var receivedCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mgr := webhook.NewWebhookManager("")
	cfg := &webhook.WebhookConfig{
		ID:      "test-wh-1",
		URL:     server.URL,
		Secret:  "test-secret",
		Events:  []string{"finding.created"},
		Type:    "generic",
		Enabled: true,
	}
	mgr.AddOrUpdate(*cfg)

	mgr.DispatchFindingCreated("test-scan", "http://test.com", webhook.FindingPayload{
		ID:       "test-finding",
		Title:    "Test Finding",
		Severity: "high",
	})

	time.Sleep(500 * time.Millisecond)

	if receivedCalls == 0 {
		t.Fatal("Webhook was not called")
	}
}

func TestIntegration_ConfigRoundTrip(t *testing.T) {
	if os.Getenv("ARES_RUN_INTEGRATION") != "true" {
		t.Skip("Skipping integration test. Set ARES_RUN_INTEGRATION=true to run.")
	}

	os.Setenv("ARES_LLM_PROVIDER", "ollama")
	os.Setenv("ARES_LLM_BASE_URL", "http://localhost:11434/v1")
	os.Setenv("ARES_LLM_MODEL", "test-model")
	os.Setenv("ARES_SCAN_MAX_WORKERS", "5")
	os.Setenv("ARES_OOB_ENABLED", "true")
	os.Setenv("ARES_OOB_DNS_PORT", "5353")
	os.Setenv("ARES_DISCORD_ENABLED", "true")
	os.Setenv("ARES_PROXY_ENABLED", "true")
	os.Setenv("ARES_RESOURCES_MAX_CPU_PERCENT", "85.0")
	defer func() {
		os.Unsetenv("ARES_LLM_PROVIDER")
		os.Unsetenv("ARES_LLM_BASE_URL")
		os.Unsetenv("ARES_LLM_MODEL")
		os.Unsetenv("ARES_SCAN_MAX_WORKERS")
		os.Unsetenv("ARES_OOB_ENABLED")
		os.Unsetenv("ARES_OOB_DNS_PORT")
		os.Unsetenv("ARES_DISCORD_ENABLED")
		os.Unsetenv("ARES_PROXY_ENABLED")
		os.Unsetenv("ARES_RESOURCES_MAX_CPU_PERCENT")
	}()

	cfg := config.LoadEnv()

	if cfg.LLM.Provider != "ollama" {
		t.Errorf("Expected provider 'ollama', got '%s'", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "test-model" {
		t.Errorf("Expected model 'test-model', got '%s'", cfg.LLM.Model)
	}
	if cfg.Scan.MaxWorkers != 5 {
		t.Errorf("Expected 5 workers, got %d", cfg.Scan.MaxWorkers)
	}
	if !cfg.OOB.Enabled {
		t.Error("Expected OOB to be enabled")
	}
	if cfg.OOB.DNSPort != 5353 {
		t.Errorf("Expected OOB DNS port 5353, got %d", cfg.OOB.DNSPort)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}
}

func TestIntegration_HTTPServer(t *testing.T) {
	if os.Getenv("ARES_RUN_INTEGRATION") != "true" {
		t.Skip("Skipping integration test. Set ARES_RUN_INTEGRATION=true to run.")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestMain(m *testing.M) {
	fmt.Println("=== ARES Integration Test Suite ===")
	code := m.Run()
	if code == 0 {
		fmt.Println("All integration tests passed!")
	} else {
		fmt.Println("Some integration tests failed!")
	}
	os.Exit(code)
}
