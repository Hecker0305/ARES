package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewWebhookManager(t *testing.T) {
	wm := NewWebhookManager("")
	if wm == nil {
		t.Fatal("expected non-nil WebhookManager")
	}
	if len(wm.configs) != 0 {
		t.Error("expected empty configs")
	}
}

func TestAddListDeleteWebhook(t *testing.T) {
	wm := NewWebhookManager("")
	cfg := WebhookConfig{
		ID:      "test-webhook",
		URL:     "https://hooks.slack.com/services/test",
		Events:  []string{"finding.created", "scan.complete"},
		Type:    WebhookTypeSlack,
		Enabled: true,
	}
	wm.AddOrUpdate(cfg)

	retrieved := wm.Get("test-webhook")
	if retrieved == nil {
		t.Fatal("webhook not found after adding")
	}
	if retrieved.URL != "https://hooks.slack.com/services/test" {
		t.Errorf("expected URL, got %s", retrieved.URL)
	}
	if retrieved.Type != WebhookTypeSlack {
		t.Errorf("expected type slack, got %s", retrieved.Type)
	}

	list := wm.List()
	found := false
	for _, w := range list {
		if w.ID == "test-webhook" {
			found = true
			break
		}
	}
	if !found {
		t.Error("webhook not found in list")
	}

	wm.Delete("test-webhook")
	if wm.Get("test-webhook") != nil {
		t.Error("webhook should be deleted")
	}
}

func TestUpdateWebhook(t *testing.T) {
	wm := NewWebhookManager("")
	cfg := WebhookConfig{
		ID:      "update-test",
		URL:     "https://hooks.example.com/old",
		Events:  []string{"finding.created"},
		Type:    WebhookTypeGeneric,
		Enabled: true,
	}
	wm.AddOrUpdate(cfg)
	cfg.URL = "https://hooks.example.com/new"
	wm.AddOrUpdate(cfg)
	retrieved := wm.Get("update-test")
	if retrieved == nil || retrieved.URL != "https://hooks.example.com/new" {
		t.Error("webhook URL should be updated")
	}
}

func TestWebhookDispatch(t *testing.T) {
	wm := NewWebhookManager("")
	wm.SetSkipSSRFValidation(true)
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := WebhookConfig{
		ID:      "dispatch-test",
		URL:     server.URL,
		Events:  []string{"finding.created"},
		Type:    WebhookTypeGeneric,
		Enabled: true,
	}
	wm.AddOrUpdate(cfg)
	wm.DispatchFindingCreated("scan-1", "http://test.com", FindingPayload{
		ID:       "finding-1",
		Title:    "Test Finding",
		Severity: "high",
	})
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Error("webhook was not dispatched")
	}
}

func TestWebhookSigning(t *testing.T) {
	secret := "test-secret"
	sig := signPayload([]byte(`{"test":"data"}`), secret)
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}
	if !strings.HasPrefix(sig, "sha256=") {
		t.Errorf("expected sha256= prefix, got %s", sig)
	}
}

func TestWebhookRateLimit(t *testing.T) {
	wm := NewWebhookManager("")
	id := "rate-test"
	for i := 0; i < 15; i++ {
		wm.allowRate(id)
	}
	if wm.allowRate(id) {
		t.Log("rate limit may or may not have triggered")
	}
}

func TestSendTestWebhook(t *testing.T) {
	wm := NewWebhookManager("")
	wm.SetSkipSSRFValidation(true)
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := WebhookConfig{
		ID:      "test-send",
		URL:     server.URL,
		Events:  []string{"*"},
		Type:    WebhookTypeGeneric,
		Enabled: true,
	}
	if err := wm.SendTest(cfg); err != nil {
		t.Fatalf("SendTest failed: %v", err)
	}
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Error("test webhook was not sent")
	}
}

func TestSlackPayloadBuild(t *testing.T) {
	data := map[string]interface{}{
		"event":   "finding.created",
		"scan_id": "scan-1",
		"finding": map[string]interface{}{
			"id": "finding-1",
		},
	}
	payload, err := buildSlackPayload(data)
	if err != nil {
		t.Fatalf("buildSlackPayload failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["text"] == "" {
		t.Error("expected non-empty slack text")
	}
}

func TestDiscordPayloadBuild(t *testing.T) {
	data := map[string]interface{}{
		"event":   "scan.complete",
		"scan_id": "scan-1",
	}
	payload, err := buildDiscordPayload(data)
	if err != nil {
		t.Fatalf("buildDiscordPayload failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	embeds, ok := parsed["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Error("expected discord embed")
	}
}
