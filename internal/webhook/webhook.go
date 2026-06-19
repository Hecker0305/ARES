package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"context"

	"github.com/ares/engine/internal/logger"
)

type WebhookType string

const (
	WebhookTypeSlack   WebhookType = "slack"
	WebhookTypeDiscord WebhookType = "discord"
	WebhookTypeEmail   WebhookType = "email"
	WebhookTypeGeneric WebhookType = "generic"
)

const (
	EventFindingCreated = "finding.created"
	EventScanComplete   = "scan.complete"
	EventCriticalAlert  = "critical.alert"
)

type WebhookConfig struct {
	ID      string      `json:"id"`
	URL     string      `json:"url"`
	Secret  string      `json:"-"`
	Events  []string    `json:"events"`
	Type    WebhookType `json:"type"`
	Enabled bool        `json:"enabled"`
}

type FindingPayload struct {
	ScanID      string  `json:"scan_id"`
	Target      string  `json:"target"`
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	CVSS        float64 `json:"cvss"`
	Endpoint    string  `json:"endpoint"`
	Timestamp   string  `json:"timestamp"`
}

type ScanSummary struct {
	ScanID        string `json:"scan_id"`
	Target        string `json:"target"`
	Status        string `json:"status"`
	TotalFindings int    `json:"total_findings"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	MediumCount   int    `json:"medium_count"`
	LowCount      int    `json:"low_count"`
	Duration      string `json:"duration"`
}

type rateEntry struct {
	timestamps []time.Time
}

type WebhookManager struct {
	mu         sync.RWMutex
	configs    map[string]*WebhookConfig
	storePath  string
	rateLimits map[string]*rateEntry
	rateMu     sync.Mutex
	client     *http.Client
	skipSSRF   bool
	dirty      bool
}

func NewWebhookManager(storePath string) *WebhookManager {
	m := &WebhookManager{
		configs:    make(map[string]*WebhookConfig),
		storePath:  storePath,
		rateLimits: make(map[string]*rateEntry),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	m.load()
	return m
}

func (m *WebhookManager) DispatchFindingCreated(scanID, target string, finding FindingPayload) {
	m.dispatch(EventFindingCreated, func(cfg *WebhookConfig) ([]byte, error) {
		return m.buildPayload(cfg, map[string]interface{}{
			"event":   EventFindingCreated,
			"scan_id": scanID,
			"target":  target,
			"finding": finding,
		})
	})
}

func (m *WebhookManager) DispatchScanComplete(scanID, target string, summary ScanSummary) {
	m.dispatch(EventScanComplete, func(cfg *WebhookConfig) ([]byte, error) {
		return m.buildPayload(cfg, map[string]interface{}{
			"event":   EventScanComplete,
			"scan_id": scanID,
			"target":  target,
			"summary": summary,
		})
	})
}

func (m *WebhookManager) DispatchCriticalAlert(scanID, target string, finding FindingPayload) {
	m.dispatch(EventCriticalAlert, func(cfg *WebhookConfig) ([]byte, error) {
		return m.buildPayload(cfg, map[string]interface{}{
			"event":   EventCriticalAlert,
			"scan_id": scanID,
			"target":  target,
			"finding": finding,
		})
	})
}

func (m *WebhookManager) dispatch(event string, buildFn func(*WebhookConfig) ([]byte, error)) {
	m.mu.RLock()
	var targets []*WebhookConfig
	for _, cfg := range m.configs {
		if !cfg.Enabled {
			continue
		}
		matched := false
		for _, e := range cfg.Events {
			if e == event || e == "*" {
				matched = true
				break
			}
		}
		if matched {
			targets = append(targets, cfg)
		}
	}
	m.mu.RUnlock()

	for _, cfg := range targets {
		if !m.allowRate(cfg.ID) {
			logger.Info(fmt.Sprintf("[Webhook] Rate limited: %s (%s)", cfg.ID, cfg.Type))
			continue
		}
		payload, err := buildFn(cfg)
		if err != nil {
			logger.Error(fmt.Sprintf("[Webhook] Build payload error: %v", err))
			continue
		}
		go m.send(context.Background(), cfg, payload)
	}
}

func (m *WebhookManager) send(ctx context.Context, cfg *WebhookConfig, payload []byte) {
	if !m.skipSSRF {
		if err := validateWebhookURL(cfg.URL); err != nil {
			logger.Error(fmt.Sprintf("[Webhook] SSRF validation error: %v", err))
			return
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		logger.Error(fmt.Sprintf("[Webhook] Request error: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARES-Webhook/1.0")

	if cfg.Secret != "" {
		sig := signPayload(payload, cfg.Secret)
		req.Header.Set("X-ARES-Signature-256", sig)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		logger.Error(fmt.Sprintf("[Webhook] Send error: %v", err))
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		logger.Info(fmt.Sprintf("[Webhook] Non-2xx response: %d for %s", resp.StatusCode, cfg.URL))
	}
}

func (m *WebhookManager) buildPayload(cfg *WebhookConfig, data map[string]interface{}) ([]byte, error) {
	switch cfg.Type {
	case WebhookTypeSlack:
		return buildSlackPayload(data)
	case WebhookTypeDiscord:
		return buildDiscordPayload(data)
	default:
		return json.Marshal(data)
	}
}

func buildSlackPayload(data map[string]interface{}) ([]byte, error) {
	event, _ := data["event"].(string)
	color := "#36a64f"
	title := "ARES Notification"

	switch event {
	case EventCriticalAlert:
		color = "#FF0000"
		title = "ARES Critical Alert"
	case EventFindingCreated:
		color = "#FFA500"
		title = "ARES Finding"
	case EventScanComplete:
		color = "#36a64f"
		title = "ARES Scan Complete"
	}

	delete(data, "event")

	var fields []map[string]interface{}
	for k, v := range data {
		valStr := fmt.Sprintf("%v", v)
		if len(valStr) > 500 {
			valStr = valStr[:500] + "..."
		}
		fields = append(fields, map[string]interface{}{
			"title": k,
			"value": valStr,
			"short": len(valStr) < 100,
		})
	}

	payload := map[string]interface{}{
		"text": title,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  title,
				"fields": fields,
				"ts":     time.Now().Unix(),
			},
		},
	}
	return json.Marshal(payload)
}

func buildDiscordPayload(data map[string]interface{}) ([]byte, error) {
	event, _ := data["event"].(string)
	color := 3066993

	switch event {
	case EventCriticalAlert:
		color = 15158332
	case EventFindingCreated:
		color = 15105570
	case EventScanComplete:
		color = 3066993
	}

	delete(data, "event")

	descBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal discord payload: %v", err)
	}
	description := "```json\n" + string(descBytes) + "\n```"
	if len(description) > 4000 {
		description = description[:4000] + "\n...```"
	}

	embedTitle := "ARES Notification"
	if event != "" {
		embedTitle = event
	}

	payload := map[string]interface{}{
		"content": "ARES Notification",
		"embeds": []map[string]interface{}{
			{
				"title":       embedTitle,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	return json.Marshal(payload)
}

func (m *WebhookManager) allowRate(id string) bool {
	m.rateMu.Lock()
	defer m.rateMu.Unlock()

	now := time.Now()
	entry, ok := m.rateLimits[id]
	if !ok {
		m.rateLimits[id] = &rateEntry{
			timestamps: []time.Time{now},
		}
		return true
	}

	cutoff := now.Add(-1 * time.Minute)
	var valid []time.Time
	for _, t := range entry.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= 10 {
		entry.timestamps = valid
		return false
	}

	entry.timestamps = append(valid, now)
	return true
}

func (m *WebhookManager) load() {
	if m.storePath == "" {
		return
	}
	data, err := os.ReadFile(m.storePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error(fmt.Sprintf("[Webhook] Load error: %v", err))
		}
		return
	}
	var configs map[string]*WebhookConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		logger.Error(fmt.Sprintf("[Webhook] Unmarshal error: %v", err))
		return
	}
	m.mu.Lock()
	for k, v := range configs {
		m.configs[k] = v
	}
	m.mu.Unlock()
}

func (m *WebhookManager) List() []*WebhookConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*WebhookConfig, 0, len(m.configs))
	for _, cfg := range m.configs {
		result = append(result, cfg)
	}
	return result
}

func (m *WebhookManager) AddOrUpdate(cfg WebhookConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[cfg.ID] = &cfg
	m.doSave()
}

func (m *WebhookManager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.configs, id)
	m.doSave()
}

func (m *WebhookManager) Get(id string) *WebhookConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configs[id]
}

func (m *WebhookManager) SetSkipSSRFValidation(b bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.skipSSRF = b
}

func (m *WebhookManager) SendTest(cfg WebhookConfig) error {
	if !m.skipSSRF {
		if err := validateWebhookURL(cfg.URL); err != nil {
			return err
		}
	}
	payload, err := m.buildPayload(&cfg, map[string]interface{}{
		"event":   "test",
		"message": "This is a test notification from ARES.",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}
	m.send(context.Background(), &cfg, payload)
	return nil
}

func (m *WebhookManager) doSave() {
	m.dirty = true
	if m.storePath != "" {
		data, err := json.MarshalIndent(m.configs, "", "  ")
		if err != nil {
			logger.Error(fmt.Sprintf("[Webhook] save error: %v", err))
			return
		}
		if err := os.WriteFile(m.storePath, data, 0600); err != nil {
			logger.Error(fmt.Sprintf("[Webhook] write error: %v", err))
		}
	}
}

func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func validateWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("webhook URL must use http or https scheme")
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL must have a hostname")
	}
	lowerHost := host
	if net.ParseIP(lowerHost) != nil {
		ip := net.ParseIP(lowerHost)
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("webhook URL cannot point to private or loopback IP: %s", lowerHost)
		}
	} else {
		resolved, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("failed to resolve webhook URL hostname: %w", err)
		}
		for _, ip := range resolved {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return fmt.Errorf("webhook URL resolves to private or loopback IP: %s -> %s", host, ip)
			}
		}
	}
	return nil
}
