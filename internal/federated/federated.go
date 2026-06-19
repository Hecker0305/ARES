package federated

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type HubConfig struct {
	URL          string
	Token        string
	OrgID        string
	PushInterval time.Duration
	PullOnStart  bool
}

type SharedFinding struct {
	ID         string        `json:"id"`
	Type       string        `json:"type"`
	Target     string        `json:"target"`
	Payload    string        `json:"payload"`
	Severity   string        `json:"severity"`
	Confidence float64       `json:"confidence"`
	Evidence   string        `json:"evidence"`
	Framework  string        `json:"framework"`
	Origin     string        `json:"origin"`
	Timestamp  time.Time     `json:"timestamp"`
	TTL        time.Duration `json:"ttl"`
}

var (
	ipv4Pattern       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Pattern       = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
	emailPattern      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	hostnamePattern   = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|local|internal|corp|dev|staging|prod|localdomain)\b`)
	creditCardPattern = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	ssnPattern        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	apiKeyPattern     = regexp.MustCompile(`(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|token)\s*[:=]\s*["']?[A-Za-z0-9+/=_\-]{16,}["']?`)
	passwordPattern   = regexp.MustCompile(`(?:password|passwd|pwd|pass)\s*[:=]\s*["']?[^\s"']{4,}["']?`)
)

type FederatedHub struct {
	cfg     HubConfig
	client  *http.Client
	outbox  []SharedFinding
	inbox   []SharedFinding
	mu      sync.RWMutex
	stopCh  chan struct{}
	running bool
}

func NewFederatedHub(cfg HubConfig) *FederatedHub {
	if cfg.PushInterval == 0 {
		cfg.PushInterval = 5 * time.Minute
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
		logger.Warn(fmt.Sprintf("[Federated] Warning: no system cert pool: %v", err))
	}
	transport := &http.Transport{
		MaxIdleConns:    10,
		MaxConnsPerHost: 5,
		IdleConnTimeout: 90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
	}
	return &FederatedHub{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second, Transport: transport},
		outbox: make([]SharedFinding, 0),
		inbox:  make([]SharedFinding, 0),
		stopCh: make(chan struct{}),
	}
}

func (h *FederatedHub) Start(ctx context.Context) {
	h.mu.Lock()
	h.running = true
	h.mu.Unlock()

	if h.cfg.PullOnStart {
		if err := h.Pull(ctx); err != nil {
			logger.Error(fmt.Sprintf("[Federated] Initial pull failed: %v", err))
		}
	}

	go h.syncLoop(ctx)
}

func (h *FederatedHub) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(h.cfg.PushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopCh:
			return
		case <-ticker.C:
			if err := h.Push(ctx); err != nil {
				logger.Error(fmt.Sprintf("[Federated] Push failed: %v", err))
			}
			if err := h.Pull(ctx); err != nil {
				logger.Error(fmt.Sprintf("[Federated] Pull failed: %v", err))
			}
		}
	}
}

func (h *FederatedHub) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		h.running = false
		close(h.stopCh)
	}
}

func (h *FederatedHub) ShareFinding(f *SharedFinding) {
	h.mu.Lock()
	defer h.mu.Unlock()

	f.Timestamp = time.Now()
	if f.TTL == 0 {
		f.TTL = 24 * time.Hour
	}
	anonymized := anonymizeFinding(*f)
	h.outbox = append(h.outbox, anonymized)
}

func (h *FederatedHub) GetSharedFindings() []SharedFinding {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make([]SharedFinding, len(h.inbox))
	copy(result, h.inbox)
	return result
}

func (h *FederatedHub) Push(ctx context.Context) error {
	h.mu.Lock()
	if len(h.outbox) == 0 {
		h.mu.Unlock()
		return nil
	}
	toSend := make([]SharedFinding, len(h.outbox))
	copy(toSend, h.outbox)
	h.outbox = h.outbox[:0]
	h.mu.Unlock()

	payload, err := json.Marshal(toSend)
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}

	if !strings.HasPrefix(strings.ToLower(h.cfg.URL), "https://") {
		return fmt.Errorf("federated hub URL must use HTTPS: %s", h.cfg.URL)
	}
	endpoint := h.cfg.URL + "/api/v1/findings"
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.cfg.Token)
	req.Header.Set("X-Org-ID", h.cfg.OrgID)
	req.Header.Set("User-Agent", "ARES-Engine/1.0")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("push request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push failed (status %d): %s", resp.StatusCode, string(body))
	}

	logger.Info(fmt.Sprintf("[Federated] Pushed %d findings to hub", len(toSend)))
	return nil
}

func (h *FederatedHub) Pull(ctx context.Context) error {
	if !strings.HasPrefix(strings.ToLower(h.cfg.URL), "https://") {
		return fmt.Errorf("federated hub URL must use HTTPS: %s", h.cfg.URL)
	}
	endpoint := h.cfg.URL + "/api/v1/findings?since=" +
		time.Now().Add(-24*time.Hour).Format(time.RFC3339)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+h.cfg.Token)
	req.Header.Set("X-Org-ID", h.cfg.OrgID)
	req.Header.Set("User-Agent", "ARES-Engine/1.0")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("pull request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull failed (status %d): %s", resp.StatusCode, string(body))
	}

	var findings []SharedFinding
	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	h.mu.Lock()
	h.inbox = append(h.inbox, findings...)
	if len(h.inbox) > 1000 {
		h.inbox = h.inbox[len(h.inbox)-1000:]
	}
	h.mu.Unlock()

	logger.Info(fmt.Sprintf("[Federated] Pulled %d findings from hub", len(findings)))
	return nil
}

func (h *FederatedHub) FilterByFramework(findings []SharedFinding, framework string) []SharedFinding {
	var filtered []SharedFinding
	for _, f := range findings {
		if strings.EqualFold(f.Framework, framework) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func (h *FederatedHub) Deduplicate(findings []SharedFinding) []SharedFinding {
	seen := make(map[string]bool)
	var result []SharedFinding
	for _, f := range findings {
		key := f.ID + ":" + f.Target
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}

func (h *FederatedHub) IsRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

func anonymizeFinding(f SharedFinding) SharedFinding {
	anonymized := f
	anonymized.Target = anonymizeString(f.Target)
	anonymized.Payload = anonymizeString(f.Payload)
	anonymized.Evidence = anonymizeString(f.Evidence)
	anonymized.Origin = anonymizeString(f.Origin)
	return anonymized
}

func anonymizeString(input string) string {
	result := input
	result = ipv4Pattern.ReplaceAllString(result, "[REDACTED_IP]")
	result = ipv6Pattern.ReplaceAllString(result, "[REDACTED_IP]")
	result = emailPattern.ReplaceAllString(result, "[REDACTED_EMAIL]")
	result = hostnamePattern.ReplaceAllString(result, "[REDACTED_HOST]")
	result = creditCardPattern.ReplaceAllString(result, "[REDACTED_CC]")
	result = ssnPattern.ReplaceAllString(result, "[REDACTED_SSN]")
	result = apiKeyPattern.ReplaceAllString(result, "[REDACTED_KEY]")
	result = passwordPattern.ReplaceAllString(result, "[REDACTED_PASSWORD]")
	return result
}

func AnonymizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "[REDACTED_IP]"
	}
	if parsed.To4() != nil {
		parts := parsed.To4()
		return fmt.Sprintf("%d.%d.[REDACTED].[REDACTED]", parts[0], parts[1])
	}
	return "[REDACTED_IP]"
}
