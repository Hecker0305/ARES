package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

const maxBodySize = 1 << 20

type IncomingEvent struct {
	Source     string                 `json:"source"`
	EventType  string                 `json:"event_type"`
	Payload    map[string]interface{} `json:"payload"`
	ReceivedAt time.Time              `json:"received_at"`
	RawBody    string                 `json:"-"`
}

type incomingRateEntry struct {
	count       int
	windowStart time.Time
}

type IncomingWebhookHandler struct {
	events     chan IncomingEvent
	secret     string
	rateMu     sync.Mutex
	rateBucket map[string]*incomingRateEntry
	rateLimit  int
	rateWin    time.Duration
	stopCh     chan struct{}
}

func NewIncomingWebhookHandler(secret string) *IncomingWebhookHandler {
	h := &IncomingWebhookHandler{
		events:     make(chan IncomingEvent, 100),
		secret:     secret,
		rateBucket: make(map[string]*incomingRateEntry),
		rateLimit:  60,
		rateWin:    time.Minute,
		stopCh:     make(chan struct{}),
	}
	go h.rateCleanupLoop()
	return h
}

func (h *IncomingWebhookHandler) rateCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.rateMu.Lock()
			cutoff := time.Now().Add(-2 * h.rateWin)
			for ip, entry := range h.rateBucket {
				if entry.windowStart.Before(cutoff) {
					delete(h.rateBucket, ip)
				}
			}
			h.rateMu.Unlock()
		}
	}
}

func (h *IncomingWebhookHandler) Stop() {
	close(h.stopCh)
}

func (h *IncomingWebhookHandler) allow(ip string) bool {
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	now := time.Now()
	entry, ok := h.rateBucket[ip]
	if !ok || now.Sub(entry.windowStart) > h.rateWin {
		h.rateBucket[ip] = &incomingRateEntry{count: 1, windowStart: now}
		return true
	}
	entry.count++
	return entry.count <= h.rateLimit
}

func (h *IncomingWebhookHandler) Events() <-chan IncomingEvent {
	return h.events
}

func (h *IncomingWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.allow(r.RemoteAddr) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		http.Error(w, "unsupported content type: must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	if h.secret == "" {
		if err := validateIncomingPayload(body); err != nil {
			logger.Error(fmt.Sprintf("[Webhook-Receiver] payload validation failed: %v", err))
			http.Error(w, "payload rejected", http.StatusBadRequest)
			return
		}
	}

	ev := IncomingEvent{
		ReceivedAt: time.Now(),
		RawBody:    string(body),
	}

	source := r.Header.Get("User-Agent")
	if source != "" {
		ev.Source = source
	}
	eventType := r.Header.Get("X-GitHub-Event")
	if eventType != "" {
		ev.EventType = eventType
		ev.Source = "github"
	}
	eventType = r.Header.Get("X-GitLab-Event")
	if eventType != "" {
		ev.EventType = eventType
		ev.Source = "gitlab"
	}
	eventType = r.Header.Get("X-Jira-Webhook-Event")
	if eventType != "" {
		ev.EventType = eventType
		ev.Source = "jira"
	}
	if ev.Source == "" {
		ev.Source = "unknown"
	}

	if h.secret != "" {
		if err := verifySignature(r, body, h.secret); err != nil {
			logger.Error(fmt.Sprintf("[Webhook-Receiver] signature verification failed: %v", err))
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	if err := json.Unmarshal(body, &ev.Payload); err != nil {
		ev.Payload = map[string]interface{}{
			"raw": string(body),
		}
	}

	select {
	case h.events <- ev:
	default:
		logger.Info(fmt.Sprintf("[Webhook-Receiver] event channel full, dropping event from %s", ev.Source))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

func verifySignature(r *http.Request, body []byte, secret string) error {
	sig := r.Header.Get("X-Hub-Signature-256")
	if sig == "" {
		sig = r.Header.Get("X-ARES-Signature-256")
	}
	if sig == "" {
		return fmt.Errorf("no signature header")
	}

	sig = strings.TrimPrefix(sig, "sha256=")
	sig = strings.TrimSpace(sig)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func validateIncomingPayload(body []byte) error {
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}
