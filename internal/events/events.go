package events

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

const maxDispatchWorkers = 100

var dispatchSemaphore = make(chan struct{}, maxDispatchWorkers)

type EventType string

const (
	TargetDiscovered      EventType = "target.discovered"
	TargetFingerprinted   EventType = "target.fingerprinted"
	ServiceDiscovered     EventType = "service.discovered"
	VulnerabilityFound    EventType = "vulnerability.found"
	FindingStatusChanged  EventType = "finding.status_changed"
	VerificationStarted   EventType = "verification.started"
	VerificationCompleted EventType = "verification.completed"
	VerificationConfirmed EventType = "verification.confirmed"
	VerificationFalsePos  EventType = "verification.false_positive"
	ExploitAttempted      EventType = "exploit.attempted"
	ExploitSucceeded      EventType = "exploit.succeeded"
	ExploitFailed         EventType = "exploit.failed"
	ChainDiscovered       EventType = "chain.discovered"
	ChainEscalated        EventType = "chain.escalated"
	CredentialFound       EventType = "credential.found"
	SessionEstablished    EventType = "session.established"
	PolicyDenied          EventType = "policy.denied"
	PolicyAllowed         EventType = "policy.allowed"
	ReplayStarted         EventType = "replay.started"
	ReplayCompleted       EventType = "replay.completed"
	AgentStarted          EventType = "agent.started"
	AgentCompleted        EventType = "agent.completed"
	AgentError            EventType = "agent.error"
	PhaseChanged          EventType = "phase.changed"
	ResourceExceeded      EventType = "resource.exceeded"
	TaintPropagated       EventType = "taint.propagated"
	ProvenanceRecorded    EventType = "provenance.recorded"
)

var sensitiveEventTypes = map[EventType]bool{
	CredentialFound:    true,
	SessionEstablished: true,
	ExploitSucceeded:   true,
	ChainEscalated:     true,
}

var sensitiveFields = []string{
	"password", "secret", "token", "api_key", "apikey",
	"access_key", "secret_key", "private_key", "credential",
	"session_id", "session_token", "auth_token", "jwt",
	"cookie", "authorization", "bearer",
}

type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Source    string                 `json:"source"`
	TargetID  string                 `json:"target_id,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	TraceID   string                 `json:"trace_id,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

type Handler func(Event)

type Subscriber struct {
	handler       Handler
	allowedEvents map[EventType]bool
	allowAll      bool
	priority      int
}

type Bus struct {
	mu          sync.RWMutex
	subscribers map[EventType][]*Subscriber
	history     []Event
	maxHistory  int
}

func New() *Bus {
	return &Bus{
		subscribers: make(map[EventType][]*Subscriber),
		history:     make([]Event, 0, 1000),
		maxHistory:  10000,
	}
}

func (b *Bus) Subscribe(eventType EventType, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sub := &Subscriber{
		handler: handler,
		allowedEvents: map[EventType]bool{
			eventType: true,
		},
		priority: 0,
	}
	b.subscribers[eventType] = append(b.subscribers[eventType], sub)
}

func (b *Bus) SubscribeWithAccess(eventType EventType, handler Handler, allowedEvents []EventType) {
	b.mu.Lock()
	defer b.mu.Unlock()

	allowed := make(map[EventType]bool)
	for _, et := range allowedEvents {
		allowed[et] = true
	}

	sub := &Subscriber{
		handler:       handler,
		allowedEvents: allowed,
		priority:      0,
	}
	b.subscribers[eventType] = append(b.subscribers[eventType], sub)
}

func (b *Bus) SubscribeAll(handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sub := &Subscriber{
		handler:  handler,
		allowAll: true,
		priority: 0,
	}
	b.subscribers["*"] = append(b.subscribers["*"], sub)
}

func (b *Bus) Publish(evt Event) {
	if evt.ID == "" {
		evt.ID = uuid.New()
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}

	evt = redactSensitiveFields(evt)

	b.mu.RLock()
	handlers := b.subscribers[evt.Type]
	allHandlers := b.subscribers["*"]
	b.mu.RUnlock()

	for _, sub := range handlers {
		if !sub.canAccess(evt.Type) {
			continue
		}
		go dispatchWithTimeout(sub.handler, evt)
	}
	for _, sub := range allHandlers {
		if !sub.allowAll {
			continue
		}
		if sensitiveEventTypes[evt.Type] && !sub.canAccess(evt.Type) {
			continue
		}
		go dispatchWithTimeout(sub.handler, evt)
	}

	b.mu.Lock()
	b.history = append(b.history, evt)
	if len(b.history) > b.maxHistory {
		b.history = b.history[len(b.history)-b.maxHistory:]
	}
	b.mu.Unlock()
}

func (s *Subscriber) canAccess(eventType EventType) bool {
	if s.allowAll {
		return true
	}
	return s.allowedEvents[eventType]
}

func redactSensitiveFields(evt Event) Event {
	if evt.Data == nil {
		return evt
	}

	redacted := make(map[string]interface{})
	for k, v := range evt.Data {
		lower := strings.ToLower(k)
		if isSensitiveField(lower) {
			redacted[k] = "[REDACTED]"
		} else {
			redacted[k] = v
		}
	}
	evt.Data = redacted
	return evt
}

func isSensitiveField(field string) bool {
	for _, sf := range sensitiveFields {
		if strings.Contains(field, sf) {
			return true
		}
	}
	return false
}

func (b *Bus) History(eventType EventType) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if eventType == "" || eventType == "*" {
		result := make([]Event, len(b.history))
		copy(result, b.history)
		return result
	}
	var filtered []Event
	for _, evt := range b.history {
		if evt.Type == eventType {
			filtered = append(filtered, redactSensitiveFields(evt))
		}
	}
	return filtered
}

func (b *Bus) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.history = make([]Event, 0, b.maxHistory)
}

func (b *Bus) Stats() map[string]int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	stats := make(map[string]int)
	for _, evt := range b.history {
		stats[string(evt.Type)]++
	}
	return stats
}

func NewEvent(eventType EventType, source string, data map[string]interface{}) Event {
	return Event{
		ID:        uuid.New(),
		Type:      eventType,
		Source:    source,
		Data:      data,
		Timestamp: time.Now(),
	}
}

func NewEventWithTrace(eventType EventType, source, traceID string, data map[string]interface{}) Event {
	evt := NewEvent(eventType, source, data)
	evt.TraceID = traceID
	return evt
}

func dispatchWithTimeout(h Handler, evt Event) {
	dispatchSemaphore <- struct{}{}
	defer func() { <-dispatchSemaphore }()

	defer func() {
		if r := recover(); r != nil {
			logger.Error(fmt.Sprintf("[events] handler panic: %v", r))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{}, 1)
	go func() {
		h(evt)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (e Event) String() string {
	return fmt.Sprintf("[%s] %s from %s", e.Type, e.ID, e.Source)
}
