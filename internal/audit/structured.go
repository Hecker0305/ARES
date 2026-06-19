package audit

import (
	"fmt"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type StructuredEntry struct {
	Timestamp  time.Time              `json:"timestamp"`
	Actor      string                 `json:"actor"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id,omitempty"`
	Result     string                 `json:"result"`
	RemoteAddr string                 `json:"remote_addr,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
	DurationMs int64                  `json:"duration_ms,omitempty"`
}

type StructuredLogger struct {
	mu       sync.RWMutex
	enabled  bool
	excluded map[string]bool
}

var defaultStructured = &StructuredLogger{
	enabled:  true,
	excluded: make(map[string]bool),
}

func GetStructured() *StructuredLogger {
	return defaultStructured
}

func (l *StructuredLogger) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

func (l *StructuredLogger) ExcludeAction(action string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.excluded[action] = true
}

func (l *StructuredLogger) Log(actor, action, resource, resourceID, result string, opts ...StructuredOption) {
	l.mu.RLock()
	enabled := l.enabled
	excluded := l.excluded[action]
	l.mu.RUnlock()

	if !enabled || excluded {
		return
	}

	entry := StructuredEntry{
		Timestamp:  time.Now(),
		Actor:      actor,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Result:     result,
	}

	for _, opt := range opts {
		opt(&entry)
	}

	fields := logger.Fields{
		"audit":      true,
		"actor":      entry.Actor,
		"action":     entry.Action,
		"resource":   entry.Resource,
		"resourceID": entry.ResourceID,
		"result":     entry.Result,
	}
	if entry.RemoteAddr != "" {
		fields["remoteAddr"] = entry.RemoteAddr
	}
	if entry.UserAgent != "" {
		fields["userAgent"] = entry.UserAgent
	}
	if entry.RequestID != "" {
		fields["requestID"] = entry.RequestID
	}
	if entry.DurationMs > 0 {
		fields["durationMs"] = entry.DurationMs
	}
	if len(entry.Details) > 0 {
		fields["details"] = entry.Details
	}

	logger.Info(fmt.Sprintf("[Audit] %s %s %s/%s -> %s", entry.Actor, entry.Action, entry.Resource, entry.ResourceID, entry.Result), fields)
}

func LogStructured(actor, action, resource, resourceID, result string, opts ...StructuredOption) {
	defaultStructured.Log(actor, action, resource, resourceID, result, opts...)
}

type StructuredOption func(*StructuredEntry)

func WithRemoteAddr(addr string) StructuredOption {
	return func(e *StructuredEntry) { e.RemoteAddr = addr }
}

func WithUserAgent(ua string) StructuredOption {
	return func(e *StructuredEntry) { e.UserAgent = ua }
}

func WithRequestID(id string) StructuredOption {
	return func(e *StructuredEntry) { e.RequestID = id }
}

func WithDetails(details map[string]interface{}) StructuredOption {
	return func(e *StructuredEntry) { e.Details = details }
}

func WithDuration(d time.Duration) StructuredOption {
	return func(e *StructuredEntry) { e.DurationMs = d.Milliseconds() }
}

func WithDetail(key string, value interface{}) StructuredOption {
	return func(e *StructuredEntry) {
		if e.Details == nil {
			e.Details = make(map[string]interface{})
		}
		e.Details[key] = value
	}
}
