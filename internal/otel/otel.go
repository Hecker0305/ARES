package otel

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type SpanStatus int

const (
	SpanOK    SpanStatus = 0
	SpanError SpanStatus = 1
)

func NewTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		logger.Error(fmt.Sprintf("[OTEL] Failed to generate trace ID: %v", err))
		return uuid.New()
	}
	return hex.EncodeToString(b)
}

func NewSpanID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		logger.Error(fmt.Sprintf("[OTEL] Failed to generate span ID: %v", err))
		return uuid.New()
	}
	return hex.EncodeToString(b)
}

type Span struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	ParentID   string            `json:"parent_span_id"`
	Name       string            `json:"name"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
	Status     SpanStatus        `json:"status"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Events     []SpanEvent       `json:"events,omitempty"`
}

type SpanEvent struct {
	Name       string            `json:"name"`
	Timestamp  time.Time         `json:"timestamp"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type Exporter interface {
	Export(span Span) error
	Close() error
}

type ConsoleExporter struct{}

func (e ConsoleExporter) Export(span Span) error {
	duration := span.EndTime.Sub(span.StartTime)
	status := "OK"
	if span.Status == SpanError {
		status = "ERROR"
	}
	logger.Info(fmt.Sprintf("[OTEL] %s | trace=%s span=%s parent=%s | %s (%v)",
		span.Name, span.TraceID, span.SpanID, span.ParentID, status, duration))
	return nil
}

func (e ConsoleExporter) Close() error { return nil }

type OTLPExporter struct {
	mu       sync.Mutex
	endpoint string
	headers  map[string]string
	client   *http.Client
	batch    []otlpSpan
}

type otlpSpan struct {
	TraceID    string          `json:"traceId"`
	SpanID     string          `json:"spanId"`
	ParentID   string          `json:"parentSpanId,omitempty"`
	Name       string          `json:"name"`
	StartTime  string          `json:"startTime"`
	EndTime    string          `json:"endTime"`
	Status     otlpStatus      `json:"status"`
	Attributes []otlpAttribute `json:"attributes,omitempty"`
	Events     []otlpSpanEvent `json:"events,omitempty"`
}

type otlpStatus struct {
	Code string `json:"code"`
}

type otlpAttribute struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type otlpSpanEvent struct {
	Name       string          `json:"name"`
	Timestamp  string          `json:"timestamp"`
	Attributes []otlpAttribute `json:"attributes,omitempty"`
}

func NewOTLPExporter(endpoint string, headers map[string]string) *OTLPExporter {
	return NewOTLPExporterWithTLS(endpoint, headers, true)
}

func NewOTLPExporterWithTLS(endpoint string, headers map[string]string, useTLS bool) *OTLPExporter {
	if !strings.HasPrefix(endpoint, "http") {
		if useTLS {
			endpoint = "https://" + endpoint
		} else {
			endpoint = "http://" + endpoint
		}
	}
	if headers == nil {
		headers = make(map[string]string)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if !useTLS {
		logger.Warn("[OTEL] TLS disabled for OTLP exporter - telemetry data will be sent in plaintext (not recommended for production)")
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &OTLPExporter{
		endpoint: endpoint + "/v1/traces",
		headers:  headers,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
	}
}

func (e *OTLPExporter) Export(span Span) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	otlp := otlpSpan{
		TraceID:   span.TraceID,
		SpanID:    span.SpanID,
		ParentID:  span.ParentID,
		Name:      span.Name,
		StartTime: span.StartTime.Format(time.RFC3339Nano),
		EndTime:   span.EndTime.Format(time.RFC3339Nano),
		Status:    otlpStatus{Code: "OK"},
	}
	if span.Status == SpanError {
		otlp.Status.Code = "ERROR"
	}
	for k, v := range span.Attributes {
		otlp.Attributes = append(otlp.Attributes, otlpAttribute{Key: k, Value: v})
	}
	for _, ev := range span.Events {
		otlp.Events = append(otlp.Events, otlpSpanEvent{
			Name:       ev.Name,
			Timestamp:  ev.Timestamp.Format(time.RFC3339Nano),
			Attributes: []otlpAttribute{},
		})
	}
	e.batch = append(e.batch, otlp)
	if len(e.batch) >= 10 {
		return e.flushLocked()
	}
	return nil
}

func (e *OTLPExporter) flushLocked() error {
	if len(e.batch) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]interface{}{
		"resourceSpans": []map[string]interface{}{
			{
				"resource": map[string]interface{}{},
				"scopeSpans": []map[string]interface{}{
					{
						"scope": map[string]interface{}{"name": "ares-engine"},
						"spans": e.batch,
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("otlp marshal: %w", err)
	}
	req, err := http.NewRequest("POST", e.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	e.batch = e.batch[:0]
	return nil
}

func (e *OTLPExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flushLocked()
}

type FileExporter struct {
	filePath string
	file     *os.File
	mu       sync.Mutex
}

func NewFileExporter(path string) (*FileExporter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open trace file: %w", err)
	}
	return &FileExporter{filePath: path, file: f}, nil
}

func (e *FileExporter) Export(span Span) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	line := fmt.Sprintf("%s|%s|%s|%s|%s|%d\n",
		span.TraceID, span.SpanID, span.ParentID, span.Name,
		span.StartTime.Format(time.RFC3339Nano), span.Status)
	_, err := e.file.WriteString(line)
	return err
}

func (e *FileExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.file.Close()
}

type Tracer struct {
	mu        sync.RWMutex
	exporters []Exporter
	active    map[string]*Span
	spanOrder []string
}

var globalTracer *Tracer
var globalOnce sync.Once

func GetTracer() *Tracer {
	globalOnce.Do(func() {
		globalTracer = &Tracer{
			exporters: []Exporter{ConsoleExporter{}},
			active:    make(map[string]*Span),
			spanOrder: make([]string, 0),
		}
	})
	return globalTracer
}

func (t *Tracer) AddExporter(e Exporter) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.exporters = append(t.exporters, e)
}

func (t *Tracer) StartSpan(traceID, parentID, name string) *Span {
	t.mu.Lock()
	defer t.mu.Unlock()

	spanID := NewSpanID()
	span := &Span{
		TraceID:    traceID,
		SpanID:     spanID,
		ParentID:   parentID,
		Name:       name,
		StartTime:  time.Now(),
		Status:     SpanOK,
		Attributes: make(map[string]string),
		Events:     make([]SpanEvent, 0),
	}
	if len(t.active) >= 10000 {
		oldest := t.spanOrder[0]
		t.spanOrder = t.spanOrder[1:]
		delete(t.active, oldest)
	}
	t.active[spanID] = span
	t.spanOrder = append(t.spanOrder, spanID)
	return span
}

func (t *Tracer) EndSpan(span *Span) {
	if span == nil {
		return
	}
	span.EndTime = time.Now()

	t.mu.Lock()
	delete(t.active, span.SpanID)
	exporters := make([]Exporter, len(t.exporters))
	copy(exporters, t.exporters)
	t.mu.Unlock()

	for _, e := range exporters {
		if err := e.Export(*span); err != nil {
			logger.Error(fmt.Sprintf("[OTEL] export error: %v", err))
		}
	}
}

func (t *Tracer) AddEvent(span *Span, name string, attrs map[string]string) {
	if span == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	span.Events = append(span.Events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attrs,
	})
}

func (t *Tracer) SetStatus(span *Span, status SpanStatus) {
	if span == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	span.Status = status
}

func (t *Tracer) SetAttribute(span *Span, key, value string) {
	if span == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	span.Attributes[key] = value
}

func StartSpan(traceID, parentID, name string) *Span {
	return GetTracer().StartSpan(traceID, parentID, name)
}

func EndSpan(span *Span) {
	GetTracer().EndSpan(span)
}

func AddEvent(span *Span, name string, attrs map[string]string) {
	GetTracer().AddEvent(span, name, attrs)
}

func SetStatus(span *Span, status SpanStatus) {
	GetTracer().SetStatus(span, status)
}

func SetAttribute(span *Span, key, value string) {
	GetTracer().SetAttribute(span, key, value)
}

// InitFromEnv auto-configures the global tracer from environment variables.
// ARES_OTEL_ENDPOINT: OTLP collector endpoint (e.g. http://localhost:4318)
// ARES_OTEL_AUTH_HEADER: Authorization header for OTLP (e.g. Bearer <token>)
// ARES_OTEL_SERVICE_NAME: Service name for resource attributes
// ARES_OTEL_FILE_EXPORT: File path for local trace export
func InitFromEnv() {
	endpoint := os.Getenv("ARES_OTEL_ENDPOINT")
	authHeader := os.Getenv("ARES_OTEL_AUTH_HEADER")
	serviceName := os.Getenv("ARES_OTEL_SERVICE_NAME")
	fileExport := os.Getenv("ARES_OTEL_FILE_EXPORT")

	t := GetTracer()

	if serviceName != "" {
		t.mu.Lock()
		for _, span := range t.active {
			span.Attributes["service.name"] = serviceName
		}
		t.mu.Unlock()
	}

	if endpoint != "" {
		headers := make(map[string]string)
		if authHeader != "" {
			headers["Authorization"] = authHeader
		}
		exp := NewOTLPExporter(endpoint, headers)
		t.AddExporter(exp)
		logger.Info(fmt.Sprintf("[OTEL] OTLP exporter initialized: %s", endpoint))
	}

	if fileExport != "" {
		exp, err := NewFileExporter(fileExport)
		if err != nil {
			logger.Error(fmt.Sprintf("[OTEL] File exporter failed: %v", err))
		} else {
			t.AddExporter(exp)
			logger.Info(fmt.Sprintf("[OTEL] File exporter initialized: %s", fileExport))
		}
	}

	if endpoint == "" && fileExport == "" {
		logger.Info("[OTEL] No exporter configured (console exporter active). Set ARES_OTEL_ENDPOINT or ARES_OTEL_FILE_EXPORT")
	}
}
