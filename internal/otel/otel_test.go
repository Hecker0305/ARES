package otel

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGetTracer(t *testing.T) {
	tr := GetTracer()
	if tr == nil {
		t.Fatal("expected non-nil tracer")
	}
}

func TestStartEndSpan(t *testing.T) {
	span := StartSpan("trace-1", "", "test-span")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if span.Name != "test-span" {
		t.Errorf("expected test-span, got %s", span.Name)
	}
	EndSpan(span)
	if span.EndTime.IsZero() {
		t.Error("expected EndTime to be set")
	}
}

func TestSetStatus(t *testing.T) {
	span := StartSpan("t", "", "status-test")
	SetStatus(span, SpanOK)
	if span.Status != SpanOK {
		t.Errorf("expected SpanOK, got %v", span.Status)
	}
	SetStatus(span, SpanError)
	EndSpan(span)
}

func TestSetAttribute(t *testing.T) {
	span := StartSpan("t", "", "attr-test")
	SetAttribute(span, "key1", "value1")
	if span.Attributes["key1"] != "value1" {
		t.Errorf("expected value1, got %s", span.Attributes["key1"])
	}
	EndSpan(span)
}

func TestAddEvent(t *testing.T) {
	span := StartSpan("t", "", "event-test")
	AddEvent(span, "test-event", map[string]string{"key": "val"})
	if len(span.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(span.Events))
	}
	EndSpan(span)
}

func TestConsoleExporter(t *testing.T) {
	e := ConsoleExporter{}
	span := &Span{Name: "test", TraceID: "t", SpanID: "s", StartTime: time.Now(), EndTime: time.Now()}
	err := e.Export(*span)
	if err != nil {
		t.Errorf("Export error: %v", err)
	}
	err = e.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}
}

func TestFileExporter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otel.log")
	e, err := NewFileExporter(path)
	if err != nil {
		t.Fatalf("NewFileExporter error: %v", err)
	}
	span := &Span{Name: "file-test", TraceID: "t", SpanID: "s", StartTime: time.Now(), EndTime: time.Now()}
	err = e.Export(*span)
	if err != nil {
		t.Errorf("Export error: %v", err)
	}
	err = e.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}
}

func TestTracerAddExporter(t *testing.T) {
	tr := GetTracer()
	tr.AddExporter(ConsoleExporter{})
}

func TestConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			span := StartSpan("t", "", "conc-test")
			SetAttribute(span, "k", "v")
			AddEvent(span, "e", nil)
			EndSpan(span)
		}()
	}
	wg.Wait()
}

func TestSpanStatusValues(t *testing.T) {
	if SpanOK != 0 {
		t.Error("SpanOK mismatch")
	}
	if SpanError != 1 {
		t.Error("SpanError mismatch")
	}
}
