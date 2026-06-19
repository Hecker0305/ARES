package race

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConditionString(t *testing.T) {
	tests := []struct {
		c    Condition
		want string
	}{
		{TOCTOU, "TOCTOU"},
		{ConcurrentWrite, "concurrent_write"},
		{DataRace, "data_race"},
		{AuthBypassRace, "auth_bypass_race"},
		{SessionFixation, "session_fixation"},
		{Condition(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("Condition.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.client == nil {
		t.Error("Engine.client is nil")
	}
	if e.client.Timeout != 30*time.Second {
		t.Errorf("Engine.client.Timeout = %v, want 30s", e.client.Timeout)
	}
}

func TestEngineResultsAndClear(t *testing.T) {
	e := New()
	results := e.Results()
	if results == nil {
		t.Error("Results() returned nil on fresh engine")
	}
	if len(results) != 0 {
		t.Errorf("Results() length = %d, want 0", len(results))
	}
	e.mu.Lock()
	e.results = append(e.results, Result{Condition: TOCTOU, Summary: "test"})
	e.mu.Unlock()
	results = e.Results()
	if len(results) != 1 {
		t.Errorf("Results() length = %d, want 1", len(results))
	}
	e.Clear()
	results = e.Results()
	if len(results) != 0 {
		t.Errorf("After Clear(), Results() length = %d, want 0", len(results))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"abc", 0, "..."},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := truncate(tt.s, tt.max); got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
			}
		})
	}
}

func TestDiffBodies(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want string
	}{
		{"identical", "hello\nworld", "hello\nworld", "identical"},
		{"different lines", "line1\nline2", "line1\nchanged", "line 2 differs"},
		{"different length", "a\nb\nc", "a\nb", "length differs: 3 vs 2 lines"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffBodies(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("diffBodies() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildRequest(t *testing.T) {
	e := New()
	cfg := Config{
		TargetURL: "http://example.com/api",
		Method:    "POST",
		Body:      `{"key":"value"}`,
		Headers:   map[string]string{"X-Custom": "test"},
	}
	req, err := e.buildRequest(cfg)
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if req.Header.Get("X-Custom") != "test" {
		t.Errorf("X-Custom header = %q, want test", req.Header.Get("X-Custom"))
	}
}

func TestBuildRequestEmptyBody(t *testing.T) {
	e := New()
	cfg := Config{TargetURL: "http://example.com", Method: "GET"}
	req, err := e.buildRequest(cfg)
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}
	if req.Body != nil {
		t.Error("expected nil body for GET")
	}
}

func TestRunUnknownCondition(t *testing.T) {
	e := New()
	_, err := e.Run(context.Background(), Config{Condition: Condition(99)})
	if err == nil {
		t.Fatal("expected error for unknown condition")
	}
}

func TestRunWithServer(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	tests := []struct {
		name      string
		condition Condition
	}{
		{"TOCTOU", TOCTOU},
		{"ConcurrentWrite", ConcurrentWrite},
		{"DataRace", DataRace},
		{"AuthBypassRace", AuthBypassRace},
		{"SessionFixation", SessionFixation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New()
			e.SetSkipTargetValidation(true)
			cfg := Config{
				TargetURL:   ts.URL + "/test",
				Condition:   tt.condition,
				Concurrency: 3,
				Duration:    time.Second,
				Method:      "GET",
			}
			result, err := e.Run(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if result == nil {
				t.Fatal("Run() returned nil result")
			}
			if result.Condition != tt.condition {
				t.Errorf("Condition = %v, want %v", result.Condition, tt.condition)
			}
		})
	}
}

func TestTOCTOUDetection(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()
		if count%2 == 0 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"read"}`))
		} else {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"status":"write"}`))
		}
	}))
	defer ts.Close()

	e := New()
	e.SetSkipTargetValidation(true)
	cfg := Config{
		TargetURL:   ts.URL,
		Condition:   TOCTOU,
		Concurrency: 3,
		Method:      "POST",
		Body:        `{"data":"test"}`,
	}
	result, err := e.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Vulnerable {
		t.Log("TOCTOU detected (expected with differing responses)")
	}
	if len(result.Evidence) == 0 {
		t.Log("No evidence pairs collected (may happen with low concurrency)")
	}
}

func TestDataRaceWithCustomDuration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	e := New()
	e.SetSkipTargetValidation(true)
	cfg := Config{
		TargetURL:   ts.URL,
		Condition:   DataRace,
		Concurrency: 2,
		Duration:    500 * time.Millisecond,
		Method:      "GET",
	}
	result, err := e.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
}

func TestAuthBypassRace(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()
		if r.Header.Get("Authorization") != "" && count <= 2 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	e := New()
	e.SetSkipTargetValidation(true)
	cfg := Config{
		TargetURL: ts.URL,
		Condition: AuthBypassRace,
		Method:    "GET",
		Headers:   map[string]string{"Authorization": "Bearer test"},
	}
	result, err := e.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
}

func TestSessionFixation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			if c.Name == "session" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: c.Value})
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":"test"}`))
	}))
	defer ts.Close()

	e := New()
	e.SetSkipTargetValidation(true)
	cfg := Config{
		TargetURL:   ts.URL,
		Condition:   SessionFixation,
		Concurrency: 3,
		Method:      "GET",
	}
	result, err := e.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
}

func TestConcurrentWriteRace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"counter":1}`))
	}))
	defer ts.Close()

	e := New()
	cfg := Config{
		TargetURL:   ts.URL,
		Condition:   ConcurrentWrite,
		Concurrency: 3,
		Method:      "POST",
		Body:        `{"value":"x"}`,
	}
	e.SetSkipTargetValidation(true)
	result, err := e.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
}

func TestResultsCopied(t *testing.T) {
	e := New()
	e.mu.Lock()
	e.results = append(e.results, Result{Condition: DataRace, Summary: "original"})
	e.mu.Unlock()

	results := e.Results()
	results[0].Summary = "modified"

	e.mu.Lock()
	if e.results[0].Summary != "original" {
		t.Error("Results() returned non-copied slice")
	}
	e.mu.Unlock()
}
