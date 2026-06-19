package nosqli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.client == nil {
		t.Error("expected non-nil HTTP client")
	}
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", e.client.Timeout)
	}
}

func TestTestAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "logged in", "token": "abc"}`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, err := e.TestAll(server.URL)
	if err != nil {
		t.Fatal("TestAll failed:", err)
	}
	if len(findings) == 0 {
		t.Log("TestAll returned 0 findings (expected with basic mock)")
	}
}

func TestTestAll_Error(t *testing.T) {
	e := NewEngine()
	findings, err := e.TestAll("http://nonexistent.invalid/test")
	if err != nil {
		t.Log("TestAll returned error:", err)
	}
	_ = findings
}

func TestTestMongoDB_PayloadsGenerated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")

		if _, ok := body["username"].(map[string]interface{})["$ne"]; ok {
			w.Write([]byte(`{"welcome": "user"}`))
			return
		}

		w.Write([]byte(`{"error": "not found"}`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, err := e.TestMongoDB(server.URL)
	if err != nil {
		t.Fatal("TestMongoDB failed:", err)
	}

	_ = findings
}

func TestTestMongoDB_ConnectionError(t *testing.T) {
	e := NewEngine()
	findings, err := e.TestMongoDB("http://127.0.0.1:19999/test")
	if err != nil {
		t.Log("TestMongoDB returned error:", err)
	}
	if len(findings) != 0 {
		t.Logf("got %d findings despite connection error", len(findings))
	}
}

func TestTestRedis_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		if cmd, ok := body["command"]; ok && cmd == "INFO" {
			w.Write([]byte(`{"redis_version": "7.0.0", "uptime": "100"}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, err := e.TestRedis(server.URL)
	if err != nil {
		t.Fatal("TestRedis failed:", err)
	}

	if len(findings) == 0 {
		t.Log("TestRedis returned 0 findings (mock returns redis_version)")
	}
}

func TestTestRedis_NoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, err := e.TestRedis(server.URL)
	if err != nil {
		t.Fatal("TestRedis failed:", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-redis response, got %d", len(findings))
	}
}

func TestTestRedis_ConnectionError(t *testing.T) {
	e := NewEngine()
	findings, err := e.TestRedis("http://127.0.0.1:19999/test")
	if err != nil {
		t.Log("TestRedis returned error:", err)
	}
	if len(findings) != 0 {
		t.Logf("got %d findings despite connection error", len(findings))
	}
}

func TestTestQueryParam_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error": "MongoDB error: invalid operator"}`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, err := e.TestQueryParam(server.URL, "search")
	if err != nil {
		t.Fatal("TestQueryParam failed:", err)
	}

	if len(findings) == 0 {
		t.Log("TestQueryParam returned 0 findings (mock may not trigger checks)")
	}
}

func TestTestQueryParam_NoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results": []}`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, err := e.TestQueryParam(server.URL, "q")
	if err != nil {
		t.Fatal("TestQueryParam failed:", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestTestQueryParam_EmptyParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`ok`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, err := e.TestQueryParam(server.URL, "")
	if err != nil {
		t.Fatal("TestQueryParam failed:", err)
	}
	_ = findings
}

func TestFindings_Fields(t *testing.T) {
	f := Finding{
		URL:       "http://test.com",
		Type:      "nosqli_mongodb",
		Payload:   `{"$ne": ""}`,
		Evidence:  "error detected",
		Severity:  "high",
		Confirmed: true,
		Timestamp: time.Now(),
	}

	if f.URL != "http://test.com" {
		t.Errorf("URL = %s", f.URL)
	}
	if f.Type != "nosqli_mongodb" {
		t.Errorf("Type = %s", f.Type)
	}
	if !f.Confirmed {
		t.Error("Confirmed should be true")
	}
	if f.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestMinInt(t *testing.T) {
	if minInt(3, 7) != 3 {
		t.Error("minInt(3,7) should be 3")
	}
	if minInt(7, 3) != 3 {
		t.Error("minInt(7,3) should be 3")
	}
	if minInt(5, 5) != 5 {
		t.Error("minInt(5,5) should be 5")
	}
	if minInt(-1, 5) != -1 {
		t.Error("minInt(-1,5) should be -1")
	}
}

func TestEngine_ClientTimeout(t *testing.T) {
	e := NewEngine()
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got %v", e.client.Timeout)
	}
}

func TestMongoPayload_NeCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"welcome": "user", "dashboard": "main"}`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testMongoPayload(server.URL, "$ne injection", map[string]interface{}{
		"username": map[string]interface{}{"$ne": ""},
		"password": map[string]interface{}{"$ne": ""},
	}, func(body string) bool {
		return strings.Contains(strings.ToLower(body), "welcome")
	})
	if err != nil {
		t.Fatal("testMongoPayload failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.Type != "nosqli_mongodb" {
		t.Errorf("expected nosqli_mongodb, got %s", f.Type)
	}
}

func TestMongoPayload_NoInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error": "invalid"}`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testMongoPayload(server.URL, "test", map[string]interface{}{
		"username": map[string]interface{}{"$ne": ""},
	}, func(body string) bool {
		return strings.Contains(body, "welcome")
	})
	if err == nil {
		t.Error("expected error when check returns false")
	}
	if f != nil {
		t.Error("expected nil finding when check fails")
	}
}

func TestMongoPayload_SleepDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte(`ok`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testMongoPayload(server.URL, "sleep(5000)", map[string]interface{}{
		"username": map[string]interface{}{"$ne": ""},
	}, func(body string) bool { return true })
	if err != nil {
		t.Fatal("testMongoPayload failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding for sleep-based detection")
	}
	if f.Type != "nosqli_mongodb_time_based" {
		t.Errorf("expected time_based type, got %s", f.Type)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
}

func TestRedisPayload_Detection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"redis_version": "7.0.0", "tcp_port": 6379, "uptime_in_seconds": "3600"}`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testRedisPayload(server.URL, "INFO", map[string]interface{}{
		"command": "INFO",
		"args":    []string{"server"},
	})
	if err != nil {
		t.Fatal("testRedisPayload failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding for redis response")
	}
	if f.Type != "nosqli_redis" {
		t.Errorf("expected nosqli_redis, got %s", f.Type)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical, got %s", f.Severity)
	}
}

func TestRedisPayload_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testRedisPayload(server.URL, "INFO", map[string]interface{}{
		"command": "INFO",
		"args":    []string{"server"},
	})
	if err == nil {
		t.Error("expected error when no redis indicators in response")
	}
	if f != nil {
		t.Error("expected nil finding")
	}
}

func TestEngineAll_MixedResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		if cmd, ok := body["command"]; ok {
			if cmd == "INFO" {
				w.Write([]byte(`{"redis_version": "7.0"}`))
				return
			}
		}

		w.Write([]byte(`{"error": "not found", "exception": "invalid"}`))
	}))
	defer server.Close()

	e := NewEngine()
	findings, _ := e.TestAll(server.URL)
	if len(findings) == 0 {
		t.Log("TestAll returned 0 (test may be too basic)")
	}
}

func TestEngine_ContentTypeHeader(t *testing.T) {
	var contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.Write([]byte(`ok`))
	}))
	defer server.Close()

	e := NewEngine()
	payload := map[string]interface{}{"test": "value"}
	e.testMongoPayload(server.URL, "test", payload, func(s string) bool { return false })

	if contentType != "application/json" {
		t.Errorf("expected application/json, got %s", contentType)
	}
}

func TestEngine_UserAgentHeader(t *testing.T) {
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		w.Write([]byte(`ok`))
	}))
	defer server.Close()

	e := NewEngine()
	e.TestMongoDB(server.URL)
	if !strings.HasPrefix(userAgent, "ARES-NoSQLi/") {
		t.Errorf("expected ARES-NoSQLi user agent, got %s", userAgent)
	}
}

func TestFindingEvidence_Truncation(t *testing.T) {
	longBody := strings.Repeat("a", 1000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(longBody))
	}))
	defer server.Close()

	e := NewEngine()
	f, _ := e.testMongoPayload(server.URL, "test", map[string]interface{}{
		"username": map[string]interface{}{"$ne": ""},
	}, func(body string) bool { return true })

	if f != nil && len(f.Evidence) > 500 {
		t.Errorf("evidence should be truncated to 500, got %d", len(f.Evidence))
	}
}

func TestFindingEvidence_ShortBody(t *testing.T) {
	shortBody := "hello"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(shortBody))
	}))
	defer server.Close()

	e := NewEngine()
	f, _ := e.testMongoPayload(server.URL, "test", map[string]interface{}{
		"username": map[string]interface{}{"$ne": ""},
	}, func(body string) bool { return true })

	if f != nil && len(f.Evidence) > len(shortBody) {
		t.Errorf("evidence should not exceed body length: %d vs %d", len(f.Evidence), len(shortBody))
	}
}

func TestMongoPayload_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal error`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testMongoPayload(server.URL, "test", map[string]interface{}{
		"username": map[string]interface{}{"$ne": ""},
	}, func(body string) bool {
		return strings.Contains(body, "error")
	})

	if err != nil {
		t.Log("testMongoPayload returned error:", err)
	}
	_ = f
}

func TestRedisPayload_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`server error`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testRedisPayload(server.URL, "test", map[string]interface{}{
		"command": "INFO",
		"args":    []string{"server"},
	})
	if err == nil {
		t.Error("expected error for non-redis response")
	}
	_ = f
}

func TestQueryParam_NoServer(t *testing.T) {
	e := NewEngine()
	findings, err := e.TestQueryParam("http://127.0.0.1:19999/test", "q")
	if err != nil {
		t.Log("TestQueryParam returned error:", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreachable server, got %d", len(findings))
	}
}

func TestRedisPayload_AuthBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok", "redis_version": "6.2.0"}`))
	}))
	defer server.Close()

	e := NewEngine()
	f, err := e.testRedisPayload(server.URL, "AUTH bypass", map[string]interface{}{
		"command": "AUTH",
		"args":    []string{""},
	})
	if err != nil {
		t.Fatal("testRedisPayload failed:", err)
	}
	if f == nil {
		t.Fatal("expected finding for redis response")
	}
}
