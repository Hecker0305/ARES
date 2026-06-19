package deserial

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine("oob.example.com")
	if e == nil {
		t.Fatal("expected non-nil Engine")
	}
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", e.client.Timeout)
	}
	if e.oobDomain != "oob.example.com" {
		t.Errorf("expected oobDomain oob.example.com, got %s", e.oobDomain)
	}
}

func TestNewEngine_EmptyOOB(t *testing.T) {
	e := NewEngine("")
	if e.oobDomain != "" {
		t.Errorf("expected empty oobDomain, got %s", e.oobDomain)
	}
}

func TestDetectJavaDeserial(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"java.io.StreamCorruptedException", "java.io.StreamCorruptedException", true},
		{"ObjectInputStream", "java.io.ObjectInputStream", true},
		{"ClassNotFoundException", "ClassNotFoundException", true},
		{"invalidClass", "invalidClass", true},
		{"streamCorrupted", "streamcorrupted", true},
		{"no match", "OK", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		got := detectJavaDeserial(tt.body)
		if got != tt.want {
			t.Errorf("detectJavaDeserial(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}

func TestDetectPHPDeserial(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"unserialize error", "unserialize(): Error", true},
		{"PHP object", "PHP object", true},
		{"fatal error", "Fatal error: Uncaught", true},
		{"wakeup", "__wakeup", true},
		{"no match", "OK", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		got := detectPHPDeserial(tt.body)
		if got != tt.want {
			t.Errorf("detectPHPDeserial(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}

func TestDetectPythonDeserial(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"pickle", "pickle data", true},
		{"unpickling", "unpickling error", true},
		{"yaml.load", "yaml.load", true},
		{"unsafe yaml", "unsafe yaml", true},
		{"no match", "OK", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		got := detectPythonDeserial(tt.body)
		if got != tt.want {
			t.Errorf("detectPythonDeserial(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}

func TestDetectDotNetDeserial(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"BinaryFormatter", "BinaryFormatter", true},
		{"TypeInitialization", "typeinitialization error", true},
		{"SerializationException", "SerializationException", true},
		{"ObjectStateFormatter", "ObjectStateFormatter", true},
		{"no match", "OK", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		got := detectDotNetDeserial(tt.body)
		if got != tt.want {
			t.Errorf("detectDotNetDeserial(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}

func TestGenerateJavaPayload(t *testing.T) {
	payload := generateJavaPayload("CommonsCollections5", "ping oob.example.com")
	if !strings.Contains(payload, "CommonsCollections5") {
		t.Error("payload should contain gadget name")
	}
	if !strings.Contains(payload, "ping oob.example.com") {
		t.Error("payload should contain command")
	}
	if !strings.Contains(payload, "ysoserial") {
		t.Error("payload should mention ysoserial")
	}
}

func TestGeneratePharPayload(t *testing.T) {
	payload := generatePharPayload()
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("phar payload should be valid base64: %v", err)
	}
	if len(data) != 8 {
		t.Errorf("expected 8 bytes, got %d", len(data))
	}
	expected := []byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i, b := range data {
		if b != expected[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, b, expected[i])
		}
	}
}

func TestGeneratePicklePayload(t *testing.T) {
	payload := generatePicklePayload("id")
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("pickle payload should be valid base64: %v", err)
	}
	decoded := string(data)
	if !strings.Contains(decoded, "system") {
		t.Error("pickle payload should contain system call")
	}
	if !strings.Contains(decoded, "id") {
		t.Error("pickle payload should contain the command")
	}
}

func TestGeneratePickleOOB(t *testing.T) {
	payload := generatePickleOOB("oob.example.com")
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("OOB pickle payload should be valid base64: %v", err)
	}
	decoded := string(data)
	if !strings.Contains(decoded, "curl http://oob.example.com") {
		t.Error("OOB pickle payload should contain curl command")
	}
}

func TestGenerateDotNetPayload(t *testing.T) {
	payload := generateDotNetPayload("LosFormatter")
	if !strings.Contains(payload, "LosFormatter") {
		t.Error("payload should contain formatter name")
	}
	if !strings.Contains(payload, "TypeConfuseDelegate") {
		t.Error("payload should contain gadget name")
	}
}

func TestGenerateViewStatePayload(t *testing.T) {
	payload := generateViewStatePayload("oob.example.com")
	if !strings.Contains(payload, "__VIEWSTATE") {
		t.Error("payload should contain __VIEWSTATE key")
	}
	if !strings.Contains(payload, "__VIEWSTATEGENERATOR") {
		t.Error("payload should contain __VIEWSTATEGENERATOR key")
	}
	if !strings.Contains(payload, "CA0B0334") {
		t.Error("payload should contain the viewstate generator value")
	}
}

func TestTestJava_DetectsMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("java.io.StreamCorruptedException"))
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	findings, err := e.TestJava(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Java deserial findings")
	}
	for _, f := range findings {
		if !strings.HasPrefix(f.Type, "deserial_java_") {
			t.Errorf("expected type prefix deserial_java_, got %s", f.Type)
		}
		if !f.Confirmed {
			t.Error("expected confirmed finding")
		}
	}
}

func TestTestPHP_DetectsMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Fatal error: Uncaught"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestPHP(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected PHP deserial findings")
	}
}

func TestTestPython_DetectsMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("unpickling error occurred"))
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	findings, err := e.TestPython(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Python deserial findings")
	}
}

func TestTestDotNet_DetectsMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("BinaryFormatter deserialization error"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestDotNet(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected .NET deserial findings")
	}
}

func TestTestDotNet_NoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestDotNet(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestTestViewState_DetectsMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("BinaryFormatter error"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestViewState(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected ViewState findings")
	}
}

func TestTestViewState_NoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	e := NewEngine("")
	findings, err := e.TestViewState(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestTestAll_AggregatesAll(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("java.io.StreamCorruptedException"))
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	e.SetAuthFn(func() bool { return true })
	findings, err := e.TestAll(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from TestAll")
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{5, 3, 3},
		{0, 0, 0},
		{-1, 10, -1},
		{42, 42, 42},
	}
	for _, tt := range tests {
		got := minInt(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestPayloadTruncation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("java.io.StreamCorruptedException"))
	}))
	defer ts.Close()

	e := NewEngine("oob.example.com")
	findings, _ := e.TestJava(ts.URL)
	for _, f := range findings {
		if len(f.Payload) > 200 {
			t.Errorf("payload truncated to %d, expected max 200", len(f.Payload))
		}
	}
}
