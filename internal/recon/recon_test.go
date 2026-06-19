package recon

import (
	"context"
	"testing"
	"time"
)

func TestNewSubdomainEnum(t *testing.T) {
	e, err := NewSubdomainEnum("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil enum")
	}
	if e.Domain != "example.com" {
		t.Errorf("expected example.com, got %s", e.Domain)
	}
}

func TestNewHTTPProbe(t *testing.T) {
	p := NewHTTPProbe()
	if p == nil {
		t.Fatal("expected non-nil probe")
	}
}

func TestNewHTTPProbeProbe(t *testing.T) {
	p := NewHTTPProbe()
	results := p.Probe(context.Background(), []string{"http://localhost:19999"})
	if results != nil {
		t.Logf("probe returned %d results", len(results))
	}
}

func TestNewHTTPRequest(t *testing.T) {
	req, err := NewHTTPRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("NewHTTPRequest error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("expected GET, got %s", req.Method)
	}
}

func TestNewPortScanner(t *testing.T) {
	s, err := NewPortScanner("127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.Target != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", s.Target)
	}
}

func TestPortScannerScan(t *testing.T) {
	s, err := NewPortScanner("127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.Timeout = 2 * time.Second
	s.Ports = []int{9999}
	ports, err := s.Scan(context.Background())
	if err != nil {
		t.Logf("Scan error (expected without listener): %v", err)
	}
	_ = ports
}

func TestParseNmapXML(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1234" version="7.80">
<host><address addr="192.168.1.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port></ports>
<os><osmatch name="Linux"/></os>
</host></nmaprun>`
	result, err := ParseNmapXML(xml)
	if err != nil {
		t.Fatalf("ParseNmapXML error: %v", err)
	}
	if result.Host != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", result.Host)
	}
	if len(result.Ports) != 1 {
		t.Errorf("expected 1 port, got %d", len(result.Ports))
	}
	if result.Ports[0].Service != "http" {
		t.Errorf("expected http, got %s", result.Ports[0].Service)
	}
}

func TestParseNmapXMLEmpty(t *testing.T) {
	_, err := ParseNmapXML("")
	if err == nil {
		t.Error("expected error for empty XML")
	}
}

func TestHTTPClientStruct(t *testing.T) {
	c := &HTTPClient{Timeout: 10 * time.Second, MaxRedirect: 3}
	if c.Timeout != 10*time.Second {
		t.Errorf("expected 10s, got %v", c.Timeout)
	}
}
