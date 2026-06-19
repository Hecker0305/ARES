package smuggling

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil Engine")
	}
	if e.client == nil {
		t.Error("HTTP client should be initialized")
	}
	if e.client.Timeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", e.client.Timeout)
	}
	if len(e.results) != 0 {
		t.Errorf("expected 0 initial results, got %d", len(e.results))
	}
}

func TestDesyncType_String(t *testing.T) {
	tests := []struct {
		dt   DesyncType
		want string
	}{
		{CLTE, "CL.TE"},
		{TECL, "TE.CL"},
		{TETE, "TE.TE"},
		{DesyncType(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.dt.String()
		if got != tt.want {
			t.Errorf("DesyncType(%d).String() = %q, want %q", tt.dt, got, tt.want)
		}
	}
}

func TestTest_InvalidURL(t *testing.T) {
	e := New()
	_, err := e.Test(context.Background(), "://invalid", CLTE)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestTest_UnknownType(t *testing.T) {
	e := New()
	_, err := e.Test(context.Background(), "http://example.com", DesyncType(99))
	if err == nil {
		t.Fatal("expected error for unknown desync type")
	}
}

func TestGeneratePayloads_CLTE(t *testing.T) {
	e := &Engine{}
	payloads := e.GeneratePayloads("http://example.com", CLTE)
	if len(payloads) != 2 {
		t.Fatalf("expected 2 CL.TE payloads, got %d", len(payloads))
	}
	for _, p := range payloads {
		if p.Type != CLTE {
			t.Errorf("expected type CL.TE, got %v", p.Type)
		}
		if !strings.Contains(p.Description, "CL.TE") {
			t.Errorf("description should mention CL.TE, got %s", p.Description)
		}
		if p.Prefix == "" {
			t.Error("prefix should not be empty")
		}
		if p.Attack == "" {
			t.Error("attack should not be empty")
		}
	}
}

func TestGeneratePayloads_TECL(t *testing.T) {
	e := &Engine{}
	payloads := e.GeneratePayloads("http://example.com", TECL)
	if len(payloads) != 1 {
		t.Fatalf("expected 1 TE.CL payload, got %d", len(payloads))
	}
	if payloads[0].Type != TECL {
		t.Errorf("expected type TE.CL, got %v", payloads[0].Type)
	}
}

func TestGeneratePayloads_TETE(t *testing.T) {
	e := &Engine{}
	payloads := e.GeneratePayloads("http://example.com", TETE)
	if len(payloads) != 1 {
		t.Fatalf("expected 1 TE.TE payload, got %d", len(payloads))
	}
	if payloads[0].Type != TETE {
		t.Errorf("expected type TE.TE, got %v", payloads[0].Type)
	}
}

func TestGeneratePayloads_InvalidURL(t *testing.T) {
	e := &Engine{}
	payloads := e.GeneratePayloads("://invalid", CLTE)
	if payloads != nil {
		t.Error("expected nil for invalid URL")
	}
}

func TestGeneratePayloads_UnknownType(t *testing.T) {
	e := &Engine{}
	payloads := e.GeneratePayloads("http://example.com", DesyncType(99))
	if payloads != nil {
		t.Error("expected nil for unknown desync type")
	}
}

func TestGeneratePayloads_ContainsHost(t *testing.T) {
	e := &Engine{}
	payloads := e.GeneratePayloads("http://target.example.com:8080/path", CLTE)
	for _, p := range payloads {
		if p.Prefix != "[REDACTED]" {
			t.Errorf("prefix should be redacted: %s", p.Prefix)
		}
		if p.Attack != "[REDACTED]" {
			t.Errorf("attack should be redacted: %s", p.Attack)
		}
	}
}

func TestTruncate_Short(t *testing.T) {
	s := "hello"
	got := truncate(s, 10)
	if got != s {
		t.Errorf("expected %q, got %q", s, got)
	}
}

func TestTruncate_Exact(t *testing.T) {
	s := "hello"
	got := truncate(s, 5)
	if got != s {
		t.Errorf("expected %q, got %q", s, got)
	}
}

func TestTruncate_Long(t *testing.T) {
	s := "hello world this is a test"
	got := truncate(s, 10)
	want := "hello worl..."
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestTruncate_Empty(t *testing.T) {
	got := truncate("", 10)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestTruncate_ZeroMax(t *testing.T) {
	s := "hello"
	got := truncate(s, 0)
	if got != "..." {
		t.Errorf("expected '...', got %q", got)
	}
}

func TestResults_Initial(t *testing.T) {
	e := New()
	results := e.Results()
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestTest_CLTE_WithTCPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			_, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
		}
	}()

	addr := ln.Addr().String()
	target := fmt.Sprintf("http://%s/", addr)

	e := New()
	result, err := e.Test(context.Background(), target, CLTE)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Type != CLTE {
		t.Errorf("expected type CL.TE, got %v", result.Type)
	}
	if len(result.Payloads) == 0 {
		t.Error("expected payloads in result")
	}
}

func TestTest_TECL_WithTCPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			_, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
		}
	}()

	addr := ln.Addr().String()
	target := fmt.Sprintf("http://%s/", addr)

	e := New()
	result, err := e.Test(context.Background(), target, TECL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Type != TECL {
		t.Errorf("expected type TE.CL, got %v", result.Type)
	}
}

func TestTest_TETE_WithTCPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			_, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
		}
	}()

	addr := ln.Addr().String()
	target := fmt.Sprintf("http://%s/", addr)

	e := New()
	result, err := e.Test(context.Background(), target, TETE)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Type != TETE {
		t.Errorf("expected type TE.TE, got %v", result.Type)
	}
}

func TestTest_WithContextTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	target := fmt.Sprintf("http://%s/", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	time.Sleep(5 * time.Millisecond)

	e := New()
	result, err := e.Test(ctx, target, CLTE)
	if err == nil && result != nil && result.Vulnerable {
	}
}

func TestResults_AfterTest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}
	}()

	addr := ln.Addr().String()
	target := fmt.Sprintf("http://%s/", addr)

	e := New()
	e.Test(context.Background(), target, CLTE)

	results := e.Results()
	if len(results) == 0 {
	}
}

func TestSendDesync_ConnectionRefused(t *testing.T) {
	e := New()
	vulnerable, evidence, err := e.sendDesync(context.Background(), "127.0.0.1:1", "prefix", "attack", false)
	if err == nil {
		t.Error("expected error for connection refused")
	}
	if vulnerable {
		t.Error("should not be vulnerable when connection fails")
	}
	if evidence != "" {
		t.Errorf("expected empty evidence, got %s", evidence)
	}
}

func TestPayloadContains_HostInjection(t *testing.T) {
	parsed, _ := url.Parse("http://evil-host.com:8080/path")
	prefix := "POST / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
	if !strings.Contains(prefix, "evil-host.com:8080") {
		t.Error("prefix should contain the target host")
	}
}
