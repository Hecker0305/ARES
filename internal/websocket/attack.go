package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type AttackType int

const (
	PayloadInjection AttackType = iota
	OriginBypass
	ProtocolDowngrade
	DenialOfService
	CrossOriginBypass
	AuthenticationBypass
)

func (a AttackType) String() string {
	switch a {
	case PayloadInjection:
		return "payload_injection"
	case OriginBypass:
		return "origin_bypass"
	case ProtocolDowngrade:
		return "protocol_downgrade"
	case DenialOfService:
		return "denial_of_service"
	case CrossOriginBypass:
		return "cross_origin_bypass"
	case AuthenticationBypass:
		return "authentication_bypass"
	default:
		return "unknown"
	}
}

type AttackConfig struct {
	TargetURL   string
	AttackType  AttackType
	Payloads    []string
	Headers     map[string]string
	Concurrency int
	Timeout     time.Duration
}

type AttackResult struct {
	AttackType AttackType  `json:"attack_type"`
	Vulnerable bool        `json:"vulnerable"`
	Payload    string      `json:"payload"`
	Response   string      `json:"response"`
	StatusCode int         `json:"status_code"`
	Summary    string      `json:"summary"`
	RoundTrips []RoundTrip `json:"round_trips,omitempty"`
}

type RoundTrip struct {
	Sent     string `json:"sent"`
	Received string `json:"received"`
	Duration string `json:"duration"`
}

type Attacker struct {
	client  *http.Client
	results []AttackResult
	mu      sync.Mutex
}

func NewAttacker() *Attacker {
	return &Attacker{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *Attacker) Run(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	switch cfg.AttackType {
	case PayloadInjection:
		return a.testPayloadInjection(ctx, cfg)
	case OriginBypass:
		return a.testOriginBypass(ctx, cfg)
	case ProtocolDowngrade:
		return a.testProtocolDowngrade(ctx, cfg)
	case DenialOfService:
		return a.testDenialOfService(ctx, cfg)
	case CrossOriginBypass:
		return a.testCrossOriginBypass(ctx, cfg)
	case AuthenticationBypass:
		return a.testAuthBypass(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown attack type: %v", cfg.AttackType)
	}
}

func (a *Attacker) openWS(ctx context.Context, targetURL string, extraHeaders map[string]string) (net.Conn, *http.Response, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL: %w", err)
	}

	scheme := parsed.Scheme
	if scheme == "wss" {
		scheme = "wss"
	} else {
		scheme = "ws"
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		if scheme == "wss" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}

	key := make([]byte, 16)
	rand.Read(key)
	wsKey := base64.StdEncoding.EncodeToString(key)

	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}

	var reqBuilder strings.Builder
	reqBuilder.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", path))
	reqBuilder.WriteString(fmt.Sprintf("Host: %s\r\n", parsed.Host))
	reqBuilder.WriteString("Upgrade: websocket\r\n")
	reqBuilder.WriteString("Connection: Upgrade\r\n")
	reqBuilder.WriteString(fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", wsKey))
	reqBuilder.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range extraHeaders {
		reqBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	reqBuilder.WriteString("\r\n")

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(reqBuilder.String())); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write handshake: %w", err)
	}

	var respBuf [4096]byte
	n, err := conn.Read(respBuf[:])
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read handshake: %w", err)
	}

	respStr := string(respBuf[:n])
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(respStr)), nil)
	if err != nil {
		// Parse manually
		lines := strings.Split(respStr, "\r\n")
		statusCode := 0
		if len(lines) > 0 {
			fmt.Sscanf(lines[0], "HTTP/1.1 %d", &statusCode)
		}
		resp = &http.Response{StatusCode: statusCode}
	}

	conn.SetDeadline(time.Time{})
	return conn, resp, nil
}

func (a *Attacker) sendWSFrame(conn net.Conn, opcode byte, payload []byte) error {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	frame := make([]byte, 0)
	frame = append(frame, 0x80|opcode)
	if len(payload) < 126 {
		frame = append(frame, byte(len(payload)))
	} else if len(payload) < 65536 {
		frame = append(frame, 126)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(payload)))
		frame = append(frame, lenBytes...)
	} else {
		frame = append(frame, 127)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(len(payload)))
		frame = append(frame, lenBytes...)
	}
	frame = append(frame, payload...)
	_, err := conn.Write(frame)
	return err
}

func (a *Attacker) readWSFrame(conn net.Conn) (opcode byte, payload []byte, err error) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	length := int64(header[1] & 0x7F)
	if length == 126 {
		ext := make([]byte, 2)
		io.ReadFull(conn, ext)
		length = int64(binary.BigEndian.Uint16(ext))
	} else if length == 127 {
		ext := make([]byte, 8)
		io.ReadFull(conn, ext)
		length = int64(binary.BigEndian.Uint64(ext))
	}

	var maskKey [4]byte
	if masked {
		io.ReadFull(conn, maskKey[:])
	}

	if length > 65536 {
		return 0, nil, fmt.Errorf("frame too large: %d", length)
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

func (a *Attacker) testPayloadInjection(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	payloads := cfg.Payloads
	if len(payloads) == 0 {
		payloads = []string{
			"<script>alert(1)</script>",
			"{\"$ne\": null}",
			"'; DROP TABLE users; --",
			"../../../etc/passwd",
			"{{7*7}}",
		}
	}

	for _, payload := range payloads {
		conn, resp, err := a.openWS(ctx, cfg.TargetURL, cfg.Headers)
		if err != nil {
			continue
		}
		defer conn.Close()

		var trips []RoundTrip
		start := time.Now()
		if err := a.sendWSFrame(conn, 1, []byte(payload)); err != nil {
			continue
		}
		opcode, response, err := a.readWSFrame(conn)
		if err != nil {
			continue
		}
		trips = append(trips, RoundTrip{
			Sent:     payload,
			Received: truncate(string(response), 500),
			Duration: time.Since(start).String(),
		})

		responseStr := string(response)
		vulnerable := strings.Contains(responseStr, payload) || opcode == 8

		result := &AttackResult{
			AttackType: PayloadInjection,
			Vulnerable: vulnerable,
			Payload:    payload,
			Response:   truncate(responseStr, 1000),
			StatusCode: resp.StatusCode,
			RoundTrips: trips,
			Summary:    fmt.Sprintf("WebSocket payload injection test with payload: %s", truncate(payload, 100)),
		}

		if resp.StatusCode == http.StatusSwitchingProtocols {
			a.mu.Lock()
			a.results = append(a.results, *result)
			a.mu.Unlock()
		}
		return result, nil
	}

	return &AttackResult{
		AttackType: PayloadInjection,
		Vulnerable: false,
		Summary:    "No WebSocket connection could be established",
	}, nil
}

func (a *Attacker) testOriginBypass(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	maliciousOrigins := []string{
		"https://evil.com",
		"null",
		"http://localhost:9999",
		"data://",
		"https://attacker.com",
	}

	for _, origin := range maliciousOrigins {
		headers := make(map[string]string)
		for k, v := range cfg.Headers {
			headers[k] = v
		}
		headers["Origin"] = origin

		conn, resp, err := a.openWS(ctx, cfg.TargetURL, headers)
		if err != nil {
			continue
		}
		conn.Close()

		if resp.StatusCode == http.StatusSwitchingProtocols {
			result := &AttackResult{
				AttackType: OriginBypass,
				Vulnerable: true,
				Payload:    origin,
				StatusCode: resp.StatusCode,
				Summary:    fmt.Sprintf("Origin bypass: WebSocket accepted from forbidden origin %s", origin),
			}
			a.mu.Lock()
			a.results = append(a.results, *result)
			a.mu.Unlock()
			return result, nil
		}
	}

	return &AttackResult{
		AttackType: OriginBypass,
		Vulnerable: false,
		Summary:    "No origin bypass detected",
	}, nil
}

func (a *Attacker) testProtocolDowngrade(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	conn, resp, err := a.openWS(ctx, cfg.TargetURL, cfg.Headers)
	if err != nil {
		return &AttackResult{
			AttackType: ProtocolDowngrade,
			Vulnerable: false,
			Summary:    fmt.Sprintf("Cannot connect: %v", err),
		}, nil
	}
	defer conn.Close()

	wsAccept := resp.Header.Get("Sec-WebSocket-Accept")
	if wsAccept == "" {
		return &AttackResult{
			AttackType: ProtocolDowngrade,
			Vulnerable: true,
			Summary:    "Protocol downgrade: no Sec-WebSocket-Accept header, possible plain HTTP fallback",
		}, nil
	}

	hasUpgrade := false
	for _, v := range resp.Header["Upgrade"] {
		if strings.EqualFold(v, "websocket") {
			hasUpgrade = true
			break
		}
	}

	if !hasUpgrade {
		return &AttackResult{
			AttackType: ProtocolDowngrade,
			Vulnerable: true,
			Summary:    "Protocol downgrade: response missing Upgrade: websocket header",
		}, nil
	}

	return &AttackResult{
		AttackType: ProtocolDowngrade,
		Vulnerable: false,
		Summary:    "Protocol correctly upgraded to WebSocket",
	}, nil
}

func (a *Attacker) testDenialOfService(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 50
	}

	openConns := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, resp, err := a.openWS(ctx, cfg.TargetURL, cfg.Headers)
			if err != nil {
				return
			}
			if resp.StatusCode == http.StatusSwitchingProtocols {
				mu.Lock()
				openConns++
				mu.Unlock()
				// Send large payload
				largePayload := make([]byte, 65535)
				rand.Read(largePayload)
				a.sendWSFrame(conn, 2, largePayload)
				time.Sleep(100 * time.Millisecond)
				conn.Close()
			} else {
				conn.Close()
			}
		}()
	}
	wg.Wait()

	vulnerable := openConns >= concurrency/2
	summary := ""
	if vulnerable {
		summary = fmt.Sprintf("WebSocket DoS: %d/%d concurrent connections accepted with large payloads", openConns, concurrency)
	} else {
		summary = fmt.Sprintf("No WebSocket DoS: only %d/%d connections accepted", openConns, concurrency)
	}

	result := &AttackResult{
		AttackType: DenialOfService,
		Vulnerable: vulnerable,
		Summary:    summary,
	}
	a.mu.Lock()
	a.results = append(a.results, *result)
	a.mu.Unlock()
	return result, nil
}

func (a *Attacker) testCrossOriginBypass(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	conn, resp, err := a.openWS(ctx, cfg.TargetURL, cfg.Headers)
	if err != nil {
		return &AttackResult{
			AttackType: CrossOriginBypass,
			Vulnerable: false,
			Summary:    fmt.Sprintf("Cannot connect: %v", err),
		}, nil
	}
	defer conn.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "" || acao == "*" {
		return &AttackResult{
			AttackType: CrossOriginBypass,
			Vulnerable: acao == "*",
			Payload:    acao,
			Summary:    fmt.Sprintf("Cross-origin WS: Access-Control-Allow-Origin is %q", acao),
		}, nil
	}

	return &AttackResult{
		AttackType: CrossOriginBypass,
		Vulnerable: false,
		Summary:    "Cross-origin protection present",
	}, nil
}

func (a *Attacker) testAuthBypass(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	conn, resp, err := a.openWS(ctx, cfg.TargetURL, cfg.Headers)
	if err != nil {
		return &AttackResult{
			AttackType: AuthenticationBypass,
			Vulnerable: false,
			Summary:    fmt.Sprintf("Cannot connect: %v", err),
		}, nil
	}
	defer conn.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		result := &AttackResult{
			AttackType: AuthenticationBypass,
			Vulnerable: true,
			StatusCode: resp.StatusCode,
			Summary:    "WebSocket accepted without authentication credentials",
		}
		a.mu.Lock()
		a.results = append(a.results, *result)
		a.mu.Unlock()
		return result, nil
	}

	return &AttackResult{
		AttackType: AuthenticationBypass,
		Vulnerable: false,
		Summary:    "WebSocket correctly requires authentication",
	}, nil
}

func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5A0BD85B5"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (a *Attacker) Results() []AttackResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AttackResult, len(a.results))
	copy(out, a.results)
	return out
}

func (a *Attacker) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.results = nil
}
