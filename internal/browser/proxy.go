package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/security"
)

type ProxyConfig struct {
	CaidoURL       string
	CaidoToken     string
	ListenPort     int
	ReplayTarget   string
	ReplayMethod   string
	AllowedHosts   []string
	BlockLoopback  bool
	MaxBodySize    int64
	RequestTimeout time.Duration
}

type InterceptProxy struct {
	cfg           ProxyConfig
	mu            sync.RWMutex
	requests      []*ProxyRequest
	handler       http.Handler
	nextRequestID uint64
}

type ProxyRequest struct {
	ID        string
	Method    string
	URL       string
	Host      string
	Path      string
	Headers   map[string]string
	Body      string
	Status    int
	Response  string
	TimeStamp string
}

var blockedSSRFPatterns = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.google.internal.",
	"100.100.100.200",
	"100.100.100.204",
	"100.100.100.205",
}

var privateCIDRs = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("169.254.0.0/16"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("fc00::/7"),
	mustParseCIDR("fe80::/10"),
	mustParseCIDR("100.64.0.0/10"),
}

var allowedPorts = map[int]bool{
	80:   true,
	443:  true,
	8080: true,
	8443: true,
}

func mustParseCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		logger.Error("invalid CIDR configuration", logger.Fields{"cidr": s, "error": err})
		return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	return cidr
}

func NewInterceptProxy(cfg ProxyConfig) *InterceptProxy {
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 10 * 1024 * 1024
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	ip := &InterceptProxy{cfg: cfg}
	ip.handler = http.HandlerFunc(ip.handleProxy)
	return ip
}

func (ip *InterceptProxy) validateDestination(rawURL string) ([]net.IP, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("blocked scheme: %s", parsed.Scheme)
	}

	host := parsed.Hostname()

	for _, blocked := range blockedSSRFPatterns {
		if strings.EqualFold(host, blocked) || strings.EqualFold(host, blocked+".") {
			return nil, fmt.Errorf("blocked destination: metadata endpoint")
		}
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("dns resolution failed: %w", err)
	}

	var validated []net.IP
	for _, ipStr := range ips {
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil {
			continue
		}

		if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() {
			return nil, fmt.Errorf("blocked destination: private/internal IP (%s)", ipStr)
		}

		for _, cidr := range privateCIDRs {
			if cidr.Contains(parsedIP) {
				return nil, fmt.Errorf("blocked destination: private IP (%s)", ipStr)
			}
		}

		validated = append(validated, parsedIP)
	}

	if len(validated) == 0 {
		return nil, fmt.Errorf("blocked destination: no valid IPs")
	}

	if p := parsed.Port(); p != "" {
		port := 80
		if parsed.Scheme == "https" {
			port = 443
		}
		if n, err := fmt.Sscanf(p, "%d", &port); err != nil || n != 1 {
			return nil, fmt.Errorf("invalid port: %q", p)
		}
		if !allowedPorts[port] {
			return nil, fmt.Errorf("blocked destination: port %d not allowed", port)
		}
	}

	return validated, nil
}

func (ip *InterceptProxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		ip.handleConnect(w, r)
		return
	}

	req := ProxyRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Host:    r.Host,
		Path:    r.URL.Path,
		Headers: make(map[string]string),
	}

	for k, v := range r.Header {
		if len(v) > 0 {
			cleanKey := sanitizeHeaderKey(k)
			if cleanKey == "" {
				continue
			}
			req.Headers[cleanKey] = sanitizeHeaderValue(v[0])
		}
	}

	body, _ := readBody(r)
	req.Body = string(body)

	validatedIPs, err := ip.validateDestination(req.URL)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "destination blocked: %v", err)
		return
	}

	if len(ip.cfg.AllowedHosts) > 0 {
		reqHost := parsedURLForProxy(req.URL)
		allowed := false
		for _, h := range ip.cfg.AllowedHosts {
			if strings.EqualFold(reqHost, h) {
				allowed = true
				break
			}
		}
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "host %s not in allowed list", reqHost)
			return
		}
	}

	ip.mu.Lock()
	ip.nextRequestID++
	req.ID = fmt.Sprintf("%d", ip.nextRequestID)
	req.TimeStamp = time.Now().Format(time.RFC3339)
	ip.requests = append(ip.requests, &req)
	if len(ip.requests) > 10000 {
		ip.requests = ip.requests[len(ip.requests)-10000:]
	}
	ip.mu.Unlock()

	destURL := r.URL.String()
	if !strings.HasPrefix(destURL, "http://") && !strings.HasPrefix(destURL, "https://") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid URL: %s", destURL)
		return
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	ctx, cancel := context.WithTimeout(r.Context(), ip.cfg.RequestTimeout)
	defer cancel()

	outReq, err := http.NewRequestWithContext(ctx, r.Method, destURL, bodyReader)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "create request error: %v", err)
		return
	}

	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Transfer-Encoding":   true,
		"TE":                  true,
		"Trailer":             true,
		"Upgrade":             true,
		"Proxy-Authorization": true,
		"Proxy-Authenticate":  true,
	}
	for k, v := range r.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, hv := range v {
			outReq.Header.Add(k, hv)
		}
	}

	pinnedIPs := validatedIPs

	client := &http.Client{
		Timeout: ip.cfg.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			redirectURL := req.URL.String()
			redirectIPs, err := ip.validateDestination(redirectURL)
			if err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			pinnedIPs = redirectIPs
			return nil
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				dialer := &net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(pinnedIPs[0].String(), port))
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}
	resp, err := client.Do(outReq)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "forward error: %v", err)
		return
	}
	defer resp.Body.Close()

	safeHeaders := map[string]bool{
		"Content-Type":              true,
		"Content-Length":            true,
		"Content-Encoding":          true,
		"Cache-Control":             true,
		"Expires":                   true,
		"Last-Modified":             true,
		"ETag":                      true,
		"Accept-Ranges":             true,
		"Content-Range":             true,
		"Content-Disposition":       true,
		"Content-Security-Policy":   true,
		"X-Content-Type-Options":    true,
		"X-Frame-Options":           true,
		"X-XSS-Protection":          true,
		"Strict-Transport-Security": true,
	}
	for k, v := range resp.Header {
		ck := http.CanonicalHeaderKey(k)
		if !safeHeaders[ck] {
			continue
		}
		for _, hv := range v {
			w.Header().Add(k, hv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, ip.cfg.MaxBodySize))
}

var allowedConnectPorts = map[string]bool{
	"443":  true,
	"8443": true,
}

func (ip *InterceptProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	if len(ip.cfg.AllowedHosts) > 0 {
		allowed := false
		for _, h := range ip.cfg.AllowedHosts {
			if strings.EqualFold(host, h) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, fmt.Sprintf("CONNECT to %s not allowed", host), http.StatusForbidden)
			return
		}
	}

	if !allowedConnectPorts[port] {
		http.Error(w, fmt.Sprintf("CONNECT not allowed on port %s", port), http.StatusForbidden)
		return
	}

	validatedIPs, err := ip.validateDestination("https://" + host + ":" + port)
	if err != nil {
		http.Error(w, "destination blocked", http.StatusForbidden)
		return
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	pinnedAddr := net.JoinHostPort(validatedIPs[0].String(), port)
	destConn, err := dialer.Dial("tcp", pinnedAddr)
	if err != nil {
		http.Error(w, "CONNECT failed", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "connection upgrade failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		destConn.SetDeadline(time.Now().Add(30 * time.Second))
		clientConn.SetDeadline(time.Now().Add(30 * time.Second))
		io.Copy(destConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		clientConn.SetDeadline(time.Now().Add(30 * time.Second))
		destConn.SetDeadline(time.Now().Add(30 * time.Second))
		io.Copy(clientConn, destConn)
	}()
	wg.Wait()
}

func (ip *InterceptProxy) egressFilter(network, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("destination blocked: %s", ip)
		}
		for _, cidr := range privateCIDRs {
			if cidr.Contains(ip) {
				return fmt.Errorf("destination blocked: private IP range")
			}
		}
	}
	return nil
}

func (ip *InterceptProxy) replayRequest(reqID, method string) {
	ip.mu.RLock()
	var req ProxyRequest
	for _, r := range ip.requests {
		if r.ID == reqID {
			req = *r
			break
		}
	}
	ip.mu.RUnlock()

	if req.URL == "" {
		return
	}

	target := ip.cfg.ReplayTarget
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	body := strings.NewReader(req.Body)
	req2, err := http.NewRequest(method, target+req.Path, body)
	if err != nil {
		return
	}
	for k, v := range req.Headers {
		if k != "Host" && k != "Content-Length" {
			req2.Header.Set(k, v)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req2)
	if err != nil {
		logger.Error(fmt.Sprintf("[Proxy] replay failed: %v", err))
		return
	}
	defer resp.Body.Close()
}

func (ip *InterceptProxy) pushToCaido(req ProxyRequest) {
	if ip.cfg.CaidoToken == "" {
		return
	}
	sanitized := req
	sanitized.Body = security.RedactSensitiveData(sanitized.Body)
	sanitized.Response = security.RedactSensitiveData(sanitized.Response)
	data, err := json.Marshal(map[string]string{
		"method": sanitized.Method,
		"url":    sanitized.URL,
		"body":   sanitized.Body,
	})
	if err != nil {
		logger.Warn("pushToCaido: marshal error", logger.Fields{"error": err})
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	httpReq, err := http.NewRequest("POST", ip.cfg.CaidoURL+"/api/replay", bytes.NewReader(data))
	if err != nil {
		logger.Warn("pushToCaido: create request error", logger.Fields{"error": err})
		return
	}
	httpReq.Header.Set("Authorization", "Bearer "+ip.cfg.CaidoToken)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		logger.Warn("pushToCaido: request failed", logger.Fields{"error": err})
		return
	}
	defer resp.Body.Close()
}

func (ip *InterceptProxy) Requests() []ProxyRequest {
	ip.mu.RLock()
	defer ip.mu.RUnlock()
	out := make([]ProxyRequest, len(ip.requests))
	for i, r := range ip.requests {
		out[i] = *r
	}
	return out
}

func (ip *InterceptProxy) Clear() {
	ip.mu.Lock()
	ip.requests = nil
	ip.mu.Unlock()
}

func (ip *InterceptProxy) Start() error {
	addr := fmt.Sprintf(":%d", ip.cfg.ListenPort)
	logger.Info(fmt.Sprintf("[Proxy] Intercept proxy listening on %s", addr))
	return http.ListenAndServe(addr, ip.handler)
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	const maxBodySize = 10 * 1024 * 1024
	reader := io.LimitReader(r.Body, maxBodySize)
	buf := make([]byte, 1024)
	var body []byte
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return body, nil
}

func (ip *InterceptProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip.handler.ServeHTTP(w, r)
}

func sanitizeHeaderKey(k string) string {
	for _, r := range k {
		if r < 32 || r > 126 {
			return ""
		}
	}
	if len(k) == 0 || len(k) > 256 {
		return ""
	}
	return k
}

func sanitizeHeaderValue(v string) string {
	var result strings.Builder
	for _, r := range v {
		if r == '\n' || r == '\r' {
			continue
		}
		result.WriteRune(r)
	}
	if len(result.String()) > 4096 {
		return result.String()[:4096]
	}
	return result.String()
}

func parsedURLForProxy(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func isAllowedDestination(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		return false
	}
	for _, ipStr := range ips {
		pIP := net.ParseIP(ipStr)
		if pIP == nil {
			continue
		}
		if pIP.IsLoopback() || pIP.IsPrivate() || pIP.IsLinkLocalUnicast() {
			return false
		}
		for _, cidr := range privateCIDRs {
			if cidr.Contains(pIP) {
				return false
			}
		}
	}
	return true
}
