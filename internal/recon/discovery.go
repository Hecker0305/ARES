package recon

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var validTargetRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$`)

func sanitizeTarget(target string) error {
	if target == "" {
		return fmt.Errorf("empty target")
	}
	if strings.ContainsAny(target, "|;&$`'\"(){}[]<>!\n\r\\") {
		return fmt.Errorf("target contains invalid characters")
	}
	if !validTargetRe.MatchString(target) {
		return fmt.Errorf("target contains invalid characters")
	}
	return nil
}

func hostFromTarget(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		parsed, err := url.Parse(target)
		if err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return target
}

type SubdomainResult struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Timestamp  string   `json:"timestamp"`
}

type HostProbe struct {
	URL          string   `json:"url"`
	Status       int      `json:"status"`
	Title        string   `json:"title"`
	Technologies []string `json:"technologies"`
	ResponseTime int64    `json:"response_time_ms"`
}

type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

type NmapResult struct {
	Host    string `json:"host"`
	Ports   []Port `json:"ports"`
	OS      string `json:"os"`
	Latency string `json:"latency"`
}

type SubdomainEnum struct {
	Domain      string
	Wordlist    []string
	Resolver    string
	Timeout     time.Duration
	Concurrency int
}

func NewSubdomainEnum(domain string) (*SubdomainEnum, error) {
	if err := sanitizeTarget(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}
	return &SubdomainEnum{
		Domain:      domain,
		Timeout:     3 * time.Second,
		Concurrency: 50,
	}, nil
}

func (e *SubdomainEnum) Enumerate(ctx context.Context) (*SubdomainResult, error) {
	var subs []string
	var subsMu sync.Mutex

	resolver := "1.1.1.1"
	if e.Resolver != "" {
		resolver = e.Resolver
	}

	if len(e.Wordlist) == 0 {
		e.Wordlist = []string{
			"www", "api", "mail", "ftp", "localhost", "webmail", "smtp",
			"pop", "ns1", "webdisk", "ns", "cpanel", "whm", "autodiscover",
			"autoconfig", "m", "imap", "test", "ns2", "email", "demo",
			"www2", "admin", "forum", "news", "vpn", "ns3", "mail2",
			"new", "mysql", "old", "lists", "support", "mobile", "mx",
			"static", "docs", "beta", "shop", "sql", "secure", "demo",
			"database", "db", "pass", "password", "username", "login",
		}
	}

	if err := e.runWithConcurrency(ctx, func(sub string) {
		full := sub + "." + e.Domain
		if e.resolve(ctx, full, resolver) {
			subsMu.Lock()
			subs = append(subs, full)
			subsMu.Unlock()
		}
	}); err != nil {
		return nil, err
	}

	return &SubdomainResult{
		Domain:     e.Domain,
		Subdomains: subs,
		Timestamp:  time.Now().Format(time.RFC3339),
	}, nil
}

func (e *SubdomainEnum) runWithConcurrency(ctx context.Context, fn func(string)) error {
	sem := make(chan struct{}, e.Concurrency)

	var wg sync.WaitGroup
	for _, sub := range e.Wordlist {
		select {
		case <-ctx.Done():
			for i := 0; i < e.Concurrency; i++ {
				sem <- struct{}{}
			}
			return ctx.Err()
		case sem <- struct{}{}:
			wg.Add(1)
			go func(s string) {
				defer func() { <-sem }()
				defer wg.Done()
				fn(s)
			}(sub)
		}
	}
	wg.Wait()
	for i := 0; i < e.Concurrency; i++ {
		sem <- struct{}{}
	}

	return nil
}

func (e *SubdomainEnum) resolve(ctx context.Context, host, resolver string) bool {
	dialer := net.Dialer{Timeout: e.Timeout}
	conn, err := dialer.DialContext(ctx, "udp", resolver+":53")
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := make([]byte, 512)
	domain := strings.TrimSuffix(host, ".")

	parts := strings.Split(domain, ".")
	query := ""
	for i := len(parts) - 1; i >= 0; i-- {
		if query != "" {
			query += "."
		}
		query += parts[i]
	}
	query += "."

	binary := e.buildDNSQuery(query)
	if _, err := conn.Write(binary); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(e.Timeout))
	n, err := conn.Read(msg)
	if err != nil || n < 12 {
		return false
	}

	return msg[3]&0x0F != 0x03
}

func (e *SubdomainEnum) buildDNSQuery(domain string) []byte {
	msg := make([]byte, 12)

	msg[0], msg[1] = 0x12, 0x34

	msg[2] = 0x01
	msg[3] = 0x00
	msg[4], msg[5] = 0x00, 0x01
	msg[6], msg[7] = 0x00, 0x00
	msg[8], msg[9] = 0x00, 0x00
	msg[10], msg[11] = 0x00, 0x00

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)

	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x01)

	return msg
}

type HTTPProbe struct {
	Targets         []string
	Timeout         time.Duration
	FollowRedirects bool
	Technologies    map[string]string
}

func NewHTTPProbe() *HTTPProbe {
	return &HTTPProbe{
		Timeout: 10 * time.Second,
		Technologies: map[string]string{
			"X-Powered-By":     "tech",
			"X-Generator":      "tech",
			"Server":           "tech",
			"X-AspNet-Version": "aspnet",
			"X-Request-ID":     "fingerprint",
		},
	}
}

func (p *HTTPProbe) Probe(ctx context.Context, urls []string) []HostProbe {
	var results []HostProbe

	for _, url := range urls {
		start := time.Now()
		probe, err := p.probeSingle(ctx, url)
		if err == nil {
			probe.ResponseTime = time.Since(start).Milliseconds()
			results = append(results, probe)
		}
	}

	return results
}

func (p *HTTPProbe) probeSingle(ctx context.Context, url string) (HostProbe, error) {
	req, err := NewHTTPRequest("GET", url, nil)
	if err != nil {
		return HostProbe{}, err
	}

	req.Headers["User-Agent"] = "Mozilla/5.0 (compatible; Ares/2.0)"
	req.Headers["Accept"] = "*/*"

	client := &HTTPClient{Timeout: p.Timeout}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return HostProbe{}, err
	}

	var technologies []string
	for header := range p.Technologies {
		if val, ok := resp.Headers[header]; ok {
			technologies = append(technologies, val)
		}
	}

	title := extractTitle(resp.BodyText)

	return HostProbe{
		URL:          url,
		Status:       resp.StatusCode,
		Title:        title,
		Technologies: technologies,
	}, nil
}

type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	BodyText   string
}

type HTTPClient struct {
	Timeout     time.Duration
	MaxRedirect int
}

func NewHTTPRequest(method, url string, body []byte) (*HTTPRequest, error) {
	return &HTTPRequest{
		Method: method,
		URL:    url,
		Body:   string(body),
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (compatible; Ares/2.0)",
		},
	}, nil
}

func (c *HTTPClient) Do(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxRedirect == 0 {
		c.MaxRedirect = 5
	}

	var body string
	statusCode := 0
	headers := make(map[string]string)

	client := &http.Client{
		Timeout: c.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.MaxRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "no such host") {
			return &HTTPResponse{
				StatusCode: 0,
				Headers:    map[string]string{"Error": err.Error()},
				BodyText:   err.Error(),
			}, nil
		}
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	body = string(data)
	statusCode = resp.StatusCode

	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &HTTPResponse{
		StatusCode: statusCode,
		Headers:    headers,
		BodyText:   body,
	}, nil
}

var titleRegex = regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)

func extractTitle(body string) string {
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

type PortScanner struct {
	Target    string
	Ports     []int
	Timeout   time.Duration
	RateLimit time.Duration
}

func NewPortScanner(target string) (*PortScanner, error) {
	if err := sanitizeTarget(target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	defaultPorts := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443}
	return &PortScanner{
		Target:    target,
		Ports:     defaultPorts,
		Timeout:   3 * time.Second,
		RateLimit: 50 * time.Millisecond,
	}, nil
}

func (s *PortScanner) Scan(ctx context.Context) ([]Port, error) {
	var openPorts []Port

	sem := make(chan struct{}, 100)
	results := make(chan Port, len(s.Ports))
	var wg sync.WaitGroup

	go func() {
		defer func() {
			wg.Wait()
			close(results)
		}()
		for _, port := range s.Ports {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				wg.Add(1)
				go func(p int) {
					defer func() {
						<-sem
						wg.Done()
					}()
					address := net.JoinHostPort(s.Target, strconv.Itoa(p))
					conn, err := net.DialTimeout("tcp", address, s.Timeout)
					if err != nil {
						return
					}
					conn.Close()
					select {
					case results <- Port{
						Number:   p,
						Protocol: "tcp",
						State:    "open",
						Service:  guessService(p),
					}:
					case <-ctx.Done():
					}
				}(port)
			}
		}
	}()

	for port := range results {
		openPorts = append(openPorts, port)
	}

	return openPorts, nil
}

func guessService(port int) string {
	services := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		135:  "msrpc",
		139:  "netbios-ssn",
		443:  "https",
		445:  "microsoft-ds",
		993:  "imaps",
		995:  "pop3s",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		8080: "http-proxy",
		8443: "https-alt",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return "unknown"
}

func ParseNmapXML(xmlData string) (*NmapResult, error) {
	type NmapRun struct {
		XMLName xml.Name `xml:"nmaprun"`
		Host    []struct {
			Address struct {
				Addr string `xml:"addr,attr"`
			} `xml:"address"`
			Ports struct {
				Port []struct {
					PortID   string `xml:"portid,attr"`
					Protocol string `xml:"protocol,attr"`
					State    struct {
						State string `xml:"state,attr"`
					} `xml:"state"`
					Service struct {
						Name    string `xml:"name,attr"`
						Version string `xml:"version,attr"`
					} `xml:"service"`
				} `xml:"port"`
			} `xml:"ports"`
			Times struct {
				Latency string `xml:"latency,attr"`
			} `xml:"times"`
		} `xml:"host"`
	}

	var run NmapRun
	if err := xml.Unmarshal([]byte(xmlData), &run); err != nil {
		return nil, err
	}

	if len(run.Host) == 0 {
		return nil, fmt.Errorf("no hosts found in nmap output")
	}

	host := run.Host[0]
	var ports []Port
	for _, p := range host.Ports.Port {
		n, _ := strconv.Atoi(p.PortID)
		ports = append(ports, Port{
			Number:   n,
			Protocol: p.Protocol,
			State:    p.State.State,
			Service:  p.Service.Name,
			Version:  p.Service.Version,
		})
	}

	return &NmapResult{
		Host:    host.Address.Addr,
		Ports:   ports,
		Latency: host.Times.Latency,
	}, nil
}
