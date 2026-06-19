package agent

import (
	"github.com/ares/engine/internal/uuid"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

func (a *Agent) autoDetectJS(output string) string {
	patterns := []string{".js", "javascript", "bundle.js", "app.js", "main.js", "chunk.js"}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		for _, pat := range patterns {
			if strings.Contains(strings.ToLower(line), pat) && (strings.Contains(line, "http") || strings.Contains(line, "/")) {
				parts := strings.Fields(line)
				for _, part := range parts {
					if strings.HasPrefix(part, "http") && strings.Contains(part, ".js") {
						return strings.TrimSuffix(strings.Split(part, "?")[0], ".js") + ".js"
					}
				}
				re := regexp.MustCompile(`https?://[^\s\"'<>]+\.js[^\s\"'<>]*`)
				if m := re.FindString(line); m != "" {
					return strings.Split(m, "?")[0]
				}
			}
		}
	}
	return ""
}

func (a *Agent) extractCommand(params json.RawMessage) string {
	var p struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Command
}

func (a *Agent) extractPayload(params json.RawMessage) string {
	var p struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Payload
}

func agentIsWAFBlock(output string) bool {
	lower := strings.ToLower(output)
	// Require multiple signals to reduce false positives
	signals := 0
	if strings.Contains(lower, "403 forbidden") || strings.Contains(lower, "403") {
		signals++
	}
	if strings.Contains(lower, "waf") || strings.Contains(lower, "blocked") {
		signals++
	}
	if strings.Contains(lower, "access denied") || strings.Contains(lower, " captcha") {
		signals++
	}
	if strings.Contains(lower, "rate limit") {
		signals++
	}
	return signals >= 2
}

func agentExtractPayloadFromError(output string) string {
	markers := []string{"payload", "xss", "sql", "injection", "<script", "' or '", "file=", "cmd="}
	lower := strings.ToLower(output)
	for _, m := range markers {
		idx := strings.Index(lower, m)
		if idx > 0 {
			start := strings.LastIndex(output[:idx], "'")
			end := strings.Index(output[idx:], "'")
			if start != -1 && end != -1 {
				return output[start+1 : idx+end+1]
			}
		}
	}
	return ""
}

func agentContainsTechInfo(output string) bool {
	lower := strings.ToLower(output)
	keywords := []string{"apache", "nginx", "tomcat", "spring", "log4j", "exchange", "vcenter", "moveit", "big-ip", "rdp", "smb", "kubernetes", "k8s", "docker", "mysql", "postgresql", "redis", "mongodb", "elasticsearch", "wordpress", "joomla", "drupal", "sharepoint"}
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return uuid.New()
	}
	// Set version 4 bits
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func cryptoRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return int(n.Int64())
}
