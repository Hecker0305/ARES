package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
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

type EncryptedToken struct {
	Ciphertext []byte
	Nonce      []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

type Engine struct {
	client    *http.Client
	oobDomain string
	aead      cipher.AEAD
}

func NewEngine(oobDomain string) *Engine {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		logger.Error(fmt.Sprintf("failed to generate encryption key: %v", err))
		return nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create cipher: %v", err))
		return nil
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create GCM: %v", err))
		return nil
	}

	return &Engine{
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		oobDomain: oobDomain,
		aead:      aead,
	}
}

func (e *Engine) encryptToken(token string) (*EncryptedToken, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := e.aead.Seal(nil, nonce, []byte(token), nil)

	return &EncryptedToken{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}, nil
}

func (e *Engine) decryptToken(et *EncryptedToken) (string, error) {
	if time.Now().After(et.ExpiresAt) {
		return "", fmt.Errorf("encrypted token has expired")
	}

	plaintext, err := e.aead.Open(nil, et.Nonce, et.Ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token: %w", err)
	}

	return string(plaintext), nil
}

func (e *Engine) TestAll(authorizeURL, tokenURL string) ([]Finding, error) {
	var findings []Finding

	openRedirectFindings, _ := e.TestOpenRedirect(authorizeURL)
	findings = append(findings, openRedirectFindings...)

	stateFixationFindings, _ := e.TestStateFixation(authorizeURL)
	findings = append(findings, stateFixationFindings...)

	tokenLeakageFindings, _ := e.TestTokenLeakage(authorizeURL)
	findings = append(findings, tokenLeakageFindings...)

	pkceBypassFindings, _ := e.TestPKCEBypass(authorizeURL, tokenURL)
	findings = append(findings, pkceBypassFindings...)

	implicitGrantFindings, _ := e.TestImplicitGrant(authorizeURL)
	findings = append(findings, implicitGrantFindings...)

	return findings, nil
}

func (e *Engine) TestOpenRedirect(authorizeURL string) ([]Finding, error) {
	var findings []Finding

	redirectPayloads := []string{
		"https://evil.com",
		"https://evil.com/callback",
		"//evil.com",
		"https://evil.com%40trusted.com",
		"https://trusted.com.evil.com",
		"https://trusted.com%2F.evil.com",
	}

	for _, redirect := range redirectPayloads {
		u, err := url.Parse(authorizeURL)
		if err != nil {
			continue
		}

		q := u.Query()
		q.Set("redirect_uri", redirect)
		q.Set("response_type", "code")
		q.Set("client_id", "test-client")
		u.RawQuery = q.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ARES-OAuth/1.0")

		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}

		location := resp.Header.Get("Location")
		if location != "" && strings.Contains(location, "evil.com") {
			findings = append(findings, Finding{
				URL:       u.String(),
				Type:      "oauth_open_redirect",
				Payload:   "redirect_uri=[REDACTED]",
				Evidence:  fmt.Sprintf("Redirected to: %s", redactURL(location)),
				Severity:  "high",
				Confirmed: true,
				Timestamp: time.Now(),
			})
		}
		resp.Body.Close()
	}

	return findings, nil
}

func (e *Engine) TestStateFixation(authorizeURL string) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(authorizeURL)
	if err != nil {
		return findings, err
	}

	q := u.Query()
	q.Set("state", "FIXED_STATE_VALUE")
	q.Set("response_type", "code")
	q.Set("client_id", "test-client")
	q.Set("redirect_uri", "https://localhost/callback")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("User-Agent", "ARES-OAuth/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location != "" {
		locURL, _ := url.Parse(location)
		stateParam := locURL.Query().Get("state")
		if stateParam == "FIXED_STATE_VALUE" {
			findings = append(findings, Finding{
				URL:       u.String(),
				Type:      "oauth_state_fixation",
				Payload:   "state=[REDACTED]",
				Evidence:  "Server accepted attacker-controlled state parameter",
				Severity:  "medium",
				Confirmed: true,
				Timestamp: time.Now(),
			})
		}
	}

	return findings, nil
}

func (e *Engine) TestTokenLeakage(authorizeURL string) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(authorizeURL)
	if err != nil {
		return findings, err
	}

	q := u.Query()
	q.Set("response_type", "token")
	q.Set("client_id", "test-client")
	q.Set("redirect_uri", "https://localhost/callback")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("User-Agent", "ARES-OAuth/1.0")
	req.Header.Set("Referer", "https://evil.com")

	resp, err := e.client.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location != "" && (strings.Contains(location, "access_token=") || strings.Contains(location, "token=")) {
		encrypted, err := e.encryptToken(location)
		if err != nil {
			return findings, err
		}
		// encrypted token is intentionally not stored — security measure to prevent token leakage
		// we only store the fact that we captured and encrypted it as evidence
		_ = encrypted
		findings = append(findings, Finding{
			URL:       u.String(),
			Type:      "oauth_token_leakage_referer",
			Payload:   "response_type=token",
			Evidence:  "Token exposed in redirect URL (token value encrypted and redacted)",
			Severity:  "high",
			Confirmed: true,
			Timestamp: time.Now(),
		})
	}

	return findings, nil
}

func (e *Engine) TestPKCEBypass(authorizeURL, tokenURL string) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(authorizeURL)
	if err != nil {
		return findings, err
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "test-client")
	q.Set("redirect_uri", "https://localhost/callback")
	q.Set("code_challenge", "invalid_challenge")
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("User-Agent", "ARES-OAuth/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location != "" && strings.Contains(location, "code=") {
		locURL, _ := url.Parse(location)
		authCode := locURL.Query().Get("code")

		if authCode != "" {
			tokenReq, _ := http.NewRequest("POST", tokenURL, strings.NewReader(url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"redirect_uri":  {"https://localhost/callback"},
				"client_id":     {"test-client"},
				"code_verifier": {"invalid_verifier"},
			}.Encode()))
			tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			tokenResp, err := e.client.Do(tokenReq)
			if err == nil {
				defer tokenResp.Body.Close()
				tokenBody, _ := io.ReadAll(tokenResp.Body)

				if tokenResp.StatusCode == http.StatusOK {
					encrypted, err := e.encryptToken(string(tokenBody))
					if err != nil {
						return findings, err
					}
					// encrypted token intentionally not stored — security measure
					_ = encrypted
					findings = append(findings, Finding{
						URL:       tokenURL,
						Type:      "oauth_pkce_bypass",
						Payload:   "Invalid code_verifier accepted",
						Evidence:  "PKCE bypass confirmed (response body encrypted and redacted)",
						Severity:  "critical",
						Confirmed: true,
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

func (e *Engine) TestImplicitGrant(authorizeURL string) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(authorizeURL)
	if err != nil {
		return findings, err
	}

	q := u.Query()
	q.Set("response_type", "token id_token")
	q.Set("client_id", "test-client")
	q.Set("redirect_uri", "https://localhost/callback")
	q.Set("nonce", "test-nonce")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("User-Agent", "ARES-OAuth/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location != "" && strings.Contains(location, "access_token=") {
		findings = append(findings, Finding{
			URL:       u.String(),
			Type:      "oauth_implicit_grant",
			Payload:   "response_type=token id_token",
			Evidence:  "Implicit grant enabled, token in URL (token value redacted)",
			Severity:  "medium",
			Confirmed: true,
			Timestamp: time.Now(),
		})
	}

	return findings, nil
}

func (e *Engine) TestConfusedDeputy(authorizeURL string) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(authorizeURL)
	if err != nil {
		return findings, err
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "attacker-client-id")
	q.Set("redirect_uri", "https://attacker.com/callback")
	q.Set("scope", "openid profile email")
	q.Set("prompt", "consent")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("User-Agent", "ARES-OAuth/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
		findings = append(findings, Finding{
			URL:       u.String(),
			Type:      "oauth_confused_deputy",
			Payload:   "Attacker-controlled client_id and redirect_uri",
			Evidence:  fmt.Sprintf("Server responded with status %d", resp.StatusCode),
			Severity:  "medium",
			Confirmed: true,
			Timestamp: time.Now(),
		})
	}

	return findings, nil
}

func redactURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "[REDACTED]"
	}
	if parsed.RawQuery != "" {
		q := parsed.Query()
		for key := range q {
			if strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "password") {
				q.Set(key, "[REDACTED]")
			}
		}
		parsed.RawQuery = q.Encode()
	}
	return parsed.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
