package differential

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ares/engine/internal/security"
)

var digitRe = regexp.MustCompile(`\d+`)

func sanitizePayload(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			continue
		}
		if r == '\x00' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

type Result struct {
	Match         bool
	Similarity    float64
	DiffHash      string
	ResponseA     string
	ResponseB     string
	DiffRegions   []DiffRegion
	ResponseCodeA int
	ResponseCodeB int
}

type DiffRegion struct {
	Start    int
	End      int
	Context  string
	Category string
}

type TestCase struct {
	Payload      string
	Encoding     string
	Timing       time.Duration
	ResponseCode int
	Headers      map[string]string
	Body         string
	Hash         string
}

type Engine struct {
	client    *http.Client
	threshold float64
}

func NewEngine() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		threshold: 0.85,
	}
}

func (e *Engine) Threshold() float64 { return e.threshold }

func (e *Engine) CompareResponse(a, b string) (float64, string) {
	if a == b {
		return 1.0, ""
	}
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	diffCount := 0
	for i := range ha {
		if ha[i] != hb[i] {
			diffCount++
		}
	}
	similarity := 1.0 - (float64(diffCount) / 32.0)
	hash := sha256.Sum256([]byte(a + "||" + b))
	return similarity, hex.EncodeToString(hash[:])
}

func (e *Engine) TestFlakyVuln(reqA, reqB *http.Request, payload string) (bool, *Result) {
	respA, err := e.client.Do(reqA)
	if err != nil {
		return false, nil
	}
	defer respA.Body.Close()

	respB, err := e.client.Do(reqB)
	if err != nil {
		return false, nil
	}
	defer respB.Body.Close()

	bodyA, err := io.ReadAll(respA.Body)
	if err != nil {
		respB.Body.Close()
		return false, nil
	}
	bodyB, err := io.ReadAll(respB.Body)
	if err != nil {
		return false, nil
	}

	similarity, diffHash := e.CompareResponse(string(bodyA), string(bodyB))

	codeMatch := respA.StatusCode == respB.StatusCode
	bodyMatch := similarity >= e.threshold

	if !codeMatch || !bodyMatch {
		regions := e.findDiffRegions(string(bodyA), string(bodyB))
		return true, &Result{
			Match:       false,
			Similarity:  similarity,
			DiffHash:    diffHash,
			ResponseA:   string(bodyA),
			ResponseB:   string(bodyB),
			DiffRegions: regions,
		}
	}

	return false, nil
}

func (e *Engine) findDiffRegions(a, b string) []DiffRegion {
	var regions []DiffRegion

	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	var diffStart int = -1
	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			if diffStart == -1 {
				diffStart = i
			}
		} else {
			if diffStart != -1 {
				ctxStart := diffStart - 20
				if ctxStart < 0 {
					ctxStart = 0
				}
				ctxEnd := i + 20
				if ctxEnd > minLen {
					ctxEnd = minLen
				}
				category := categorizeDiff(a[diffStart:i], b[diffStart:i])
				regions = append(regions, DiffRegion{
					Start:    diffStart,
					End:      i,
					Context:  a[ctxStart:ctxEnd],
					Category: category,
				})
				diffStart = -1
			}
		}
	}

	if diffStart != -1 {
		ctxStart := diffStart - 20
		if ctxStart < 0 {
			ctxStart = 0
		}
		ctxEnd := minLen
		category := categorizeDiff(a[diffStart:], b[diffStart:])
		regions = append(regions, DiffRegion{
			Start:    diffStart,
			End:      minLen,
			Context:  a[ctxStart:ctxEnd],
			Category: category,
		})
	}

	return regions
}

func categorizeDiff(a, b string) string {
	if digitRe.MatchString(a + b) {
		return "numeric-change"
	}
	if strings.Contains(a+b, "error") || strings.Contains(a+b, "exception") {
		return "error-change"
	}
	if len(a) != len(b) {
		return "length-change"
	}
	return "content-change"
}

func (e *Engine) EncodeVariants(payload string) []*TestCase {
	var cases []*TestCase

	encodings := []struct {
		name  string
		apply func(string) string
	}{
		{"original", func(s string) string { return s }},
		{"url-encode", func(s string) string { return url.PathEscape(s) }},
		{"double-url-encode", func(s string) string { return url.PathEscape(url.PathEscape(s)) }},
		{"unicode-escape", func(s string) string {
			var sb strings.Builder
			for _, r := range s {
				sb.WriteString(fmt.Sprintf("\\u%04x", r))
			}
			return sb.String()
		}},
		{"url-unicode-composed", func(s string) string {
			var sb strings.Builder
			for _, r := range s {
				if r > 127 || r == '<' || r == '>' || r == '"' {
					sb.WriteString(fmt.Sprintf("%%u%04x", r))
				} else {
					sb.WriteRune(r)
				}
			}
			return sb.String()
		}},
	}

	for _, enc := range encodings {
		encoded := enc.apply(payload)
		cases = append(cases, &TestCase{
			Payload:      encoded,
			Encoding:     enc.name,
			ResponseCode: 0,
			Headers:      make(map[string]string),
		})
	}

	return cases
}

func (e *Engine) RunDifferential(baseURL, endpoint string, payloads []string, method string) map[string]*Result {
	results := make(map[string]*Result)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 20)

	for _, payload := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(payload string) {
			defer wg.Done()
			defer func() { <-sem }()

			safePayload := sanitizePayload(payload)
			encodedPayload := url.QueryEscape(safePayload)

			cases := e.EncodeVariants(safePayload)
			for _, tc := range cases {
				if err := security.ValidateURL(endpoint); err != nil {
					continue
				}
				reqBody := "param=" + encodedPayload
				req, err := http.NewRequest(method, endpoint, strings.NewReader(reqBody))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				start := time.Now()
				resp, err := e.client.Do(req)
				elapsed := time.Since(start)
				if err != nil {
					continue
				}
				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				resp.Body.Close()
				tc.ResponseCode = resp.StatusCode
				tc.Timing = elapsed
				tc.Body = string(respBody)
				tc.Headers = make(map[string]string)
				for k := range resp.Header {
					tc.Headers[k] = resp.Header.Get(k)
				}
				h := sha256.Sum256(respBody)
				tc.Hash = hex.EncodeToString(h[:])

				mu.Lock()
				key := fmt.Sprintf("%s:%s", payload, tc.Encoding)
				if existing, ok := results[key]; ok {
					if tc.ResponseCode != existing.ResponseCodeA || fuzzyMatch(string(respBody), existing.ResponseA) < e.threshold {
						_, diffHash := e.CompareResponse(existing.ResponseA, string(respBody))
						results[key] = &Result{
							Match:         fuzzyMatch(string(respBody), existing.ResponseA) < e.threshold,
							Similarity:    fuzzyMatch(string(respBody), existing.ResponseA),
							DiffHash:      diffHash,
							ResponseA:     existing.ResponseA,
							ResponseB:     string(respBody),
							ResponseCodeA: existing.ResponseCodeA,
							ResponseCodeB: tc.ResponseCode,
						}
					}
				} else {
					results[key] = &Result{
						ResponseA:     string(respBody),
						ResponseCodeA: tc.ResponseCode,
						ResponseB:     "",
						ResponseCodeB: 0,
					}
				}
				mu.Unlock()
			}
		}(payload)
	}

	wg.Wait()
	return results
}

func fuzzyMatch(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	ha := sha256.Sum256([]byte(strings.ToLower(a)))
	hb := sha256.Sum256([]byte(strings.ToLower(b)))
	diffCount := 0
	for i := range ha {
		if ha[i] != hb[i] {
			diffCount++
		}
	}
	return 1.0 - (float64(diffCount) / 32.0)
}

func (e *Engine) Summary(results map[string]*Result) string {
	var sb strings.Builder
	flaky := 0
	stable := 0
	for _, r := range results {
		if r.Match && r.Similarity < e.threshold {
			flaky++
		} else {
			stable++
		}
	}
	sb.WriteString(fmt.Sprintf("Differential testing: %d stable, %d flaky responses\n", stable, flaky))
	if flaky > 0 {
		sb.WriteString(fmt.Sprintf("Found %d payloads with inconsistent responses — may indicate intermittent WAF or real vulns missed by regex validator\n", flaky))
	}
	return sb.String()
}
