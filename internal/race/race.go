package race

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type Condition int

const (
	TOCTOU Condition = iota
	ConcurrentWrite
	DataRace
	AuthBypassRace
	SessionFixation
)

func (c Condition) String() string {
	switch c {
	case TOCTOU:
		return "TOCTOU"
	case ConcurrentWrite:
		return "concurrent_write"
	case DataRace:
		return "data_race"
	case AuthBypassRace:
		return "auth_bypass_race"
	case SessionFixation:
		return "session_fixation"
	default:
		return "unknown"
	}
}

type Config struct {
	TargetURL      string
	Concurrency    int
	Duration       time.Duration
	Method         string
	Body           string
	Headers        map[string]string
	Condition      Condition
	RaceWindow     time.Duration
	FollowRedirect bool
}

type Result struct {
	Condition  Condition     `json:"condition"`
	Vulnerable bool          `json:"vulnerable"`
	Evidence   []RequestPair `json:"evidence"`
	Summary    string        `json:"summary"`
}

type RequestPair struct {
	RequestA    string `json:"request_a"`
	ResponseA   string `json:"response_a"`
	StatusCodeA int    `json:"status_code_a"`
	RequestB    string `json:"request_b"`
	ResponseB   string `json:"response_b"`
	StatusCodeB int    `json:"status_code_b"`
	Delta       string `json:"delta"`
}

type Engine struct {
	client        *http.Client
	results       []Result
	mu            sync.Mutex
	skipTargetVal bool
}

func (e *Engine) SetSkipTargetValidation(skip bool) {
	e.skipTargetVal = skip
}

func New() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func validateTargetURL(targetURL string) error {
	if targetURL == "" {
		return fmt.Errorf("empty target URL")
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("empty host")
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
			return fmt.Errorf("target resolves to private/internal IP: %s", ip.String())
		}
	}
	return nil
}

func (e *Engine) Run(ctx context.Context, cfg Config) (*Result, error) {
	if !e.skipTargetVal {
		if err := validateTargetURL(cfg.TargetURL); err != nil {
			return nil, fmt.Errorf("URL validation failed: %w", err)
		}
	}
	switch cfg.Condition {
	case TOCTOU:
		return e.testTOCTOU(ctx, cfg)
	case ConcurrentWrite:
		return e.testConcurrentWrite(ctx, cfg)
	case DataRace:
		return e.testDataRace(ctx, cfg)
	case AuthBypassRace:
		return e.testAuthBypassRace(ctx, cfg)
	case SessionFixation:
		return e.testSessionFixation(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown race condition: %v", cfg.Condition)
	}
}

func (e *Engine) testTOCTOU(ctx context.Context, cfg Config) (*Result, error) {
	writeReq := func() (*http.Response, string, error) {
		req, err := e.buildRequest(cfg)
		if err != nil {
			return nil, "", err
		}
		resp, err := e.client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil {
			return resp, "", fmt.Errorf("failed to read response body: %v", err)
		}
		return resp, string(body), nil
	}

	readReq := func() (*http.Response, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.TargetURL, nil)
		if err != nil {
			return nil, "", err
		}
		for k, v := range cfg.Headers {
			req.Header.Set(k, v)
		}
		resp, err := e.client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil {
			return resp, "", fmt.Errorf("failed to read response body: %v", err)
		}
		return resp, string(body), nil
	}

	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 20
	}

	var pairs []RequestPair
	for i := 0; i < concurrency; i++ {
		var wg sync.WaitGroup
		var respA *http.Response
		var respB *http.Response
		var bodyA, bodyB string

		wg.Add(2)
		go func() {
			defer wg.Done()
			r, b, err := writeReq()
			if err != nil {
				logger.Error(fmt.Sprintf("[Race] writeReq failed: %v", err))
			}
			respA, bodyA = r, b
		}()
		go func() {
			defer wg.Done()
			r, b, err := readReq()
			if err != nil {
				logger.Error(fmt.Sprintf("[Race] readReq failed: %v", err))
			}
			respB, bodyB = r, b
		}()
		wg.Wait()

		if respA != nil && respB != nil {
			pairs = append(pairs, RequestPair{
				RequestA:    "WRITE " + cfg.TargetURL,
				ResponseA:   truncate(bodyA, 500),
				StatusCodeA: respA.StatusCode,
				RequestB:    "READ " + cfg.TargetURL,
				ResponseB:   truncate(bodyB, 500),
				StatusCodeB: respB.StatusCode,
				Delta:       diffBodies(bodyA, bodyB),
			})
		}
	}

	vulnerable := false
	summary := ""
	for _, p := range pairs {
		if p.StatusCodeA != p.StatusCodeB || (p.ResponseA != p.ResponseB && len(p.ResponseA) > 0 && len(p.ResponseB) > 0) {
			vulnerable = true
			summary = "TOCTOU detected: concurrent read/write produced inconsistent responses"
			break
		}
	}
	if !vulnerable {
		summary = "No TOCTOU detected"
	}

	result := &Result{
		Condition:  TOCTOU,
		Vulnerable: vulnerable,
		Evidence:   pairs,
		Summary:    summary,
	}
	e.mu.Lock()
	e.results = append(e.results, *result)
	e.mu.Unlock()
	return result, nil
}

func (e *Engine) testConcurrentWrite(ctx context.Context, cfg Config) (*Result, error) {
	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 30
	}

	var statusCodes []int
	var bodies []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for i := 0; i < concurrency*2; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			req, err := e.buildRequest(cfg)
			if err != nil {
				return
			}
			resp, err := e.client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
			if err != nil {
				logger.Error(fmt.Sprintf("[Race] failed to read response: %v", err))
				return
			}
			mu.Lock()
			statusCodes = append(statusCodes, resp.StatusCode)
			bodies = append(bodies, string(body))
			mu.Unlock()
		}()
	}
	wg.Wait()

	seen := make(map[string]int)
	for _, b := range bodies {
		key := truncate(b, 200)
		seen[key]++
	}

	vulnerable := len(seen) > 1
	summary := ""
	if vulnerable {
		summary = fmt.Sprintf("Concurrent write race: %d different response variants from %d requests", len(seen), len(bodies))
	} else {
		summary = "No concurrent write race detected"
	}

	result := &Result{
		Condition:  ConcurrentWrite,
		Vulnerable: vulnerable,
		Summary:    summary,
	}
	e.mu.Lock()
	e.results = append(e.results, *result)
	e.mu.Unlock()
	return result, nil
}

func (e *Engine) testDataRace(ctx context.Context, cfg Config) (*Result, error) {
	var raceDetected int32
	start := time.Now()
	duration := cfg.Duration
	if duration == 0 {
		duration = 5 * time.Second
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if atomic.LoadInt32(&raceDetected) > 0 {
					return
				}
				if time.Since(start) > duration {
					return
				}
				req, err := e.buildRequest(cfg)
				if err != nil {
					continue
				}
				resp, err := e.client.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
					atomic.StoreInt32(&raceDetected, 1)
				}
			}
		}()
	}
	wg.Wait()

	result := &Result{
		Condition:  DataRace,
		Vulnerable: atomic.LoadInt32(&raceDetected) > 0,
		Summary: func() string {
			if atomic.LoadInt32(&raceDetected) > 0 {
				return "Data race window detected"
			}
			return "No data race detected"
		}(),
	}
	e.mu.Lock()
	e.results = append(e.results, *result)
	e.mu.Unlock()
	return result, nil
}

func (e *Engine) testAuthBypassRace(ctx context.Context, cfg Config) (*Result, error) {
	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 50
	}

	var authedCode, unauthedCode int

	authedReq, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.TargetURL, strings.NewReader(cfg.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create authed request: %v", err)
	}
	for k, v := range cfg.Headers {
		authedReq.Header.Set(k, v)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp, err := e.client.Do(authedReq.Clone(ctx))
		if err == nil {
			resp.Body.Close()
			authedCode = resp.StatusCode
		}
	}()
	go func() {
		defer wg.Done()
		unauthedReq, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.TargetURL, strings.NewReader(cfg.Body))
		if err != nil {
			logger.Error(fmt.Sprintf("[Race] failed to create unauthed request: %v", err))
			return
		}
		resp, err := e.client.Do(unauthedReq)
		if err == nil {
			resp.Body.Close()
			unauthedCode = resp.StatusCode
		}
	}()
	wg.Wait()

	vulnerable := authedCode == unauthedCode && authedCode != http.StatusUnauthorized && authedCode != http.StatusForbidden
	summary := ""
	if vulnerable {
		summary = fmt.Sprintf("Auth bypass race: authed=%d unauthed=%d responses match", authedCode, unauthedCode)
	} else {
		summary = "No auth bypass race detected"
	}

	// Race window: fire many rapid sequential requests
	var rapidCodes []int
	for i := 0; i < concurrency; i++ {
		sessReq, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.TargetURL, strings.NewReader(cfg.Body))
		if err != nil {
			continue
		}
		resp, err := e.client.Do(sessReq)
		if err == nil {
			resp.Body.Close()
			rapidCodes = append(rapidCodes, resp.StatusCode)
		}
	}

	result := &Result{
		Condition:  AuthBypassRace,
		Vulnerable: vulnerable,
		Summary:    summary,
	}
	e.mu.Lock()
	e.results = append(e.results, *result)
	e.mu.Unlock()
	return result, nil
}

func (e *Engine) testSessionFixation(ctx context.Context, cfg Config) (*Result, error) {
	var pairs []RequestPair
	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 10
	}

	sessionCookie := &http.Cookie{Name: "session", Value: "attacker_set_value_" + uuid.New()}

	for i := 0; i < concurrency; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.TargetURL, nil)
		if err != nil {
			continue
		}
		req.AddCookie(sessionCookie)
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, c := range resp.Cookies() {
			if c.Name == sessionCookie.Name && c.Value == sessionCookie.Value {
				pairs = append(pairs, RequestPair{
					RequestA:    "FIXED SESSION: " + sessionCookie.Value,
					ResponseA:   truncate(string(body), 300),
					StatusCodeA: resp.StatusCode,
				})
			}
		}
	}

	vulnerable := len(pairs) > 0
	summary := ""
	if vulnerable {
		summary = fmt.Sprintf("Session fixation: attacker-controlled session cookie accepted in %d/%d requests", len(pairs), concurrency)
	} else {
		summary = "No session fixation detected"
	}

	result := &Result{
		Condition:  SessionFixation,
		Vulnerable: vulnerable,
		Evidence:   pairs,
		Summary:    summary,
	}
	e.mu.Lock()
	e.results = append(e.results, *result)
	e.mu.Unlock()
	return result, nil
}

func (e *Engine) buildRequest(cfg Config) (*http.Request, error) {
	var bodyReader io.Reader
	if cfg.Body != "" {
		bodyReader = strings.NewReader(cfg.Body)
	}
	req, err := http.NewRequest(cfg.Method, cfg.TargetURL, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func diffBodies(a, b string) string {
	if a == b {
		return "identical"
	}
	aLines := strings.Split(a, "\n")
	bLines := strings.Split(b, "\n")
	if len(aLines) != len(bLines) {
		return fmt.Sprintf("length differs: %d vs %d lines", len(aLines), len(bLines))
	}
	var diffs []string
	for i := 0; i < len(aLines) && i < len(bLines); i++ {
		if aLines[i] != bLines[i] {
			diffs = append(diffs, fmt.Sprintf("line %d differs", i+1))
			if len(diffs) >= 5 {
				break
			}
		}
	}
	return strings.Join(diffs, "; ")
}

func (e *Engine) Results() []Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Result, len(e.results))
	copy(out, e.results)
	return out
}

func (e *Engine) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results = nil
}
