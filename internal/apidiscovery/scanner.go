package apidiscovery

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/ares/engine/internal/ratelimit"
)

type Scanner struct {
	maxConcurrency int
	rateLimiter    *ratelimit.Limiter
	timeout        time.Duration
}

type ScanOption func(*Scanner)

func WithConcurrency(n int) ScanOption {
	return func(s *Scanner) {
		if n > 0 {
			s.maxConcurrency = n
		}
	}
}

func WithRateLimit(rps float64, burst int) ScanOption {
	return func(s *Scanner) {
		s.rateLimiter = ratelimit.New(rps, burst)
	}
}

func WithTimeout(d time.Duration) ScanOption {
	return func(s *Scanner) {
		if d > 0 {
			s.timeout = d
		}
	}
}

func NewScanner(opts ...ScanOption) *Scanner {
	s := &Scanner{
		maxConcurrency: 10,
		rateLimiter:    ratelimit.New(5, 10),
		timeout:        30 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) ScanTarget(ctx context.Context, baseURL string) *APIDiscoveryResult {
	if baseURL == "" {
		return &APIDiscoveryResult{Error: "empty target URL", TargetURL: baseURL}
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return &APIDiscoveryResult{Error: fmt.Sprintf("invalid target URL: %v", err), TargetURL: baseURL}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &APIDiscoveryResult{Error: fmt.Sprintf("unsupported scheme: %s", u.Scheme), TargetURL: baseURL}
	}
	if u.Host == "" {
		return &APIDiscoveryResult{Error: "empty host in target URL", TargetURL: baseURL}
	}

	scanStart := time.Now()
	result := &APIDiscoveryResult{
		TargetURL: baseURL,
		Timestamp: scanStart.Format(time.RFC3339),
	}

	d := NewDiscoverer(baseURL, s.timeout)

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.maxConcurrency)
	var mu sync.Mutex

	discoveryTasks := []struct {
		name string
		fn   func() *APIDiscoveryResult
	}{
		{"swagger", d.discoverSwagger},
		{"graphql", d.discoverGraphQL},
		{"grpc", d.discoverGRPC},
	}

	for _, task := range discoveryTasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(t struct {
			name string
			fn   func() *APIDiscoveryResult
		}) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			s.rateLimiter.Wait()

			taskCtx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()

			// We use a channel to handle the discovery result
			done := make(chan *APIDiscoveryResult, 1)
			go func() {
				done <- t.fn()
			}()

			var taskResult *APIDiscoveryResult
			select {
			case <-taskCtx.Done():
				return
			case taskResult = <-done:
			}

			if taskResult != nil {
				mu.Lock()
				if taskResult.SpecURL != "" {
					result.SpecURL = taskResult.SpecURL
					result.SpecVersion = taskResult.SpecVersion
				}
				if taskResult.GraphQLDetected {
					result.GraphQLDetected = true
					result.GraphQLEndpoint = taskResult.GraphQLEndpoint
				}
				if taskResult.GRPCDetected {
					result.GRPCDetected = true
					result.GRPCEndpoints = append(result.GRPCEndpoints, taskResult.GRPCEndpoints...)
				}
				result.Endpoints = append(result.Endpoints, taskResult.Endpoints...)
				result.AuthTypes = append(result.AuthTypes, taskResult.AuthTypes...)
				mu.Unlock()
			}
		}(task)
	}

	wg.Wait()

	mu.Lock()
	versions := d.detectAPIVersions()
	result.APIVersions = versions
	result.ScanDuration = time.Since(scanStart).Round(time.Millisecond).String()
	mu.Unlock()

	seen := make(map[string]bool)
	var deduped []DiscoveredEndpoint
	for _, ep := range result.Endpoints {
		key := ep.Method + ":" + ep.Path
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, ep)
		}
	}
	result.Endpoints = deduped

	if len(result.Endpoints) == 0 && !result.GraphQLDetected && !result.GRPCDetected {
		result.Error = fmt.Sprintf("no API endpoints discovered at %s", baseURL)
	}

	return result
}

func (s *Scanner) ScanTargets(ctx context.Context, targets []string) []*APIDiscoveryResult {
	results := make([]*APIDiscoveryResult, 0, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			s.rateLimiter.Wait()

			res := s.ScanTarget(ctx, t)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return results
}
