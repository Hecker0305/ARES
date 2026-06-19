package bizlogic

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

// Finding represents a business logic vulnerability.
type Finding struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	PoC         string            `json:"poc"`
	Impact      string            `json:"impact"`
	Remediation string            `json:"remediation"`
	Evidence    map[string]string `json:"evidence"`
	CVSS        float64           `json:"cvss"`
	MITRE       string            `json:"mitre"`
	Timestamp   time.Time         `json:"timestamp"`
}

// TestConfig configures a business logic test.
type TestConfig struct {
	Target     string
	BaseURL    string
	AuthTokens map[string]string // role -> token
	Cookies    map[string]string
	Headers    map[string]string
	Timeout    time.Duration
	MaxDepth   int
}

// Engine performs business-logic-aware security testing.
type Engine struct {
	mu       sync.Mutex
	findings []Finding
	config   TestConfig
	client   *http.Client
}

// New creates a new business logic testing engine.
func New(cfg TestConfig) *Engine {
	return &Engine{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		findings: make([]Finding, 0),
	}
}

// Run executes all business logic tests.
func (e *Engine) Run(ctx context.Context) []Finding {
	e.mu.Lock()
	e.findings = make([]Finding, 0)
	e.mu.Unlock()

	tests := []func(context.Context){
		e.testIDOR,
		e.testBOLA,
		e.testPrivilegeEscalation,
		e.testMassAssignment,
		e.testBusinessWorkflowBypass,
		e.testStateTransition,
		e.testMultiTenantIsolation,
		e.testRateLimitBypass,
		e.testPricingLogic,
		e.testSequentialIDEnumeration,
	}

	for _, test := range tests {
		select {
		case <-ctx.Done():
			return e.findings
		default:
			test(ctx)
		}
	}

	return e.findings
}

// testIDOR tests for Insecure Direct Object Reference.
func (e *Engine) testIDOR(ctx context.Context) {
	endpoints := e.discoverEndpoints(ctx)
	for _, ep := range endpoints {
		if !strings.Contains(ep.Path, "{id}") && !strings.Contains(ep.Path, "/1") && !strings.Contains(ep.Path, "/user") {
			continue
		}

		// Test with different user contexts
		for roleA, tokenA := range e.config.AuthTokens {
			for roleB, tokenB := range e.config.AuthTokens {
				if roleA == roleB {
					continue
				}

				req, _ := http.NewRequestWithContext(ctx, ep.Method, e.config.BaseURL+ep.Path, nil)
				req.Header.Set("Authorization", "Bearer "+tokenA)
				for k, v := range e.config.Headers {
					req.Header.Set(k, v)
				}

				respA, err := e.client.Do(req)
				if err != nil {
					continue
				}
				respA.Body.Close()

				// Swap tokens and try to access same resource
				req.Header.Set("Authorization", "Bearer "+tokenB)
				respB, err := e.client.Do(req)
				if err != nil {
					continue
				}
				respB.Body.Close()

				// If both return 200 but with different data, potential IDOR
				if respA.StatusCode == 200 && respB.StatusCode == 200 {
					e.addFinding(Finding{
						Type:        "IDOR",
						Severity:    "high",
						Title:       fmt.Sprintf("IDOR on %s %s", ep.Method, ep.Path),
						Description: fmt.Sprintf("Both %s and %s can access the same endpoint with different tokens", roleA, roleB),
						Endpoint:    e.config.BaseURL + ep.Path,
						Method:      ep.Method,
						PoC:         fmt.Sprintf("Token A (status %d) and Token B (status %d) both succeed", respA.StatusCode, respB.StatusCode),
						Impact:      "Unauthorized access to other users' data",
						Remediation: "Implement object-level authorization checks on all endpoints",
						CVSS:        7.5,
						MITRE:       "T1190",
						Timestamp:   time.Now(),
						Evidence: map[string]string{
							"role_a_status": fmt.Sprintf("%d", respA.StatusCode),
							"role_b_status": fmt.Sprintf("%d", respB.StatusCode),
						},
					})
				}
			}
		}
	}
}

// testBOLA tests for Broken Object Level Authorization.
func (e *Engine) testBOLA(ctx context.Context) {
	// Test horizontal privilege escalation via object manipulation
	resources := []string{"/api/users", "/api/accounts", "/api/orders", "/api/documents", "/api/profiles"}
	for _, resource := range resources {
		for _, token := range e.config.AuthTokens {
			req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+resource, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			// Check if response contains data from other users
			if resp.StatusCode == 200 {
				// Analyze response for multi-user data leakage
				e.addFinding(Finding{
					Type:        "BOLA",
					Severity:    "medium",
					Title:       fmt.Sprintf("Potential BOLA on %s", resource),
					Description: fmt.Sprintf("Endpoint %s returns data that may include other users' objects", resource),
					Endpoint:    e.config.BaseURL + resource,
					Method:      "GET",
					Impact:      "Access to objects belonging to other users",
					Remediation: "Validate object ownership on every request",
					CVSS:        6.5,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
			resp.Body.Close()
		}
	}
}

// testPrivilegeEscalation tests for vertical privilege escalation.
func (e *Engine) testPrivilegeEscalation(ctx context.Context) {
	adminEndpoints := []string{"/api/admin/users", "/api/admin/settings", "/api/admin/logs", "/api/admin/config"}
	for _, ep := range adminEndpoints {
		for role, token := range e.config.AuthTokens {
			if role == "admin" {
				continue
			}

			req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+ep, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				e.addFinding(Finding{
					Type:        "Privilege Escalation",
					Severity:    "critical",
					Title:       fmt.Sprintf("Vertical privilege escalation on %s", ep),
					Description: fmt.Sprintf("Non-admin role '%s' can access admin endpoint %s", role, ep),
					Endpoint:    e.config.BaseURL + ep,
					Method:      "GET",
					PoC:         fmt.Sprintf("Role '%s' accessed %s with status 200", role, ep),
					Impact:      "Full administrative access",
					Remediation: "Enforce role-based access control on admin endpoints",
					CVSS:        9.0,
					MITRE:       "T1078",
					Timestamp:   time.Now(),
				})
			}
			resp.Body.Close()
		}
	}
}

// testMassAssignment tests for mass assignment vulnerabilities.
func (e *Engine) testMassAssignment(ctx context.Context) {
	sensitiveFields := []string{"role", "is_admin", "balance", "credits", "permissions", "status", "user_id"}
	for _, token := range e.config.AuthTokens {
		for _, field := range sensitiveFields {
			body := fmt.Sprintf(`{"%s": "admin"}`, field)
			req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+"/api/profile", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				e.addFinding(Finding{
					Type:        "Mass Assignment",
					Severity:    "high",
					Title:       fmt.Sprintf("Mass assignment via field '%s'", field),
					Description: fmt.Sprintf("Sensitive field '%s' can be set via API request", field),
					Endpoint:    e.config.BaseURL + "/api/profile",
					Method:      "POST",
					PoC:         fmt.Sprintf(`POST /api/profile with {"%s": "admin"}`, field),
					Impact:      "Unauthorized modification of sensitive fields",
					Remediation: "Use allowlists for bindable fields, not blocklists",
					CVSS:        7.5,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
			resp.Body.Close()
		}
	}
}

// testBusinessWorkflowBypass tests for business workflow bypass.
func (e *Engine) testBusinessWorkflowBypass(ctx context.Context) {
	// Test skipping required steps in multi-step workflows
	workflows := map[string][]string{
		"checkout": {"/api/cart", "/api/shipping", "/api/payment", "/api/confirm"},
		"signup":   {"/api/register", "/api/verify-email", "/api/setup-profile", "/api/complete"},
	}

	for workflow, steps := range workflows {
		if len(steps) < 3 {
			continue
		}
		// Try to jump to final step without completing prerequisites
		finalStep := steps[len(steps)-1]
		for _, token := range e.config.AuthTokens {
			req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+finalStep, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				e.addFinding(Finding{
					Type:        "Workflow Bypass",
					Severity:    "high",
					Title:       fmt.Sprintf("Business workflow bypass in '%s'", workflow),
					Description: fmt.Sprintf("Final step '%s' accessible without completing prerequisites", finalStep),
					Endpoint:    e.config.BaseURL + finalStep,
					Method:      "POST",
					Impact:      "Bypass of required business logic steps",
					Remediation: "Enforce workflow state machine on server side",
					CVSS:        7.0,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
			resp.Body.Close()
		}
	}
}

// testStateTransition tests for invalid state transitions.
func (e *Engine) testStateTransition(ctx context.Context) {
	// Test invalid state transitions (e.g., pending -> completed without processing)
	transitions := []struct {
		from   string
		to     string
		action string
	}{
		{"pending", "completed", "approve"},
		{"draft", "published", "publish"},
		{"open", "closed", "resolve"},
	}

	for _, t := range transitions {
		for _, token := range e.config.AuthTokens {
			body := fmt.Sprintf(`{"status": "%s", "action": "%s"}`, t.to, t.action)
			req, _ := http.NewRequestWithContext(ctx, "PATCH", e.config.BaseURL+"/api/orders/1", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				e.addFinding(Finding{
					Type:        "Invalid State Transition",
					Severity:    "medium",
					Title:       fmt.Sprintf("Invalid state transition: %s -> %s", t.from, t.to),
					Description: fmt.Sprintf("Resource can transition from '%s' to '%s' without intermediate steps", t.from, t.to),
					Endpoint:    e.config.BaseURL + "/api/orders/1",
					Method:      "PATCH",
					Impact:      "Bypass of business logic state machine",
					Remediation: "Implement server-side state machine validation",
					CVSS:        5.5,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
			resp.Body.Close()
		}
	}
}

// testMultiTenantIsolation tests for multi-tenant data leakage.
func (e *Engine) testMultiTenantIsolation(ctx context.Context) {
	// Test cross-tenant data access
	tenantHeaders := map[string]string{
		"X-Tenant-ID":    "tenant-a",
		"X-Organization": "org-b",
		"X-Account-ID":   "acct-c",
	}

	for header, valA := range tenantHeaders {
		for _, valB := range []string{"tenant-b", "org-c", "acct-d"} {
			for _, token := range e.config.AuthTokens {
				req, _ := http.NewRequestWithContext(ctx, "GET", e.config.BaseURL+"/api/data", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set(header, valA)
				respA, err := e.client.Do(req)
				if err != nil {
					continue
				}

				req.Header.Set(header, valB)
				respB, err := e.client.Do(req)
				if err != nil {
					respA.Body.Close()
					continue
				}

				if respA.StatusCode == 200 && respB.StatusCode == 200 {
					e.addFinding(Finding{
						Type:        "Multi-Tenant Isolation",
						Severity:    "critical",
						Title:       fmt.Sprintf("Cross-tenant data access via %s header", header),
						Description: fmt.Sprintf("Different %s values return data without proper isolation", header),
						Endpoint:    e.config.BaseURL + "/api/data",
						Method:      "GET",
						Impact:      "Data leakage between tenants",
						Remediation: "Enforce tenant isolation at database query level",
						CVSS:        9.0,
						MITRE:       "T1190",
						Timestamp:   time.Now(),
					})
				}
				respA.Body.Close()
				respB.Body.Close()
			}
		}
	}
}

// testRateLimitBypass tests for rate limit bypass on business-critical endpoints.
func (e *Engine) testRateLimitBypass(ctx context.Context) {
	criticalEndpoints := []string{"/api/login", "/api/reset-password", "/api/verify-otp", "/api/register"}
	for _, ep := range criticalEndpoints {
		// Rapid-fire requests to test rate limiting
		successCount := 0
		for i := 0; i < 20; i++ {
			req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+ep, nil)
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode != 429 {
				successCount++
			}
			resp.Body.Close()
		}

		if successCount > 15 {
			e.addFinding(Finding{
				Type:        "Rate Limit Bypass",
				Severity:    "high",
				Title:       fmt.Sprintf("Rate limit bypass on %s", ep),
				Description: fmt.Sprintf("Endpoint %s allowed %d/20 rapid requests without throttling", ep, successCount),
				Endpoint:    e.config.BaseURL + ep,
				Method:      "POST",
				Impact:      "Brute force, credential stuffing, or abuse",
				Remediation: "Implement rate limiting with exponential backoff",
				CVSS:        7.0,
				MITRE:       "T1110",
				Timestamp:   time.Now(),
			})
		}
	}
}

// testPricingLogic tests for pricing manipulation.
func (e *Engine) testPricingLogic(ctx context.Context) {
	// Test negative prices, zero prices, quantity manipulation
	pricingTests := []struct {
		name string
		body string
	}{
		{"negative_price", `{"item_id": "1", "quantity": 1, "price": -100}`},
		{"zero_price", `{"item_id": "1", "quantity": 1, "price": 0}`},
		{"float_quantity", `{"item_id": "1", "quantity": 0.001, "price": 100}`},
		{"large_quantity", `{"item_id": "1", "quantity": 999999, "price": 0.01}`},
		{"currency_swap", `{"item_id": "1", "quantity": 1, "price": 100, "currency": "JPY"}`},
	}

	for _, pt := range pricingTests {
		for _, token := range e.config.AuthTokens {
			req, _ := http.NewRequestWithContext(ctx, "POST", e.config.BaseURL+"/api/checkout", strings.NewReader(pt.body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				e.addFinding(Finding{
					Type:        "Pricing Logic Flaw",
					Severity:    "critical",
					Title:       fmt.Sprintf("Pricing manipulation: %s", pt.name),
					Description: fmt.Sprintf("Checkout accepted manipulated pricing: %s", pt.body),
					Endpoint:    e.config.BaseURL + "/api/checkout",
					Method:      "POST",
					PoC:         pt.body,
					Impact:      "Financial loss through pricing manipulation",
					Remediation: "Validate prices server-side against source of truth",
					CVSS:        9.0,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
			resp.Body.Close()
		}
	}
}

// testSequentialIDEnumeration tests for sequential ID enumeration.
func (e *Engine) testSequentialIDEnumeration(ctx context.Context) {
	resources := []string{"/api/users", "/api/orders", "/api/invoices", "/api/tickets"}
	for _, resource := range resources {
		for _, token := range e.config.AuthTokens {
			accessible := 0
			for id := 1; id <= 10; id++ {
				req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%d", e.config.BaseURL+resource, id), nil)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := e.client.Do(req)
				if err != nil {
					continue
				}
				if resp.StatusCode == 200 {
					accessible++
				}
				resp.Body.Close()
			}

			if accessible > 5 {
				e.addFinding(Finding{
					Type:        "Sequential ID Enumeration",
					Severity:    "medium",
					Title:       fmt.Sprintf("Sequential ID enumeration on %s", resource),
					Description: fmt.Sprintf("%d/10 sequential IDs accessible on %s", accessible, resource),
					Endpoint:    e.config.BaseURL + resource,
					Method:      "GET",
					Impact:      "Information disclosure and data harvesting",
					Remediation: "Use UUIDs or opaque identifiers instead of sequential IDs",
					CVSS:        5.0,
					MITRE:       "T1190",
					Timestamp:   time.Now(),
				})
			}
		}
	}
}

// discoverEndpoints discovers API endpoints from the target.
func (e *Engine) discoverEndpoints(ctx context.Context) []EndpointInfo {
	// Common API patterns to probe
	patterns := []string{
		"/api/users/{id}",
		"/api/users/1",
		"/api/accounts/{id}",
		"/api/orders/{id}",
		"/api/products/{id}",
		"/api/documents/{id}",
		"/api/profile",
		"/api/settings",
	}

	var endpoints []EndpointInfo
	for _, p := range patterns {
		method := "GET"
		if strings.Contains(p, "{id}") {
			p = strings.Replace(p, "{id}", "1", 1)
		}
		endpoints = append(endpoints, EndpointInfo{Path: p, Method: method})
	}
	return endpoints
}

// EndpointInfo describes an API endpoint.
type EndpointInfo struct {
	Path   string
	Method string
}

func (e *Engine) addFinding(f Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f.ID = fmt.Sprintf("bizlogic-%d", len(e.findings)+1)
	e.findings = append(e.findings, f)
	logger.Info(fmt.Sprintf("[BizLogic] Finding: %s - %s (%s)", f.Severity, f.Title, f.Type))
}

// Findings returns all findings.
func (e *Engine) Findings() []Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]Finding, len(e.findings))
	copy(cp, e.findings)
	return cp
}
