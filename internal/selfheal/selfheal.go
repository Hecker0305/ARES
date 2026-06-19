package selfheal

import (
	"github.com/ares/engine/internal/uuid"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type PatchSuggestion struct {
	VulnType     string `json:"vuln_type"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Language     string `json:"language"`
	SecureCode   string `json:"secure_code"`
	InsecureCode string `json:"insecure_code"`
	Explanation  string `json:"explanation"`
	CVEMapping   string `json:"cve_mapping,omitempty"`
	Complexity   string `json:"complexity"`
}

type RegressionTest struct {
	VulnType string `json:"vuln_type"`
	TestName string `json:"test_name"`
	TestCode string `json:"test_code"`
	Expected string `json:"expected"`
}

type PolicyRecommendation struct {
	Policy string `json:"policy"`
	Reason string `json:"reason"`
	Config string `json:"config"`
	Risk   string `json:"risk"`
}

type RemediationPlan struct {
	ID              string                 `json:"id"`
	Findings        []string               `json:"findings"`
	Patches         []PatchSuggestion      `json:"patches"`
	RegressionTests []RegressionTest       `json:"regression_tests"`
	Policies        []PolicyRecommendation `json:"policies"`
	Priority        int                    `json:"priority"`
	CreatedAt       time.Time              `json:"created_at"`
}

type ServiceIntegrity struct {
	Name           string
	BinaryPath     string
	ExpectedSHA256 string
}

type Engine struct {
	mu            sync.RWMutex
	remediationDB map[string][]PatchSuggestion
	testDB        map[string][]RegressionTest
	policyDB      map[string][]PolicyRecommendation
	integrityDB   map[string]ServiceIntegrity
}

func New() *Engine {
	e := &Engine{
		remediationDB: make(map[string][]PatchSuggestion),
		testDB:        make(map[string][]RegressionTest),
		policyDB:      make(map[string][]PolicyRecommendation),
		integrityDB:   make(map[string]ServiceIntegrity),
	}
	e.seedDefaults()
	return e
}

func (e *Engine) RegisterServiceIntegrity(name, binaryPath, expectedSHA256 string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.integrityDB[name] = ServiceIntegrity{
		Name:           name,
		BinaryPath:     binaryPath,
		ExpectedSHA256: expectedSHA256,
	}
}

func (e *Engine) VerifyServiceIntegrity(name string) error {
	e.mu.RLock()
	svc, ok := e.integrityDB[name]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("service %q not registered for integrity check", name)
	}

	data, err := os.ReadFile(svc.BinaryPath)
	if err != nil {
		return fmt.Errorf("cannot read binary %q: %w", svc.BinaryPath, err)
	}

	hash := sha256.Sum256(data)
	actualSHA256 := hex.EncodeToString(hash[:])

	if svc.ExpectedSHA256 != "" && actualSHA256 != svc.ExpectedSHA256 {
		return fmt.Errorf("integrity check failed for %q: expected %s, got %s", name, svc.ExpectedSHA256, actualSHA256)
	}
	return nil
}

func (e *Engine) VerifyAndRestart(serviceName string, restartFn func() error) error {
	if err := e.VerifyServiceIntegrity(serviceName); err != nil {
		return fmt.Errorf("refusing to restart %s: %w", serviceName, err)
	}
	return restartFn()
}

func (e *Engine) seedDefaults() {
	e.remediationDB["sqli"] = []PatchSuggestion{
		{
			VulnType: "sqli", Severity: "Critical",
			Title:    "SQL Injection in user input handling",
			Language: "go",
			InsecureCode: `func getUser(id string) *User {
	query := "SELECT * FROM users WHERE id='" + id + "'"
	rows := db.Query(query)
}`,
			SecureCode: `func getUser(id string) *User {
	query := "SELECT * FROM users WHERE id = ?"
	rows := db.Query(query, id)
}`,
			Explanation: "Use parameterized queries. String concatenation allows SQL injection.",
			Complexity:  "low",
		},
		{
			VulnType: "sqli", Severity: "Critical",
			Title:    "SQL Injection in search endpoint",
			Language: "python",
			InsecureCode: `def search_users(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)`,
			SecureCode: `def search_users(name):
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (name,))`,
			Explanation: "Use prepared statements with parameter binding.",
			Complexity:  "low",
		},
	}
	e.remediationDB["xss"] = []PatchSuggestion{
		{
			VulnType: "xss", Severity: "High",
			Title:    "Reflected XSS in search results",
			Language: "go",
			InsecureCode: `func searchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, "<html><body>Search: %s</body></html>", q)
}`,
			SecureCode: `func searchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	tmpl := "<html><body>Search: {{.}}</body></html>"
	t := template.Must(template.New("search").Parse(tmpl))
	t.Execute(w, q)
}`,
			Explanation: "Use HTML templates with auto-escaping. Never use fmt.Sprintf for HTML.",
			Complexity:  "low",
		},
	}
	e.remediationDB["ssrf"] = []PatchSuggestion{
		{
			VulnType: "ssrf", Severity: "High",
			Title:    "SSRF via URL parameter",
			Language: "go",
			InsecureCode: `func fetchURL(url string) (string, error) {
	resp, err := http.Get(url)
	return resp.Body.String(), err
}`,
			SecureCode: `var allowedHosts = []string{"api.example.com", "cdn.example.com"}

func fetchURL(urlStr string) (string, error) {
	parsed, err := url.Parse(urlStr)
	if err != nil { return "", err }
	if !isAllowed(parsed.Host) { return "", fmt.Errorf("host not allowed") }
	resp, err := http.Get(urlStr)
	return resp.Body.String(), err
}

func isAllowed(host string) bool {
	for _, a := range allowedHosts {
		if host == a { return true }
	}
	return false
}`,
			Explanation: "Implement URL allowlist. Never make requests to arbitrary URLs from user input.",
			Complexity:  "medium",
		},
	}
	e.remediationDB["lfi"] = []PatchSuggestion{
		{
			VulnType: "lfi", Severity: "High",
			Title:    "Local File Inclusion in template rendering",
			Language: "php",
			InsecureCode: `$file = $_GET['page'];
include($file . '.php');`,
			SecureCode: `$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed)) {
    include($page . '.php');
} else {
    include('home.php');
}`,
			Explanation: "Use file whitelist. Never include files based on user input without validation.",
			Complexity:  "low",
		},
	}
	e.remediationDB["rce"] = []PatchSuggestion{
		{
			VulnType: "rce", Severity: "Critical",
			Title:    "Remote Code Execution via shell injection",
			Language: "go",
			InsecureCode: `func runCommand(cmd string) (string, error) {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	return string(out), nil
}`,
			SecureCode: `func runCommand(binary string, args ...string) (string, error) {
	cmd := exec.Command(binary, args...)
	out, err := cmd.Output()
	return string(out), err
}`,
			Explanation: "Never use shell -c. Use exec.Command with explicit arguments.",
			Complexity:  "low",
		},
	}

	e.testDB["sqli"] = []RegressionTest{
		{
			VulnType: "sqli", TestName: "TestSQLiPrevention",
			TestCode: `func TestSQLiPrevention(t *testing.T) {
	payload := "' OR '1'='1"
	user := getUser(payload)
	if user != nil {
		t.Error("SQL injection should not return results")
	}
}`,
			Expected: "No SQL injection should succeed",
		},
	}
	e.testDB["xss"] = []RegressionTest{
		{
			VulnType: "xss", TestName: "TestXSSPrevention",
			TestCode: `func TestXSSPrevention(t *testing.T) {
	payload := "<script>alert(1)</script>"
	result := searchHandler(payload)
	if strings.Contains(result, payload) {
		t.Error("XSS should be escaped in output")
	}
}`,
			Expected: "No raw XSS payload should appear in response",
		},
	}

	e.policyDB["ssrf"] = []PolicyRecommendation{
		{
			Policy: "Restrict outbound network access",
			Reason: "Prevent SSRF attacks by restricting which hosts can be accessed",
			Config: `network_policy:
  egress:
    allow:
      - api.example.com:443
      - cdn.example.com:443
    deny:
      - 169.254.0.0/16
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16`,
			Risk: "High",
		},
	}
	e.policyDB["sqli"] = []PolicyRecommendation{
		{
			Policy: "Use parameterized queries",
			Reason: "Prevent SQL injection by enforcing prepared statements",
			Config: `code_review:
  rules:
    - id: sql-injection-prevention
      pattern: 'SELECT * FROM .* WHERE .* \$?\{?\w*\}?'
      severity: error
      message: "Use parameterized queries instead of string interpolation"`,
			Risk: "Critical",
		},
	}
}

func (e *Engine) GeneratePatch(vulnType string) *PatchSuggestion {
	e.mu.RLock()
	defer e.mu.RUnlock()
	patches, ok := e.remediationDB[vulnType]
	if !ok || len(patches) == 0 {
		return nil
	}
	return &patches[0]
}

func (e *Engine) GenerateAllPatches(vulnType string) []PatchSuggestion {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.remediationDB[vulnType]
}

func (e *Engine) GenerateRegressionTest(vulnType string) *RegressionTest {
	e.mu.RLock()
	defer e.mu.RUnlock()
	tests, ok := e.testDB[vulnType]
	if !ok || len(tests) == 0 {
		return nil
	}
	return &tests[0]
}

func (e *Engine) GeneratePolicyRecommendation(vulnType string) *PolicyRecommendation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	policies, ok := e.policyDB[vulnType]
	if !ok || len(policies) == 0 {
		return nil
	}
	return &policies[0]
}

func (e *Engine) BuildRemediationPlan(findings []string) *RemediationPlan {
	e.mu.RLock()
	defer e.mu.RUnlock()
	plan := &RemediationPlan{
		ID:              uuid.New(),
		Findings:        findings,
		Patches:         make([]PatchSuggestion, 0),
		RegressionTests: make([]RegressionTest, 0),
		Policies:        make([]PolicyRecommendation, 0),
		CreatedAt:       time.Now(),
	}

	for _, finding := range findings {
		normalized := strings.ToLower(finding)
		if patches := e.GenerateAllPatches(normalized); patches != nil {
			plan.Patches = append(plan.Patches, patches...)
		}
		if test := e.GenerateRegressionTest(normalized); test != nil {
			plan.RegressionTests = append(plan.RegressionTests, *test)
		}
		if policy := e.GeneratePolicyRecommendation(normalized); policy != nil {
			plan.Policies = append(plan.Policies, *policy)
		}
	}

	criticalCount := 0
	for _, p := range plan.Patches {
		if p.Severity == "Critical" {
			criticalCount++
		}
	}
	if criticalCount > 0 {
		plan.Priority = 1
	} else if len(plan.Patches) > 0 {
		plan.Priority = 2
	} else {
		plan.Priority = 3
	}

	return plan
}

func (e *Engine) FormatRemediation(plan *RemediationPlan) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Remediation Plan (Priority: P%d)\n\n", plan.Priority))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", plan.CreatedAt.Format(time.RFC3339)))

	sb.WriteString("## Patches Required\n\n")
	for _, patch := range plan.Patches {
		sb.WriteString(fmt.Sprintf("### %s (%s)\n\n", patch.Title, patch.Severity))
		sb.WriteString(fmt.Sprintf("- Vuln Type: %s\n", patch.VulnType))
		sb.WriteString(fmt.Sprintf("- Language: %s\n", patch.Language))
		sb.WriteString(fmt.Sprintf("- Complexity: %s\n\n", patch.Complexity))
		sb.WriteString("**Insecure Code:**\n```\n" + patch.InsecureCode + "\n```\n\n")
		sb.WriteString("**Secure Code:**\n```\n" + patch.SecureCode + "\n```\n\n")
		sb.WriteString(fmt.Sprintf("**Explanation:** %s\n\n", patch.Explanation))
		sb.WriteString("---\n\n")
	}

	if len(plan.RegressionTests) > 0 {
		sb.WriteString("## Regression Tests\n\n")
		for _, test := range plan.RegressionTests {
			sb.WriteString(fmt.Sprintf("### %s\n\n", test.TestName))
			sb.WriteString("```go\n" + test.TestCode + "\n```\n\n")
			sb.WriteString(fmt.Sprintf("Expected: %s\n\n", test.Expected))
		}
	}

	if len(plan.Policies) > 0 {
		sb.WriteString("## Policy Recommendations\n\n")
		for _, p := range plan.Policies {
			sb.WriteString(fmt.Sprintf("- **%s** (%s risk): %s\n", p.Policy, p.Risk, p.Reason))
			sb.WriteString("```yaml\n" + p.Config + "\n```\n\n")
		}
	}

	return sb.String()
}
