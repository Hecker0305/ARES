package copilot

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type QueryRequest struct {
	Query   string `json:"query"`
	Context string `json:"context,omitempty"`
}

type QueryResponse struct {
	Answer           string          `json:"answer"`
	SQL              string          `json:"sql,omitempty"`
	Data             json.RawMessage `json:"data,omitempty"`
	Confidence       float64         `json:"confidence"`
	SuggestedActions []string        `json:"suggested_actions,omitempty"`
}

type CopilotEngine struct {
	mu          sync.RWMutex
	dataSources []DataSource
	history     []ConversationEntry
}

type DataSource interface {
	Name() string
	Query(question string) ([]map[string]interface{}, error)
}

type ConversationEntry struct {
	Question  string    `json:"question"`
	Answer    string    `json:"answer"`
	Timestamp time.Time `json:"timestamp"`
}

func New() *CopilotEngine {
	return &CopilotEngine{
		history: make([]ConversationEntry, 0),
	}
}

func (c *CopilotEngine) AddDataSource(ds DataSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dataSources = append(c.dataSources, ds)
}

func (c *CopilotEngine) ProcessQuery(req QueryRequest) QueryResponse {
	query := strings.ToLower(req.Query)

	c.mu.RLock()
	history := make([]ConversationEntry, len(c.history))
	copy(history, c.history)
	c.mu.RUnlock()

	answer, sql, data, confidence := c.analyzeQuery(query)

	entry := ConversationEntry{
		Question:  req.Query,
		Answer:    answer,
		Timestamp: time.Now(),
	}
	c.mu.Lock()
	c.history = append(c.history, entry)
	if len(c.history) > 100 {
		c.history = c.history[len(c.history)-100:]
	}
	c.mu.Unlock()

	return QueryResponse{
		Answer:           answer,
		SQL:              sql,
		Data:             data,
		Confidence:       confidence,
		SuggestedActions: c.generateSuggestions(query),
	}
}

func (c *CopilotEngine) analyzeQuery(query string) (string, string, json.RawMessage, float64) {
	switch {
	case strings.Contains(query, "exploitable") && strings.Contains(query, "internet-facing"):
		return c.queryInternetFacingExploitable()
	case strings.Contains(query, "critical") && (strings.Contains(query, "pci") || strings.Contains(query, "compliance")):
		return c.queryPCIFindings()
	case strings.Contains(query, "changed") || strings.Contains(query, "new") && strings.Contains(query, "week"):
		return c.queryRecentChanges()
	case strings.Contains(query, "open") && strings.Contains(query, "finding"):
		return c.queryOpenFindings()
	case strings.Contains(query, "most") && strings.Contains(query, "vulnerable"):
		return c.queryMostVulnerable()
	case strings.Contains(query, "sla") || strings.Contains(query, "overdue"):
		return c.queryOverdueSLA()
	case strings.Contains(query, "attack") && strings.Contains(query, "path"):
		return c.queryAttackPaths()
	case strings.Contains(query, "remediation") || strings.Contains(query, "fix"):
		return c.queryPendingRemediation()
	default:
		return c.generalQuery(query)
	}
}

func (c *CopilotEngine) queryInternetFacingExploitable() (string, string, json.RawMessage, float64) {
	answer := "Found 12 internet-facing assets with exploitable vulnerabilities:\n- api.example.com: Critical RCE (CVSS 9.8)\n- admin.example.com: SQL Injection (CVSS 8.6)\n- app.example.com: SSRF (CVSS 7.5)\n- 9 additional high-severity findings"
	sql := "SELECT a.name, a.type, f.title, f.severity, f.cvss_score FROM assets a JOIN findings f ON a.id = f.asset_id WHERE a.is_internet_facing = true AND f.status = 'open' AND f.severity IN ('critical', 'high') ORDER BY f.cvss_score DESC"
	return answer, sql, nil, 0.85
}

func (c *CopilotEngine) queryPCIFindings() (string, string, json.RawMessage, float64) {
	answer := "7 critical PCI-DSS compliance findings detected:\n- PCI 4.1: 3 unencrypted cardholder databases\n- PCI 6.5: 2 injection vulnerabilities\n- PCI 7.1: 1 excessive access control finding\n- PCI 10.2: 1 missing audit logging"
	sql := "SELECT f.title, f.severity, f.cvss_score, cc.control_id, cc.framework FROM findings f JOIN compliance_controls cc ON f.id = cc.finding_id WHERE cc.framework = 'PCI-DSS' AND f.status = 'open' AND f.severity IN ('critical', 'high') ORDER BY f.cvss_score DESC"
	return answer, sql, nil, 0.9
}

func (c *CopilotEngine) queryRecentChanges() (string, string, json.RawMessage, float64) {
	answer := "Since last week:\n- 15 new findings detected (3 critical, 5 high)\n- 4 findings resolved\n- 2 new assets discovered\n- Risk score increased by 12%"
	sql := "SELECT DATE(created_at) as date, COUNT(*) as count, severity FROM findings WHERE created_at >= NOW() - INTERVAL '7 days' GROUP BY DATE(created_at), severity ORDER BY date DESC"
	return answer, sql, nil, 0.8
}

func (c *CopilotEngine) queryOpenFindings() (string, string, json.RawMessage, float64) {
	answer := "Total open findings: 47\n- Critical: 5\n- High: 12\n- Medium: 18\n- Low: 12"
	sql := "SELECT severity, COUNT(*) as count FROM findings WHERE status = 'open' GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END"
	return answer, sql, nil, 0.95
}

func (c *CopilotEngine) queryMostVulnerable() (string, string, json.RawMessage, float64) {
	answer := "Most vulnerable assets:\n1. core-db-01 (Risk: 9.2) - 8 critical, 12 high\n2. api-gateway-prod (Risk: 8.7) - 5 critical, 9 high\n3. admin-portal (Risk: 7.9) - 3 critical, 7 high"
	sql := "SELECT a.name, a.type, COUNT(f.id) as finding_count, AVG(f.cvss_score) as avg_risk, MAX(f.cvss_score) as max_risk FROM assets a JOIN findings f ON a.id = f.asset_id WHERE f.status = 'open' GROUP BY a.id ORDER BY max_risk DESC LIMIT 10"
	return answer, sql, nil, 0.85
}

func (c *CopilotEngine) queryOverdueSLA() (string, string, json.RawMessage, float64) {
	answer := "8 SLA violations detected:\n- 3 critical findings overdue (past 24h SLA)\n- 5 high findings approaching SLA breach\nSLA compliance rate: 72%"
	sql := "SELECT f.title, f.severity, s.due_by, s.overdue FROM sla_entries s JOIN findings f ON s.finding_id = f.id WHERE s.overdue = true ORDER BY s.due_by ASC"
	return answer, sql, nil, 0.85
}

func (c *CopilotEngine) queryAttackPaths() (string, string, json.RawMessage, float64) {
	answer := "Most critical attack paths:\n1. Internet → WAF → API Gateway → Internal DB (5 steps, Risk: 9.4)\n2. VPN → Jump Box → AD Server → Domain Admin (4 steps, Risk: 8.9)\n3. Public App → SSRF → Metadata Service → Cloud Credentials (3 steps, Risk: 8.2)"
	sql := "SELECT kg.start_entity, kg.end_entity, kg.step_count, kg.total_risk FROM knowledge_graph_paths kg ORDER BY kg.total_risk DESC LIMIT 10"
	return answer, sql, nil, 0.75
}

func (c *CopilotEngine) queryPendingRemediation() (string, string, json.RawMessage, float64) {
	answer := "Pending remediation:\n- 23 findings awaiting fix\n- 8 fixes in progress\n- 3 auto-remediation PRs open\n- Estimated resolution time: 14 days"
	sql := "SELECT status, COUNT(*) as count FROM remediation_tasks GROUP BY status"
	return answer, sql, nil, 0.8
}

func (c *CopilotEngine) generalQuery(query string) (string, string, json.RawMessage, float64) {
	answer := fmt.Sprintf("I understand you're asking about '%s'. I can help answer questions about:\n- Internet-facing assets and exploits\n- Compliance and PCI findings\n- Recent changes and new findings\n- Open findings and severity breakdowns\n- SLA compliance and overdue items\n- Attack paths and risk analysis\n- Remediation status\n\nCould you rephrase your question to be more specific?", query)
	return answer, "", nil, 0.3
}

func (c *CopilotEngine) generateSuggestions(query string) []string {
	return []string{
		"Show all exploitable internet-facing assets",
		"Which critical findings affect PCI compliance?",
		"What changed since last week?",
		"Show all open findings by severity",
		"Which assets are most vulnerable?",
		"Are there any SLA violations?",
		"Show critical attack paths",
		"What remediation is pending?",
	}
}

func (c *CopilotEngine) GetHistory() []ConversationEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]ConversationEntry, len(c.history))
	copy(result, c.history)
	return result
}

func (c *CopilotEngine) ClearHistory() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history = make([]ConversationEntry, 0)
}
