package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var mcpAPIKey string

func init() {
	mcpAPIKey = os.Getenv("ARES_MCP_API_KEY")
	if mcpAPIKey == "" {
		mcpAPIKey = os.Getenv("ARES_API_KEY")
	}
}

type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type MCPCapabilities struct {
	Tools *struct{} `json:"tools,omitempty"`
}

type MCPTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema struct {
		Type       string               `json:"type"`
		Required   []string             `json:"required,omitempty"`
		Properties map[string]MCPSchema `json:"properties"`
	} `json:"inputSchema"`
}

type MCPSchema struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type MCPToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type MCPToolResult struct {
	Content []MCPContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

type MCPContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

var (
	scans   = make(map[string]*ScanState)
	scansMu sync.Mutex
	scanID  = 0
)

type ScanState struct {
	ID        string
	Target    string
	Status    string
	Findings  []Finding
	StartedAt time.Time
}

type Finding struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Severity string  `json:"severity"`
	Target   string  `json:"target"`
	Evidence string  `json:"-"`
	CVSS     float64 `json:"cvss"`
}

var tools = []MCPTool{
	{
		Name:        "scan",
		Description: "Start a security scan against a target URL or domain",
		InputSchema: struct {
			Type       string               `json:"type"`
			Required   []string             `json:"required,omitempty"`
			Properties map[string]MCPSchema `json:"properties"`
		}{
			Type:     "object",
			Required: []string{"target"},
			Properties: map[string]MCPSchema{
				"target": {Type: "string", Description: "Target URL or domain to scan"},
				"phases": {Type: "string", Description: "Comma-separated scan phases (optional)"},
			},
		},
	},
	{
		Name:        "get_findings",
		Description: "Get findings from a scan by scan ID",
		InputSchema: struct {
			Type       string               `json:"type"`
			Required   []string             `json:"required,omitempty"`
			Properties map[string]MCPSchema `json:"properties"`
		}{
			Type:     "object",
			Required: []string{"scan_id"},
			Properties: map[string]MCPSchema{
				"scan_id": {Type: "string", Description: "The scan ID to get findings for"},
			},
		},
	},
	{
		Name:        "get_scan_status",
		Description: "Get the status of a running or completed scan",
		InputSchema: struct {
			Type       string               `json:"type"`
			Required   []string             `json:"required,omitempty"`
			Properties map[string]MCPSchema `json:"properties"`
		}{
			Type:     "object",
			Required: []string{"scan_id"},
			Properties: map[string]MCPSchema{
				"scan_id": {Type: "string", Description: "The scan ID to check"},
			},
		},
	},
	{
		Name:        "get_attack_graph",
		Description: "Get the attack graph for a scan showing exploit chains",
		InputSchema: struct {
			Type       string               `json:"type"`
			Required   []string             `json:"required,omitempty"`
			Properties map[string]MCPSchema `json:"properties"`
		}{
			Type:     "object",
			Required: []string{"scan_id"},
			Properties: map[string]MCPSchema{
				"scan_id": {Type: "string", Description: "The scan ID to get the graph for"},
			},
		},
	},
	{
		Name:        "remediate",
		Description: "Get remediation suggestions for a finding",
		InputSchema: struct {
			Type       string               `json:"type"`
			Required   []string             `json:"required,omitempty"`
			Properties map[string]MCPSchema `json:"properties"`
		}{
			Type:     "object",
			Required: []string{"finding_id"},
			Properties: map[string]MCPSchema{
				"finding_id": {Type: "string", Description: "The finding ID to get remediation for"},
			},
		},
	},
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var req MCPRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			sendError(nil, -32700, "Parse error")
			continue
		}

		handleRequest(req)
	}
}

var mcpAuthToken string

func handleRequest(req MCPRequest) {
	switch req.Method {
	case "initialize":
		if mcpAPIKey != "" {
			var initParams struct {
				Capabilities map[string]interface{} `json:"capabilities"`
				ClientInfo   map[string]string      `json:"clientInfo"`
				APIKey       string                 `json:"apiKey"`
			}
			if req.Params != nil {
				json.Unmarshal(req.Params, &initParams)
			}
			if initParams.APIKey != mcpAPIKey {
				sendError(req.ID, -32601, "unauthorized: invalid or missing API key")
				return
			}
			mcpAuthToken = initParams.APIKey
		}
		sendResult(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "ares-engine",
				"version": "2.0.0",
			},
		})
	case "tools/list":
		if mcpAPIKey == "" || mcpAuthToken != mcpAPIKey {
			sendError(req.ID, -32601, "unauthorized")
			return
		}
		sendResult(req.ID, map[string]interface{}{
			"tools": tools,
		})
	case "tools/call":
		if mcpAPIKey == "" || mcpAuthToken != mcpAPIKey {
			sendError(req.ID, -32601, "unauthorized")
			return
		}
		handleToolCall(req)
	case "notifications/initialized":
		sendResult(req.ID, map[string]interface{}{})
	default:
		sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func handleToolCall(req MCPRequest) {
	var args struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &args); err != nil {
		sendError(req.ID, -32602, "Invalid tool call arguments")
		return
	}

	switch args.Name {
	case "scan":
		handleScan(req.ID, args.Arguments)
	case "get_findings":
		handleGetFindings(req.ID, args.Arguments)
	case "get_scan_status":
		handleGetScanStatus(req.ID, args.Arguments)
	case "get_attack_graph":
		handleGetAttackGraph(req.ID, args.Arguments)
	case "remediate":
		handleRemediate(req.ID, args.Arguments)
	default:
		sendError(req.ID, -32601, fmt.Sprintf("Unknown tool: %s", args.Name))
	}
}

func handleScan(id interface{}, args map[string]interface{}) {
	target, _ := args["target"].(string)
	if target == "" {
		sendError(id, -32602, "target is required")
		return
	}

	if !isValidTarget(target) {
		sendError(id, -32602, "invalid target: must be a valid URL or domain")
		return
	}

	scansMu.Lock()
	scanID++
	sid := fmt.Sprintf("ares-scan-%d", scanID)
	scans[sid] = &ScanState{
		ID:        sid,
		Target:    target,
		Status:    "running",
		StartedAt: time.Now(),
	}
	scansMu.Unlock()

	go simulateScan(sid, target)

	sendResult(id, MCPToolResult{
		Content: []MCPContent{{
			Type: "text",
			Text: fmt.Sprintf("Scan started: %s\nTarget: %s\nStatus: running\n\nUse get_scan_status to check progress or get_findings when complete.", sid, target),
		}},
	})
}

func handleGetFindings(id interface{}, args map[string]interface{}) {
	scanID, _ := args["scan_id"].(string)
	if scanID == "" {
		sendError(id, -32602, "scan_id is required")
		return
	}

	scansMu.Lock()
	scan, ok := scans[scanID]
	scansMu.Unlock()

	if !ok {
		sendError(id, -32601, "Scan not found")
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Scan: %s | Target: %s | Status: %s\n\n", scan.ID, scan.Target, scan.Status))
	sb.WriteString(fmt.Sprintf("Total findings: %d\n\n", len(scan.Findings)))

	for i, f := range scan.Findings {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, f.Severity, f.Title))
		sb.WriteString(fmt.Sprintf("   Target: %s | CVSS: %.1f\n", f.Target, f.CVSS))
		sb.WriteString(fmt.Sprintf("   Evidence: %s\n\n", f.Evidence))
	}

	sendResult(id, MCPToolResult{
		Content: []MCPContent{{Type: "text", Text: sb.String()}},
	})
}

func handleGetScanStatus(id interface{}, args map[string]interface{}) {
	scanID, _ := args["scan_id"].(string)
	if scanID == "" {
		sendError(id, -32602, "scan_id is required")
		return
	}

	scansMu.Lock()
	scan, ok := scans[scanID]
	scansMu.Unlock()

	if !ok {
		sendError(id, -32601, "Scan not found")
		return
	}

	sendResult(id, MCPToolResult{
		Content: []MCPContent{{
			Type: "text",
			Text: fmt.Sprintf("Scan: %s\nTarget: %s\nStatus: %s\nFindings: %d\nStarted: %s\nDuration: %s",
				scan.ID, scan.Target, scan.Status, len(scan.Findings),
				scan.StartedAt.Format(time.RFC3339),
				time.Since(scan.StartedAt).Round(time.Second)),
		}},
	})
}

func handleGetAttackGraph(id interface{}, args map[string]interface{}) {
	scanID, _ := args["scan_id"].(string)
	if scanID == "" {
		sendError(id, -32602, "scan_id is required")
		return
	}

	scansMu.Lock()
	scan, ok := scans[scanID]
	scansMu.Unlock()

	if !ok {
		sendError(id, -32601, "Scan not found")
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Attack Graph for %s (%s)\n\n", scan.Target, scan.ID))
	sb.WriteString("graph LR\n")

	for i, f := range scan.Findings {
		nodeID := fmt.Sprintf("v%d", i+1)
		sb.WriteString(fmt.Sprintf("  %s[\"%s<br/>%s\"]\n", nodeID, f.Title, f.Severity))
	}

	for i := 0; i < len(scan.Findings)-1; i++ {
		sb.WriteString(fmt.Sprintf("  v%d --> v%d\n", i+1, i+2))
	}

	sendResult(id, MCPToolResult{
		Content: []MCPContent{{Type: "text", Text: sb.String()}},
	})
}

func handleRemediate(id interface{}, args map[string]interface{}) {
	findingID, _ := args["finding_id"].(string)
	if findingID == "" {
		sendError(id, -32602, "finding_id is required")
		return
	}

	scansMu.Lock()
	var finding *Finding
	for _, scan := range scans {
		for i := range scan.Findings {
			if scan.Findings[i].ID == findingID {
				finding = &scan.Findings[i]
				break
			}
		}
	}
	scansMu.Unlock()

	if finding == nil {
		sendError(id, -32601, "Finding not found")
		return
	}

	remediation := getRemediation(finding)
	sendResult(id, MCPToolResult{
		Content: []MCPContent{{Type: "text", Text: remediation}},
	})
}

func getRemediation(f *Finding) string {
	remediations := map[string]string{
		"sqli": `## SQL Injection Remediation

**Affected:** ` + f.Target + `

### Fix
1. Use parameterized queries/prepared statements
2. Implement input validation with allowlists
3. Apply least-privilege database accounts
4. Use ORM frameworks with built-in protection

### Example (Go)
` + "```go" + `
// BAD
query := "SELECT * FROM users WHERE id = " + userInput

// GOOD
query := "SELECT * FROM users WHERE id = ?"
db.Query(query, userInput)
` + "```",
		"xss": `## Cross-Site Scripting Remediation

**Affected:** ` + f.Target + `

### Fix
1. Context-aware output encoding
2. Content Security Policy headers
3. Input validation and sanitization
4. Use framework auto-escaping

### Example
` + "```go" + `
import "html"
safeOutput := html.EscapeString(userInput)
` + "```",
		"rce": `## Remote Code Execution Remediation

**Affected:** ` + f.Target + `

### Fix
1. Never pass user input to system commands
2. Use allowlists for command arguments
3. Implement strict input validation
4. Use language-specific APIs instead of shell commands`,
	}

	lower := strings.ToLower(f.Title)
	for key, remediation := range remediations {
		if strings.Contains(lower, key) {
			return remediation
		}
	}

	return fmt.Sprintf(`## Remediation for %s

**Finding:** %s
**Severity:** %s
**Target:** %s

### General Recommendations
1. Review the affected endpoint for security controls
2. Implement input validation and output encoding
3. Apply principle of least privilege
4. Add security monitoring and logging
5. Conduct code review for similar patterns

### CVSS Score: %.1f`, f.Title, f.Title, f.Severity, f.Target, f.CVSS)
}

func isValidTarget(target string) bool {
	if len(target) > 2048 {
		return false
	}
	blocked := []string{"localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "metadata.google.internal"}
	lower := strings.ToLower(target)
	for _, b := range blocked {
		if strings.Contains(lower, b) {
			return false
		}
	}
	if strings.HasPrefix(lower, "file://") || strings.HasPrefix(lower, "gopher://") || strings.HasPrefix(lower, "ftp://") {
		return false
	}
	return true
}

func simulateScan(sid, target string) {
	time.Sleep(2 * time.Second)

	scansMu.Lock()
	scan, ok := scans[sid]
	if !ok {
		scansMu.Unlock()
		return
	}
	scan.Findings = append(scan.Findings, Finding{
		ID:       "f-1",
		Title:    "SQL Injection",
		Severity: "Critical",
		Target:   target,
		Evidence: "sqlmap confirmed time-based blind SQLi on /api/users?id=1",
		CVSS:     9.8,
	})
	scan.Findings = append(scan.Findings, Finding{
		ID:       "f-2",
		Title:    "XSS Reflected",
		Severity: "Medium",
		Target:   target,
		Evidence: "Payload reflected in response without encoding",
		CVSS:     6.1,
	})
	scan.Status = "completed"
	scansMu.Unlock()
}

func sendResult(id interface{}, result interface{}) {
	resp := MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}

func sendError(id interface{}, code int, message string) {
	resp := MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &MCPError{Code: code, Message: message},
	}
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}
