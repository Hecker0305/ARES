package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type BurpIntegration struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

type BurpIssue struct {
	Type              string  `json:"type"`
	Name              string  `json:"name"`
	Severity          string  `json:"severity"`
	Confidence        string  `json:"confidence"`
	URL               string  `json:"url"`
	Path              string  `json:"path"`
	Parameter         string  `json:"parameter,omitempty"`
	IssueBackground   string  `json:"issue_background,omitempty"`
	Remediation       string  `json:"remediation,omitempty"`
	RemediationDetail string  `json:"remediation_detail,omitempty"`
	Request           string  `json:"request,omitempty"`
	Response          string  `json:"response,omitempty"`
	CollaboratorEvent bool    `json:"collaborator_event,omitempty"`
	CVSS              float64 `json:"cvss,omitempty"`
}

type BurpScanConfig struct {
	Scope           []string `json:"scope"`
	ScanSpeed       string   `json:"scan_speed,omitempty"`
	ScanType        string   `json:"scan_type,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	InsertionPoints []string `json:"insertion_points,omitempty"`
}

func NewBurpIntegration(baseURL, apiKey string) *BurpIntegration {
	return &BurpIntegration{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

func (b *BurpIntegration) Connect() error {
	req, err := http.NewRequest("GET", b.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("burp connect request failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("burp connect failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("burp API returned status %d", resp.StatusCode)
	}
	return nil
}

func (b *BurpIntegration) SendRequest(method, path string, headers map[string]string, body []byte) ([]byte, error) {
	url := b.baseURL + path
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("burp request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("burp API error %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func (b *BurpIntegration) ImportFindings() ([]BurpIssue, error) {
	data, err := b.SendRequest("GET", "/issues", nil, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Issues []BurpIssue `json:"issues"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("burp parse issues: %w", err)
	}
	return response.Issues, nil
}

func (b *BurpIntegration) ImportFindingsBySeverity(severity string) ([]BurpIssue, error) {
	all, err := b.ImportFindings()
	if err != nil {
		return nil, err
	}

	var filtered []BurpIssue
	for _, issue := range all {
		if issue.Severity == severity {
			filtered = append(filtered, issue)
		}
	}
	return filtered, nil
}

func (b *BurpIntegration) ExportScanConfig(cfg BurpScanConfig) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}

	resp, err := b.SendRequest("POST", "/scan/config", nil, data)
	if err != nil {
		return "", err
	}

	var result struct {
		ConfigID string `json:"config_id"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("burp parse config response: %w", err)
	}
	return result.ConfigID, nil
}

func (b *BurpIntegration) StartScan(cfg BurpScanConfig) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}

	resp, err := b.SendRequest("POST", "/scan/start", nil, data)
	if err != nil {
		return "", err
	}

	var result struct {
		ScanID string `json:"scan_id"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("burp parse scan response: %w", err)
	}
	return result.ScanID, nil
}

func (b *BurpIntegration) GetScanStatus(scanID string) (string, error) {
	resp, err := b.SendRequest("GET", "/scan/"+scanID+"/status", nil, nil)
	if err != nil {
		return "", err
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("burp parse status: %w", err)
	}
	return result.Status, nil
}

func (b *BurpIntegration) StopScan(scanID string) error {
	_, err := b.SendRequest("POST", "/scan/"+scanID+"/stop", nil, nil)
	return err
}

func (b *BurpIntegration) GetTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "burp_scan",
			Description: "Start a Burp Suite scan against a target",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"target": {Type: "string", Description: "Target URL to scan"},
					"speed":  {Type: "string", Description: "Scan speed (slow/normal/fast)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "burp_import_findings",
			Description: "Import findings from Burp Suite",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"severity": {Type: "string", Description: "Filter by severity (optional)"},
				},
			},
		},
		{
			Name:        "burp_export_config",
			Description: "Export scan configuration to Burp Suite",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"scope": {Type: "array", Description: "URL scope list"},
				},
				Required: []string{"scope"},
			},
		},
	}
}
