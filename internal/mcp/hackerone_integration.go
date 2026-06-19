package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HackerOneIntegration struct {
	client   *http.Client
	baseURL  string
	username string
	apiToken string
}

type HackerOneProgram struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Handle          string `json:"handle"`
		Name            string `json:"name"`
		State           string `json:"state"`
		OffersBounty    bool   `json:"offers_bounties"`
		SubmissionState string `json:"submission_state"`
	} `json:"attributes"`
}

type HackerOneScope struct {
	ID         string `json:"id"`
	Attributes struct {
		AssetIdentifier       string `json:"asset_identifier"`
		AssetType             string `json:"asset_type"`
		EligibleForBounty     bool   `json:"eligible_for_bounty"`
		EligibleForSubmission bool   `json:"eligible_for_submission"`
	} `json:"attributes"`
}

type HackerOneReportSubmission struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Impact      string `json:"impact,omitempty"`
	WeaknessID  string `json:"weakness_id,omitempty"`
	Source      string `json:"source,omitempty"`
}

func NewHackerOneIntegration(baseURL, username, apiToken string) *HackerOneIntegration {
	return &HackerOneIntegration{
		client:   &http.Client{Timeout: 30 * time.Second},
		baseURL:  baseURL,
		username: username,
		apiToken: apiToken,
	}
}

func (h *HackerOneIntegration) Connect() error {
	req, err := http.NewRequest("GET", h.baseURL+"/v1/programs", nil)
	if err != nil {
		return fmt.Errorf("hackerone connect request: %w", err)
	}
	req.SetBasicAuth(h.username, h.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("hackerone connect failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hackerone API returned status %d", resp.StatusCode)
	}
	return nil
}

func (h *HackerOneIntegration) FetchPrograms() ([]HackerOneProgram, error) {
	req, err := http.NewRequest("GET", h.baseURL+"/v1/programs", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(h.username, h.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone fetch programs failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []HackerOneProgram `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("hackerone parse programs: %w", err)
	}
	return result.Data, nil
}

func (h *HackerOneIntegration) FetchProgramScope(programID string) ([]HackerOneScope, error) {
	req, err := http.NewRequest("GET", h.baseURL+"/v1/programs/"+programID+"/structured_scopes", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(h.username, h.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone fetch scope failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []HackerOneScope `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("hackerone parse scope: %w", err)
	}
	return result.Data, nil
}

func (h *HackerOneIntegration) SubmitReport(report HackerOneReportSubmission) (string, error) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "report",
			"attributes": map[string]interface{}{
				"title":                     report.Title,
				"vulnerability_information": report.Description,
				"severity_rating":           report.Severity,
			},
		},
	}

	if report.Impact != "" {
		payload["data"].(map[string]interface{})["attributes"].(map[string]interface{})["impact"] = report.Impact
	}
	if report.WeaknessID != "" {
		payload["data"].(map[string]interface{})["attributes"].(map[string]interface{})["weakness_id"] = report.WeaknessID
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", h.baseURL+"/v1/reports", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(h.username, h.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("hackerone submit report failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hackerone submit API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("hackerone submit parse: %w", err)
	}
	return result.Data.ID, nil
}

func (h *HackerOneIntegration) CheckReportStatus(reportID string) (string, error) {
	req, err := http.NewRequest("GET", h.baseURL+"/v1/reports/"+reportID, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(h.username, h.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("hackerone check status failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Data struct {
			Attributes struct {
				State string `json:"state"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("hackerone parse status: %w", err)
	}
	return result.Data.Attributes.State, nil
}

func (h *HackerOneIntegration) PostComment(reportID, comment string) error {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "activity-comment",
			"attributes": map[string]string{
				"body": comment,
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", h.baseURL+"/v1/reports/"+reportID+"/comments", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.SetBasicAuth(h.username, h.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("hackerone comment post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hackerone comment API returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (h *HackerOneIntegration) ListReports(state string) ([]HackerOneReportSubmission, error) {
	url := h.baseURL + "/v1/reports"
	if state != "" {
		url += "?filter%5B%5D=state:" + state
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(h.username, h.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone list reports failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []struct {
			Attributes struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				Severity    string `json:"severity"`
				State       string `json:"state"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("hackerone parse reports: %w", err)
	}

	reports := make([]HackerOneReportSubmission, len(result.Data))
	for i, item := range result.Data {
		reports[i] = HackerOneReportSubmission{
			Title:       item.Attributes.Title,
			Description: item.Attributes.Description,
			Severity:    item.Attributes.Severity,
		}
	}
	return reports, nil
}

func (h *HackerOneIntegration) GetTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "hackerone_fetch_programs",
			Description: "Fetch HackerOne bounty programs",
			InputSchema: ToolInputSchema{
				Type:       "object",
				Properties: map[string]ToolProperty{},
			},
		},
		{
			Name:        "hackerone_fetch_scope",
			Description: "Fetch scope for a HackerOne program",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"program_id": {Type: "string", Description: "Program ID to fetch scope for"},
				},
				Required: []string{"program_id"},
			},
		},
		{
			Name:        "hackerone_submit_report",
			Description: "Submit a vulnerability report to HackerOne",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"title":       {Type: "string", Description: "Report title"},
					"description": {Type: "string", Description: "Vulnerability description"},
					"severity":    {Type: "string", Description: "Severity rating"},
					"impact":      {Type: "string", Description: "Business impact (optional)"},
				},
				Required: []string{"title", "description", "severity"},
			},
		},
		{
			Name:        "hackerone_check_status",
			Description: "Check the status of a submitted report",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"report_id": {Type: "string", Description: "Report ID to check"},
				},
				Required: []string{"report_id"},
			},
		},
		{
			Name:        "hackerone_post_comment",
			Description: "Post a comment on a HackerOne report",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"report_id": {Type: "string", Description: "Report ID"},
					"comment":   {Type: "string", Description: "Comment text"},
				},
				Required: []string{"report_id", "comment"},
			},
		},
	}
}

func (h *HackerOneIntegration) InScope(programID, target string) bool {
	scopes, err := h.FetchProgramScope(programID)
	if err != nil {
		return false
	}

	target = strings.ToLower(target)
	for _, scope := range scopes {
		if !scope.Attributes.EligibleForSubmission {
			continue
		}
		asset := strings.ToLower(scope.Attributes.AssetIdentifier)
		if strings.Contains(target, asset) || strings.HasSuffix(target, "."+asset) {
			return true
		}
	}
	return false
}
