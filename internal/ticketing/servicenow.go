package ticketing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ares/engine/internal/logger"
)

func (tm *TicketManager) createServiceNowTicket(id string, cfg *TicketConfig, scanID, target string, finding FindingInfo) error {
	shortDesc := fmt.Sprintf("[ARES] %s - %s", finding.Severity, finding.Title)
	desc := fmt.Sprintf("ARES Scan: %s\nTarget: %s\nScan ID: %s\n\nDescription:\n%s\n\nCVSS: %.1f\nFinding Type: %s\n\nEvidence:\n%v",
		finding.Title, target, scanID, finding.Description, finding.CVSS, finding.Type, finding.Evidence)

	body := map[string]interface{}{
		"short_description": shortDesc,
		"description":       desc,
		"category":          "security",
		"impact":            serviceNowImpact(finding.Severity),
		"urgency":           serviceNowUrgency(finding.Severity),
	}

	if cfg.Assignee != "" {
		body["assigned_to"] = cfg.Assignee
	}

	data, err := json.Marshal(body)
	if err != nil {
		logger.Error("Failed to marshal ServiceNow request body", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return fmt.Errorf("failed to marshal ServiceNow request: %w", err)
	}
	apiURL := strings.TrimRight(cfg.URL, "/") + "/api/now/table/incident"
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		logger.Error("Failed to create ServiceNow request", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if cfg.Username != "" && cfg.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error("ServiceNow API call failed", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			err := fmt.Errorf("ServiceNow API returned %d, failed to read response: %w", resp.StatusCode, err)
			logger.Warn("ServiceNow API returned error, failed to read response", logger.Fields{"component": "Ticketing", "provider_id": id, "status_code": resp.StatusCode, "error": err})
			return err
		}
		err = fmt.Errorf("ServiceNow API returned %d: %s", resp.StatusCode, string(respBody))
		logger.Warn("ServiceNow API returned error", logger.Fields{"component": "Ticketing", "provider_id": id, "status_code": resp.StatusCode, "response": string(respBody)})
		return err
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		logger.Error("Failed to read ServiceNow response", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return err
	}

	var snResp struct {
		Result struct {
			SysID     string `json:"sys_id"`
			Number    string `json:"number"`
			ShortDesc string `json:"short_description"`
			State     string `json:"state"`
			CreatedOn string `json:"sys_created_on"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &snResp); err != nil {
		logger.Warn("Failed to parse ServiceNow response", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
	} else {
		logger.Info("ServiceNow incident created", logger.Fields{
			"component":    "Ticketing",
			"provider_id":  id,
			"finding_id":   finding.ID,
			"incident_num": snResp.Result.Number,
			"sys_id":       snResp.Result.SysID,
			"incident_url": fmt.Sprintf("%s/nav_to.do?uri=incident.do?sys_id=%s", strings.TrimRight(cfg.URL, "/"), snResp.Result.SysID),
		})
	}
	return nil
}

func serviceNowImpact(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "1"
	case "high":
		return "2"
	case "medium":
		return "3"
	default:
		return "3"
	}
}

func serviceNowUrgency(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "1"
	case "high":
		return "2"
	case "medium":
		return "3"
	default:
		return "3"
	}
}
