package ticketing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ares/engine/internal/logger"
)

func (tm *TicketManager) createLinearIssue(id string, cfg *TicketConfig, scanID, target string, finding FindingInfo) error {
	title := fmt.Sprintf("[ARES] %s - %s", finding.Severity, finding.Title)
	description := fmt.Sprintf("## Vulnerability Report\n\n**Scan ID:** %s\n**Target:** %s\n**Severity:** %s\n**CVSS:** %.1f\n**Type:** %s\n\n### Description\n%s\n\n### Evidence\n```\n%v\n```",
		scanID, target, finding.Severity, finding.CVSS, finding.Type, finding.Description, finding.Evidence)

	priority := linearPriority(finding.Severity)

	query := fmt.Sprintf(`mutation {
		issueCreate(input: {
			title: %s,
			description: %s,
			teamId: %s,
			priority: %d,
			labelIds: []
		}) {
			success
			issue {
				id
				url
				identifier
			}
		}
	}`, jsonEscaped(title), jsonEscaped(description), jsonEscaped(cfg.TeamID), priority)

	body := map[string]string{
		"query": query,
	}

	data, err := json.Marshal(body)
	if err != nil {
		logger.Error("Failed to marshal Linear request body", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return fmt.Errorf("failed to marshal Linear request: %w", err)
	}
	apiURL := strings.TrimRight(cfg.URL, "/") + "/graphql"
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		logger.Error("Failed to create Linear request", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error("Linear API call failed", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		logger.Error("Failed to read Linear response", logger.Fields{"component": "Ticketing", "provider_id": id, "error": err})
		return fmt.Errorf("failed to read Linear response: %w", err)
	}

	if resp.StatusCode >= 300 {
		err := fmt.Errorf("linear API returned %d: %s", resp.StatusCode, string(respBody))
		logger.Warn("Linear API returned error", logger.Fields{"component": "Ticketing", "provider_id": id, "status_code": resp.StatusCode, "response": string(respBody)})
		return err
	}

	var graphResp struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &graphResp); err == nil && len(graphResp.Errors) > 0 {
		msgs := make([]string, len(graphResp.Errors))
		for i, e := range graphResp.Errors {
			msgs[i] = e.Message
		}
		err := fmt.Errorf("linear GraphQL errors: %s", strings.Join(msgs, "; "))
		logger.Warn("Linear GraphQL errors", logger.Fields{"component": "Ticketing", "provider_id": id, "errors": strings.Join(msgs, "; ")})
		return err
	}

	logger.Info("Linear issue created for finding", logger.Fields{"component": "Ticketing", "provider_id": id, "finding_id": finding.ID})
	return nil
}

func linearPriority(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 4
	}
}

func jsonEscaped(s string) string {
	data, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(data)
}
