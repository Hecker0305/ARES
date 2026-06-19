package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type CaidoIntegration struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

type CaidoRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type CaidoFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Endpoint    string `json:"endpoint"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Request     string `json:"request,omitempty"`
	Response    string `json:"response,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type CaidoGraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type CaidoGraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

func NewCaidoIntegration(baseURL, apiKey string) *CaidoIntegration {
	return &CaidoIntegration{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

func (c *CaidoIntegration) Connect() error {
	query := CaidoGraphQLRequest{
		Query: `{ __typename }`,
	}
	resp, err := c.graphQL(query)
	if err != nil {
		return fmt.Errorf("caido connect failed: %w", err)
	}
	if len(resp.Errors) > 0 {
		return fmt.Errorf("caido connection error: %s", resp.Errors[0].Message)
	}
	return nil
}

func (c *CaidoIntegration) graphQL(req CaidoGraphQLRequest) (*CaidoGraphQLResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", c.baseURL+"/graphql", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("caido graphql request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var gqlResp CaidoGraphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return nil, fmt.Errorf("caido graphql parse: %w", err)
	}
	return &gqlResp, nil
}

func (c *CaidoIntegration) ImportRequest(caidoReq CaidoRequest) (string, error) {
	query := CaidoGraphQLRequest{
		Query: `mutation ImportRequest($input: RequestInput!) {
			importRequest(input: $input) { id }
		}`,
		Variables: map[string]interface{}{
			"input": caidoReq,
		},
	}

	resp, err := c.graphQL(query)
	if err != nil {
		return "", err
	}
	if len(resp.Errors) > 0 {
		return "", fmt.Errorf("caido import request error: %s", resp.Errors[0].Message)
	}

	var result struct {
		ImportRequest struct {
			ID string `json:"id"`
		} `json:"importRequest"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return "", fmt.Errorf("caido parse import response: %w", err)
	}
	return result.ImportRequest.ID, nil
}

func (c *CaidoIntegration) ExportFindings() ([]CaidoFinding, error) {
	query := CaidoGraphQLRequest{
		Query: `{
			findings {
				id title severity endpoint type description
			}
		}`,
	}

	resp, err := c.graphQL(query)
	if err != nil {
		return nil, err
	}
	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("caido export findings error: %s", resp.Errors[0].Message)
	}

	var result struct {
		Findings []CaidoFinding `json:"findings"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("caido parse findings: %w", err)
	}
	return result.Findings, nil
}

func (c *CaidoIntegration) ExportFindingsBySeverity(severity string) ([]CaidoFinding, error) {
	query := CaidoGraphQLRequest{
		Query: `query GetFindings($severity: String) {
			findings(severity: $severity) {
				id title severity endpoint type description
			}
		}`,
		Variables: map[string]interface{}{
			"severity": severity,
		},
	}

	resp, err := c.graphQL(query)
	if err != nil {
		return nil, err
	}
	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("caido export findings error: %s", resp.Errors[0].Message)
	}

	var result struct {
		Findings []CaidoFinding `json:"findings"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("caido parse findings: %w", err)
	}
	return result.Findings, nil
}

func (c *CaidoIntegration) CreateNote(id, note string) error {
	query := CaidoGraphQLRequest{
		Query: `mutation CreateNote($input: NoteInput!) {
			createNote(input: $input) { id }
		}`,
		Variables: map[string]interface{}{
			"input": map[string]interface{}{
				"findingId": id,
				"content":   note,
			},
		},
	}

	resp, err := c.graphQL(query)
	if err != nil {
		return err
	}
	if len(resp.Errors) > 0 {
		return fmt.Errorf("caido create note error: %s", resp.Errors[0].Message)
	}
	return nil
}

func (c *CaidoIntegration) GetProjects() ([]string, error) {
	query := CaidoGraphQLRequest{
		Query: `{ projects { id name } }`,
	}

	resp, err := c.graphQL(query)
	if err != nil {
		return nil, err
	}

	var result struct {
		Projects []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("caido parse projects: %w", err)
	}

	names := make([]string, len(result.Projects))
	for i, p := range result.Projects {
		names[i] = p.Name
	}
	return names, nil
}

func (c *CaidoIntegration) GetTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "caido_import_request",
			Description: "Import an HTTP request into Caido",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"method": {Type: "string", Description: "HTTP method"},
					"url":    {Type: "string", Description: "Request URL"},
					"body":   {Type: "string", Description: "Request body (optional)"},
				},
				Required: []string{"method", "url"},
			},
		},
		{
			Name:        "caido_export_findings",
			Description: "Export findings from Caido",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"severity": {Type: "string", Description: "Filter by severity (optional)"},
				},
			},
		},
	}
}
