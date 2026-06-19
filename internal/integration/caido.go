package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type CaidoClient struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client
}

type CaidoGraphQLRequest struct {
	Query     string      `json:"query"`
	Variables interface{} `json:"variables,omitempty"`
}

type CaidoGraphQLResponse struct {
	Data   interface{} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

type CaidoProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CaidoRequest struct {
	ID        string `json:"id"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Length    int    `json:"length"`
	MimeType  string `json:"mimeType"`
	Timestamp string `json:"timestamp"`
}

func NewCaidoClient(baseURL, apiToken string) *CaidoClient {
	return &CaidoClient{
		baseURL:  baseURL,
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *CaidoClient) query(query string, variables interface{}, result interface{}) error {
	reqBody := CaidoGraphQLRequest{
		Query:     query,
		Variables: variables,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("caido: marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/graphql", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("caido: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("caido: execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("caido: read response: %w", err)
	}

	var gqlResp CaidoGraphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return fmt.Errorf("caido: parse response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return fmt.Errorf("caido: graphql error: %s", gqlResp.Errors[0].Message)
	}

	if result != nil {
		data, _ := json.Marshal(gqlResp.Data)
		if err := json.Unmarshal(data, result); err != nil {
			return fmt.Errorf("caido: unmarshal result: %w", err)
		}
	}
	return nil
}

func (c *CaidoClient) ListProjects() ([]CaidoProject, error) {
	query := `{ projects { id name } }`
	var result struct {
		Projects []CaidoProject `json:"projects"`
	}
	if err := c.query(query, nil, &result); err != nil {
		return nil, err
	}
	return result.Projects, nil
}

func (c *CaidoClient) GetRequests(projectID string, limit int) ([]CaidoRequest, error) {
	query := `query GetRequests($projectId: ID!, $limit: Int!) {
		requests(projectId: $projectId, limit: $limit) {
			id method url host path status length mimeType timestamp
		}
	}`
	var result struct {
		Requests []CaidoRequest `json:"requests"`
	}
	if err := c.query(query, map[string]interface{}{
		"projectId": projectID,
		"limit":     limit,
	}, &result); err != nil {
		return nil, err
	}
	return result.Requests, nil
}

func (c *CaidoClient) SendToReplay(requestID string) error {
	query := `mutation SendToReplay($requestId: ID!) {
		sendToReplay(requestId: $requestId)
	}`
	return c.query(query, map[string]interface{}{
		"requestId": requestID,
	}, nil)
}

func (c *CaidoClient) ImportRequest(method, url, headers, body string) (*CaidoRequest, error) {
	query := `mutation ImportRequest($input: ImportRequestInput!) {
		importRequest(input: $input) { id method url status }
	}`
	var result struct {
		ImportRequest CaidoRequest `json:"importRequest"`
	}
	if err := c.query(query, map[string]interface{}{
		"input": map[string]string{
			"method":  method,
			"url":     url,
			"headers": headers,
			"body":    body,
		},
	}, &result); err != nil {
		return nil, err
	}
	return &result.ImportRequest, nil
}

func (c *CaidoClient) Health() error {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return fmt.Errorf("caido: health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caido: health returned status %d", resp.StatusCode)
	}
	return nil
}
