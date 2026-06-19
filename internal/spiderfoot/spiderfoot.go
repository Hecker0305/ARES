package spiderfoot

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
)

type SpiderfootEngine struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

func NewSpiderfootEngine(baseURL, apiKey string) *SpiderfootEngine {
	return &SpiderfootEngine{
		client:  &http.Client{},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

func (e *SpiderfootEngine) apiGet(path string, params url.Values) (string, error) {
	u := fmt.Sprintf("%s%s", e.baseURL, path)
	if params != nil {
		u = fmt.Sprintf("%s?%s", u, params.Encode())
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("API-Key", e.apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func (e *SpiderfootEngine) apiPost(path string, data url.Values) (string, error) {
	u := fmt.Sprintf("%s%s", e.baseURL, path)
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if e.apiKey != "" {
		req.Header.Set("API-Key", e.apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func runCLI(args []string) (string, error) {
	cmd := exec.Command("spiderfoot", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("spiderfoot CLI failed: %w\nstderr: %s", err, stderr.String())
	}
	return stdout.String(), nil
}
