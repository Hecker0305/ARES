package empire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func (e *EmpireEngine) Login(username, password string) (string, error) {
	body := map[string]string{"username": username, "password": password}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("login marshal error: %w", err)
	}
	resp, err := e.doRequest(http.MethodPost, "/api/admin/login", jsonBody)
	if err != nil {
		return "", fmt.Errorf("login error: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &result); err == nil {
		if t, ok := result["token"].(string); ok {
			e.token = t
		}
	}
	return resp, nil
}

func (e *EmpireEngine) Logout() (string, error) {
	return e.doRequest(http.MethodPost, "/api/admin/logout", nil)
}

func (e *EmpireEngine) doRequest(method, endpoint string, body []byte) (string, error) {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.baseURL+endpoint, reqBody)
	if err != nil {
		return "", fmt.Errorf("request creation error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request error: %w", err)
	}
	defer resp.Body.Close()
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("response read error: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return string(respData), fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respData))
	}
	return string(respData), nil
}
