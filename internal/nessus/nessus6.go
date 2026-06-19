package nessus

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (e *NessusEngine) nessus6request(method, endpoint, body string) (string, error) {
	u := fmt.Sprintf("https://%s:%d%s", e.config.Host, e.config.Port, endpoint)
	resp, err := e.request(method, u, body)
	if err != nil {
		return "", fmt.Errorf("nessus6 request failed: %w", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, resp.ContentLength)
	resp.Body.Read(buf)
	return string(buf), nil
}

func (e *NessusEngine) nessus6Login(username, password string) (string, error) {
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	u := fmt.Sprintf("https://%s:%d/login", e.config.Host, e.config.Port)
	req, err := http.NewRequest("POST", u, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("nessus6 login request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("nessus6 login failed: %w", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]), nil
}

func (e *NessusEngine) nessus6Logout() (string, error) {
	return e.nessus6request("POST", "/logout", "")
}

func (e *NessusEngine) nessus6ListScans() (string, error) {
	return e.nessus6request("GET", "/scan", "")
}

func (e *NessusEngine) nessus6GetScan(scanID int) (string, error) {
	return e.nessus6request("GET", fmt.Sprintf("/scan/%d", scanID), "")
}

func (e *NessusEngine) nessus6CreateScan(name, policyID, target string) (string, error) {
	body := fmt.Sprintf(`{"scan_name":"%s","policy_id":%s,"target":"%s"}`, name, policyID, target)
	return e.nessus6request("POST", "/scan", body)
}

func (e *NessusEngine) nessus6LaunchScan(scanID int) (string, error) {
	return e.nessus6request("POST", fmt.Sprintf("/scan/%d/launch", scanID), "")
}

func (e *NessusEngine) nessus6StopScan(scanID int) (string, error) {
	return e.nessus6request("POST", fmt.Sprintf("/scan/%d/stop", scanID), "")
}

func (e *NessusEngine) nessus6DeleteScan(scanID int) (string, error) {
	return e.nessus6request("DELETE", fmt.Sprintf("/scan/%d", scanID), "")
}

func (e *NessusEngine) nessus6ListPolicies() (string, error) {
	return e.nessus6request("GET", "/policy", "")
}

func (e *NessusEngine) nessus6GetPolicy(policyID int) (string, error) {
	return e.nessus6request("GET", fmt.Sprintf("/policy/%d", policyID), "")
}

func (e *NessusEngine) nessus6ExportScan(scanID int, format string) (string, error) {
	body := fmt.Sprintf(`{"format":"%s"}`, format)
	return e.nessus6request("POST", fmt.Sprintf("/scan/%d/export", scanID), body)
}

func (e *NessusEngine) nessus6ReportDownload(scanID, exportID int) (string, error) {
	return e.nessus6request("GET", fmt.Sprintf("/scan/%d/export/%d/download", scanID, exportID), "")
}
