package nessus

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func (e *NessusEngine) ListScans() ([]NessusScan, error) {
	resp, err := e.request("GET", e.apiURL("/scans"), "")
	if err != nil {
		return nil, fmt.Errorf("list scans failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Scans []NessusScan `json:"scans"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scans list: %w", err)
	}
	return result.Scans, nil
}

func (e *NessusEngine) GetScan(scanID int) (*NessusScan, error) {
	resp, err := e.request("GET", e.apiURL(fmt.Sprintf("/scans/%d", scanID)), "")
	if err != nil {
		return nil, fmt.Errorf("get scan failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Scan NessusScan `json:"scan"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scan: %w", err)
	}
	return &result.Scan, nil
}

func (e *NessusEngine) CreateScan(name, policyID, target string) (int, error) {
	body := fmt.Sprintf(`{"uuid":"%s","settings":{"name":"%s","text_targets":"%s"}}`, policyID, name, target)
	resp, err := e.request("POST", e.apiURL("/scans"), body)
	if err != nil {
		return 0, fmt.Errorf("create scan failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Scan struct {
			ID int `json:"id"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, fmt.Errorf("failed to parse create scan response: %w", err)
	}
	return result.Scan.ID, nil
}

func (e *NessusEngine) CreateScanWithFolder(name, policyID, target string, folderID int) (int, error) {
	body := fmt.Sprintf(`{"uuid":"%s","settings":{"name":"%s","text_targets":"%s","folder_id":%d}}`, policyID, name, target, folderID)
	resp, err := e.request("POST", e.apiURL("/scans"), body)
	if err != nil {
		return 0, fmt.Errorf("create scan with folder failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Scan struct {
			ID int `json:"id"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, fmt.Errorf("failed to parse create scan response: %w", err)
	}
	return result.Scan.ID, nil
}

func (e *NessusEngine) LaunchScan(scanID int) error {
	resp, err := e.request("POST", e.apiURL(fmt.Sprintf("/scans/%d/launch", scanID)), "")
	if err != nil {
		return fmt.Errorf("launch scan failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("launch scan returned status %d", resp.StatusCode)
	}
	return nil
}

func (e *NessusEngine) PauseScan(scanID int) error {
	resp, err := e.request("POST", e.apiURL(fmt.Sprintf("/scans/%d/pause", scanID)), "")
	if err != nil {
		return fmt.Errorf("pause scan failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pause scan returned status %d", resp.StatusCode)
	}
	return nil
}

func (e *NessusEngine) ResumeScan(scanID int) error {
	resp, err := e.request("POST", e.apiURL(fmt.Sprintf("/scans/%d/resume", scanID)), "")
	if err != nil {
		return fmt.Errorf("resume scan failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("resume scan returned status %d", resp.StatusCode)
	}
	return nil
}

func (e *NessusEngine) StopScan(scanID int) error {
	resp, err := e.request("POST", e.apiURL(fmt.Sprintf("/scans/%d/stop", scanID)), "")
	if err != nil {
		return fmt.Errorf("stop scan failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stop scan returned status %d", resp.StatusCode)
	}
	return nil
}

func (e *NessusEngine) ExportScan(scanID int, format string) (int, error) {
	body := fmt.Sprintf(`{"format":"%s"}`, format)
	resp, err := e.request("POST", e.apiURL(fmt.Sprintf("/scans/%d/export", scanID)), body)
	if err != nil {
		return 0, fmt.Errorf("export scan failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		ExportID int `json:"file"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, fmt.Errorf("failed to parse export response: %w", err)
	}
	return result.ExportID, nil
}

func (e *NessusEngine) DownloadExport(scanID, exportID int, outputPath string) error {
	resp, err := e.request("GET", e.apiURL(fmt.Sprintf("/scans/%d/export/%d/download", scanID, exportID)), "")
	if err != nil {
		return fmt.Errorf("download export failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download export returned status %d", resp.StatusCode)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write export to file: %w", err)
	}
	return nil
}

func (e *NessusEngine) DeleteScan(scanID int) error {
	resp, err := e.request("DELETE", e.apiURL(fmt.Sprintf("/scans/%d", scanID)), "")
	if err != nil {
		return fmt.Errorf("delete scan failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete scan returned status %d", resp.StatusCode)
	}
	return nil
}

func (e *NessusEngine) ListPolicies() ([]NessusPolicy, error) {
	resp, err := e.request("GET", e.apiURL("/policies"), "")
	if err != nil {
		return nil, fmt.Errorf("list policies failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Policies []NessusPolicy `json:"policies"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse policies: %w", err)
	}
	return result.Policies, nil
}

func (e *NessusEngine) GetPolicy(policyID int) (*NessusPolicy, error) {
	resp, err := e.request("GET", e.apiURL(fmt.Sprintf("/policies/%d", policyID)), "")
	if err != nil {
		return nil, fmt.Errorf("get policy failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Policy NessusPolicy `json:"policy"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}
	return &result.Policy, nil
}

func (e *NessusEngine) ListFolders() ([]NessusFolder, error) {
	resp, err := e.request("GET", e.apiURL("/folders"), "")
	if err != nil {
		return nil, fmt.Errorf("list folders failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Folders []NessusFolder `json:"folders"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse folders: %w", err)
	}
	return result.Folders, nil
}

func (e *NessusEngine) GetScanVulnerabilities(scanID int) ([]NessusVulnerability, error) {
	resp, err := e.request("GET", e.apiURL(fmt.Sprintf("/scans/%d/vulnerabilities", scanID)), "")
	if err != nil {
		return nil, fmt.Errorf("get scan vulnerabilities failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Vulnerabilities []NessusVulnerability `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse vulnerabilities: %w", err)
	}
	return result.Vulnerabilities, nil
}

func (e *NessusEngine) GetHostVulnerabilities(scanID int, hostID int) ([]NessusVulnerability, error) {
	resp, err := e.request("GET", e.apiURL(fmt.Sprintf("/scans/%d/hosts/%d", scanID, hostID)), "")
	if err != nil {
		return nil, fmt.Errorf("get host vulnerabilities failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Vulnerabilities []NessusVulnerability `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse host vulnerabilities: %w", err)
	}
	return result.Vulnerabilities, nil
}

func (e *NessusEngine) GetPluginInfo(pluginID int) (map[string]interface{}, error) {
	resp, err := e.request("GET", e.apiURL(fmt.Sprintf("/plugins/plugin/%d", pluginID)), "")
	if err != nil {
		return nil, fmt.Errorf("get plugin info failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse plugin info: %w", err)
	}
	return result, nil
}

func (e *NessusEngine) ListTemplates() (string, error) {
	resp, err := e.request("GET", e.apiURL("/editor/scan/templates"), "")
	if err != nil {
		return "", fmt.Errorf("list templates failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	return string(raw), nil
}

func (e *NessusEngine) GetScanHistory(scanID int) (string, error) {
	resp, err := e.request("GET", e.apiURL(fmt.Sprintf("/scans/%d/history", scanID)), "")
	if err != nil {
		return "", fmt.Errorf("get scan history failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	return string(raw), nil
}

func (e *NessusEngine) NetworkHealthCheck() (string, error) {
	resp, err := e.request("GET", e.apiURL("/server/health"), "")
	if err != nil {
		return "", fmt.Errorf("network health check failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	return string(raw), nil
}
