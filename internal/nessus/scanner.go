package nessus

import (
	"fmt"
	"strings"
	"time"
)

func (e *NessusEngine) RunQuickScan(target string) (*NessusScan, []NessusVulnerability, error) {
	policies, err := e.ListPolicies()
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - list policies failed: %w", err)
	}
	policyID := ""
	for _, p := range policies {
		if strings.Contains(strings.ToLower(p.Name), "basic") || strings.Contains(strings.ToLower(p.TemplateType), "basic") {
			policyID = fmt.Sprintf("%d", p.ID)
			break
		}
	}
	if policyID == "" && len(policies) > 0 {
		policyID = fmt.Sprintf("%d", policies[0].ID)
	}
	if policyID == "" {
		policyID = "731a8e52-3ea6-4a4e-96a6-8f23abf3f7b9"
	}

	scanID, err := e.CreateScan(fmt.Sprintf("Quick Scan - %s", target), policyID, target)
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - create failed: %w", err)
	}

	if err := e.LaunchScan(scanID); err != nil {
		return nil, nil, fmt.Errorf("run quick scan - launch failed: %w", err)
	}

	if err := e.WaitForScanCompletion(scanID, 30*time.Minute); err != nil {
		return nil, nil, fmt.Errorf("run quick scan - wait failed: %w", err)
	}

	scan, err := e.GetScan(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - get scan failed: %w", err)
	}

	vulns, err := e.GetScanVulnerabilities(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - get vulns failed: %w", err)
	}

	return scan, vulns, nil
}

func (e *NessusEngine) RunFullScan(target string) (*NessusScan, []NessusVulnerability, error) {
	policies, err := e.ListPolicies()
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - list policies failed: %w", err)
	}
	policyID := ""
	for _, p := range policies {
		if strings.Contains(strings.ToLower(p.Name), "full") || strings.Contains(strings.ToLower(p.TemplateType), "full") || strings.Contains(strings.ToLower(p.Name), "network") {
			policyID = fmt.Sprintf("%d", p.ID)
			break
		}
	}
	if policyID == "" && len(policies) > 0 {
		policyID = fmt.Sprintf("%d", policies[0].ID)
	}
	if policyID == "" {
		policyID = "731a8e52-3ea6-4a4e-96a6-8f23abf3f7b9"
	}

	scanID, err := e.CreateScan(fmt.Sprintf("Full Scan - %s", target), policyID, target)
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - create failed: %w", err)
	}

	if err := e.LaunchScan(scanID); err != nil {
		return nil, nil, fmt.Errorf("run full scan - launch failed: %w", err)
	}

	if err := e.WaitForScanCompletion(scanID, 2*time.Hour); err != nil {
		return nil, nil, fmt.Errorf("run full scan - wait failed: %w", err)
	}

	scan, err := e.GetScan(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - get scan failed: %w", err)
	}

	vulns, err := e.GetScanVulnerabilities(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - get vulns failed: %w", err)
	}

	return scan, vulns, nil
}

func (e *NessusEngine) RunCustomScan(target string, policyName string) (*NessusScan, []NessusVulnerability, error) {
	policies, err := e.ListPolicies()
	if err != nil {
		return nil, nil, fmt.Errorf("run custom scan - list policies failed: %w", err)
	}
	policyID := ""
	for _, p := range policies {
		if strings.EqualFold(p.Name, policyName) {
			policyID = fmt.Sprintf("%d", p.ID)
			break
		}
	}
	if policyID == "" {
		return nil, nil, fmt.Errorf("run custom scan - policy %s not found", policyName)
	}

	scanID, err := e.CreateScan(fmt.Sprintf("Custom Scan - %s", target), policyID, target)
	if err != nil {
		return nil, nil, fmt.Errorf("run custom scan - create failed: %w", err)
	}

	if err := e.LaunchScan(scanID); err != nil {
		return nil, nil, fmt.Errorf("run custom scan - launch failed: %w", err)
	}

	if err := e.WaitForScanCompletion(scanID, 2*time.Hour); err != nil {
		return nil, nil, fmt.Errorf("run custom scan - wait failed: %w", err)
	}

	scan, err := e.GetScan(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run custom scan - get scan failed: %w", err)
	}

	vulns, err := e.GetScanVulnerabilities(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run custom scan - get vulns failed: %w", err)
	}

	return scan, vulns, nil
}

func (e *NessusEngine) RunScanWithCredentials(target string, creds map[string]string) (*NessusScan, []NessusVulnerability, error) {
	policies, err := e.ListPolicies()
	if err != nil {
		return nil, nil, fmt.Errorf("run credentialed scan - list policies failed: %w", err)
	}
	policyID := ""
	if len(policies) > 0 {
		policyID = fmt.Sprintf("%d", policies[0].ID)
	}
	if policyID == "" {
		policyID = "731a8e52-3ea6-4a4e-96a6-8f23abf3f7b9"
	}

	credBody := `"credentials":{"host":{`
	first := true
	for k, v := range creds {
		if !first {
			credBody += ","
		}
		credBody += fmt.Sprintf(`"%s":"%s"`, k, v)
		first = false
	}
	credBody += `}}`

	body := fmt.Sprintf(`{"uuid":"%s","settings":{"name":"Credentialed Scan - %s","text_targets":"%s",%s}}`, policyID, target, target, credBody)
	resp, err := e.request("POST", e.apiURL("/scans"), body)
	if err != nil {
		return nil, nil, fmt.Errorf("run credentialed scan - create failed: %w", err)
	}
	resp.Body.Close()

	scanID, err := e.CreateScan(fmt.Sprintf("Credentialed Scan - %s", target), policyID, target)
	if err != nil {
		return nil, nil, fmt.Errorf("run credentialed scan - create failed: %w", err)
	}

	if err := e.LaunchScan(scanID); err != nil {
		return nil, nil, fmt.Errorf("run credentialed scan - launch failed: %w", err)
	}

	if err := e.WaitForScanCompletion(scanID, 2*time.Hour); err != nil {
		return nil, nil, fmt.Errorf("run credentialed scan - wait failed: %w", err)
	}

	scan, err := e.GetScan(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run credentialed scan - get scan failed: %w", err)
	}

	vulns, err := e.GetScanVulnerabilities(scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("run credentialed scan - get vulns failed: %w", err)
	}

	return scan, vulns, nil
}

func (e *NessusEngine) WaitForScanCompletion(scanID int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("scan %d did not complete within %v", scanID, timeout)
		}

		scan, err := e.GetScan(scanID)
		if err != nil {
			return fmt.Errorf("wait for scan completion - get scan failed: %w", err)
		}

		switch scan.Status {
		case "completed", "imported":
			return nil
		case "canceled":
			return fmt.Errorf("scan %d was canceled", scanID)
		case "running", "processing":
			time.Sleep(10 * time.Second)
		default:
			time.Sleep(10 * time.Second)
		}
	}
}

func (e *NessusEngine) GenerateReport(scanID int, outputFile string, format string) error {
	exportID, err := e.ExportScan(scanID, format)
	if err != nil {
		return fmt.Errorf("generate report - export failed: %w", err)
	}

	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		err := e.DownloadExport(scanID, exportID, outputFile)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("generate report - download failed after retries")
}

func (e *NessusEngine) CompareScans(scanID1, scanID2 int) (string, error) {
	vulns1, err := e.GetScanVulnerabilities(scanID1)
	if err != nil {
		return "", fmt.Errorf("compare scans - get vulns for scan %d failed: %w", scanID1, err)
	}
	vulns2, err := e.GetScanVulnerabilities(scanID2)
	if err != nil {
		return "", fmt.Errorf("compare scans - get vulns for scan %d failed: %w", scanID2, err)
	}

	pluginMap1 := make(map[int]bool)
	for _, v := range vulns1 {
		pluginMap1[v.PluginID] = true
	}

	var onlyInScan1, onlyInScan2 []string
	for _, v := range vulns1 {
		if !pluginMap1[v.PluginID] {
			onlyInScan1 = append(onlyInScan1, fmt.Sprintf("%s (%s)", v.PluginName, v.Host))
		}
	}
	for _, v := range vulns2 {
		if !pluginMap1[v.PluginID] {
			onlyInScan2 = append(onlyInScan2, fmt.Sprintf("%s (%s)", v.PluginName, v.Host))
		}
		pluginMap1[v.PluginID] = false
	}

	result := fmt.Sprintf(`scan_comparison:
  scan_1: %d (findings: %d)
  scan_2: %d (findings: %d)
  new_in_scan_1: %d
  new_in_scan_2: %d
  unique_to_scan_1:
`, scanID1, len(vulns1), scanID2, len(vulns2), len(onlyInScan1), len(onlyInScan2))
	for _, v := range onlyInScan1 {
		result += fmt.Sprintf("    - %s\n", v)
	}
	result += "  unique_to_scan_2:\n"
	for _, v := range onlyInScan2 {
		result += fmt.Sprintf("    - %s\n", v)
	}
	return result, nil
}

func (e *NessusEngine) GetFindingsFromScan(scanID int) (string, error) {
	vulns, err := e.GetScanVulnerabilities(scanID)
	if err != nil {
		return "", fmt.Errorf("get findings from scan failed: %w", err)
	}

	result := fmt.Sprintf("findings_for_scan_%d:\n", scanID)
	result += "  total_findings: %d\n"
	for _, v := range vulns {
		result += fmt.Sprintf("  - plugin_id: %d\n", v.PluginID)
		result += fmt.Sprintf("    plugin_name: %s\n", v.PluginName)
		result += fmt.Sprintf("    severity: %s\n", v.Severity)
		result += fmt.Sprintf("    host: %s\n", v.Host)
		result += fmt.Sprintf("    port: %d\n", v.Port)
		result += fmt.Sprintf("    protocol: %s\n", v.Protocol)
		result += fmt.Sprintf("    cvss3_score: %.1f\n", v.CVSS3Score)
		result += fmt.Sprintf("    cvss2_score: %.1f\n", v.CVSS2Score)
		result += fmt.Sprintf("    plugin_family: %s\n", v.PluginFamily)
		result += fmt.Sprintf("    synopsis: %s\n", v.Synopsis)
		result += fmt.Sprintf("    solution: %s\n", v.Solution)
	}
	return result, nil
}

func (e *NessusEngine) GetCriticalFindings(scanID int) ([]NessusVulnerability, error) {
	vulns, err := e.GetScanVulnerabilities(scanID)
	if err != nil {
		return nil, fmt.Errorf("get critical findings failed: %w", err)
	}

	var critical []NessusVulnerability
	for _, v := range vulns {
		if strings.EqualFold(v.Severity, "critical") {
			critical = append(critical, v)
		}
	}
	return critical, nil
}

func (e *NessusEngine) GetFindingsByPluginFamily(scanID int, family string) ([]NessusVulnerability, error) {
	vulns, err := e.GetScanVulnerabilities(scanID)
	if err != nil {
		return nil, fmt.Errorf("get findings by plugin family failed: %w", err)
	}

	var filtered []NessusVulnerability
	for _, v := range vulns {
		if strings.EqualFold(v.PluginFamily, family) {
			filtered = append(filtered, v)
		}
	}
	return filtered, nil
}
