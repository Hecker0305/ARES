package openvas

import (
	"fmt"
	"strings"
	"time"
)

func (e *OpenVASEngine) RunQuickScan(target string) (*OpenVASTask, []OpenVASResult, error) {
	targetID, err := e.CreateTarget(fmt.Sprintf("quick-target-%s", target), []string{target}, "80,443,22,21,25,3306,3389")
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - create target failed: %w", err)
	}

	configs, err := e.GetConfigs()
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - get configs failed: %w", err)
	}
	configID := extractXMLValue(configs, "id")
	if configID == "" {
		configID = "daba56c8-73ec-11df-a475-002264764cea"
	}

	taskID, err := e.CreateTask(fmt.Sprintf("Quick Scan - %s", target), targetID, configID)
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - create task failed: %w", err)
	}

	if err := e.StartTask(taskID); err != nil {
		return nil, nil, fmt.Errorf("run quick scan - start task failed: %w", err)
	}

	if err := e.WaitForTaskCompletion(taskID, 30*time.Minute); err != nil {
		return nil, nil, fmt.Errorf("run quick scan - wait failed: %w", err)
	}

	task, err := e.GetTask(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - get task failed: %w", err)
	}

	results, err := e.GetResults(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run quick scan - get results failed: %w", err)
	}

	return task, results, nil
}

func (e *OpenVASEngine) RunFullScan(target string) (*OpenVASTask, []OpenVASResult, error) {
	targetID, err := e.CreateTarget(fmt.Sprintf("full-target-%s", target), []string{target}, "1-65535")
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - create target failed: %w", err)
	}

	configs, err := e.GetConfigs()
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - get configs failed: %w", err)
	}
	configID := extractXMLValue(configs, "id")
	if configID == "" {
		configID = "daba56c8-73ec-11df-a475-002264764cea"
	}

	taskID, err := e.CreateTask(fmt.Sprintf("Full Scan - %s", target), targetID, configID)
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - create task failed: %w", err)
	}

	if err := e.StartTask(taskID); err != nil {
		return nil, nil, fmt.Errorf("run full scan - start task failed: %w", err)
	}

	if err := e.WaitForTaskCompletion(taskID, 2*time.Hour); err != nil {
		return nil, nil, fmt.Errorf("run full scan - wait failed: %w", err)
	}

	task, err := e.GetTask(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - get task failed: %w", err)
	}

	results, err := e.GetResults(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run full scan - get results failed: %w", err)
	}

	return task, results, nil
}

func (e *OpenVASEngine) RunComprehensiveScan(target string) (*OpenVASTask, []OpenVASResult, error) {
	targetID, err := e.CreateTarget(fmt.Sprintf("comprehensive-target-%s", target), []string{target}, "1-65535,T:1-65535,U:1-65535")
	if err != nil {
		return nil, nil, fmt.Errorf("run comprehensive scan - create target failed: %w", err)
	}

	configs, err := e.GetConfigs()
	if err != nil {
		return nil, nil, fmt.Errorf("run comprehensive scan - get configs failed: %w", err)
	}
	configID := extractXMLValue(configs, "id")
	if configID == "" {
		configID = "daba56c8-73ec-11df-a475-002264764cea"
	}

	taskID, err := e.CreateTask(fmt.Sprintf("Comprehensive Scan - %s", target), targetID, configID)
	if err != nil {
		return nil, nil, fmt.Errorf("run comprehensive scan - create task failed: %w", err)
	}

	if err := e.StartTask(taskID); err != nil {
		return nil, nil, fmt.Errorf("run comprehensive scan - start task failed: %w", err)
	}

	if err := e.WaitForTaskCompletion(taskID, 4*time.Hour); err != nil {
		return nil, nil, fmt.Errorf("run comprehensive scan - wait failed: %w", err)
	}

	task, err := e.GetTask(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run comprehensive scan - get task failed: %w", err)
	}

	results, err := e.GetResults(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run comprehensive scan - get results failed: %w", err)
	}

	return task, results, nil
}

func (e *OpenVASEngine) RunScanWithConfig(target, configID string) (*OpenVASTask, []OpenVASResult, error) {
	targetID, err := e.CreateTarget(fmt.Sprintf("custom-target-%s", target), []string{target}, "1-65535")
	if err != nil {
		return nil, nil, fmt.Errorf("run scan with config - create target failed: %w", err)
	}

	taskID, err := e.CreateTask(fmt.Sprintf("Custom Config Scan - %s", target), targetID, configID)
	if err != nil {
		return nil, nil, fmt.Errorf("run scan with config - create task failed: %w", err)
	}

	if err := e.StartTask(taskID); err != nil {
		return nil, nil, fmt.Errorf("run scan with config - start task failed: %w", err)
	}

	if err := e.WaitForTaskCompletion(taskID, 2*time.Hour); err != nil {
		return nil, nil, fmt.Errorf("run scan with config - wait failed: %w", err)
	}

	task, err := e.GetTask(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run scan with config - get task failed: %w", err)
	}

	results, err := e.GetResults(taskID)
	if err != nil {
		return nil, nil, fmt.Errorf("run scan with config - get results failed: %w", err)
	}

	return task, results, nil
}

func (e *OpenVASEngine) WaitForTaskCompletion(taskID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("task %s did not complete within %v", taskID, timeout)
		}

		task, err := e.GetTask(taskID)
		if err != nil {
			return fmt.Errorf("wait for task completion - get task failed: %w", err)
		}

		switch task.Status {
		case "Done", "Stopped":
			return nil
		case "Running", "Requested", "Queued":
			time.Sleep(10 * time.Second)
		default:
			time.Sleep(10 * time.Second)
		}
	}
}

func (e *OpenVASEngine) GenerateReport(taskID, outputFile string) (string, error) {
	task, err := e.GetTask(taskID)
	if err != nil {
		return "", fmt.Errorf("generate report - get task failed: %w", err)
	}

	if task.ReportID == "" {
		return "", fmt.Errorf("generate report - task %s has no report", taskID)
	}

	report, err := e.GetReport(task.ReportID)
	if err != nil {
		return "", fmt.Errorf("generate report - get report failed: %w", err)
	}

	output := fmt.Sprintf("report_%s:\n", task.ReportID)
	output += fmt.Sprintf("  task_id: %s\n", taskID)
	output += fmt.Sprintf("  result_count: %d\n", report.ResultCount)
	if outputFile != "" {
		output += fmt.Sprintf("  output_file: %s\n", outputFile)
	}
	return output, nil
}

func (e *OpenVASEngine) GetFindings(taskID string) (string, error) {
	results, err := e.GetResults(taskID)
	if err != nil {
		return "", fmt.Errorf("get findings failed: %w", err)
	}

	output := fmt.Sprintf("findings_for_task_%s:\n", taskID)
	output += fmt.Sprintf("  total_findings: %d\n", len(results))
	for _, r := range results {
		output += fmt.Sprintf("  - result_id: %s\n", r.ID)
		output += fmt.Sprintf("    name: %s\n", r.Name)
		output += fmt.Sprintf("    severity: %s\n", r.Severity)
		output += fmt.Sprintf("    host: %s\n", r.Host)
		output += fmt.Sprintf("    port: %s\n", r.Port)
		output += fmt.Sprintf("    cvss: %.1f\n", r.CVSS)
		output += fmt.Sprintf("    nvt: %s\n", r.NVTName)
		output += fmt.Sprintf("    solution: %s\n", r.Solution)
	}
	return output, nil
}

func (e *OpenVASEngine) GetCriticalFindings(taskID string) ([]OpenVASResult, error) {
	results, err := e.GetResults(taskID)
	if err != nil {
		return nil, fmt.Errorf("get critical findings failed: %w", err)
	}

	var critical []OpenVASResult
	for _, r := range results {
		if r.CVSS >= 9.0 || strings.EqualFold(r.Severity, "critical") {
			critical = append(critical, r)
		}
	}
	return critical, nil
}

func (e *OpenVASEngine) GetHighFindings(taskID string) ([]OpenVASResult, error) {
	results, err := e.GetResults(taskID)
	if err != nil {
		return nil, fmt.Errorf("get high findings failed: %w", err)
	}

	var high []OpenVASResult
	for _, r := range results {
		if r.CVSS >= 7.0 && r.CVSS <= 8.9 || strings.EqualFold(r.Severity, "high") {
			high = append(high, r)
		}
	}
	return high, nil
}

func (e *OpenVASEngine) GetResultsByHost(taskID string) (string, error) {
	results, err := e.GetResults(taskID)
	if err != nil {
		return "", fmt.Errorf("get results by host failed: %w", err)
	}

	hostMap := make(map[string][]OpenVASResult)
	for _, r := range results {
		hostMap[r.Host] = append(hostMap[r.Host], r)
	}

	output := fmt.Sprintf("results_by_host_for_task_%s:\n", taskID)
	for host, hostResults := range hostMap {
		output += fmt.Sprintf("  host: %s\n", host)
		output += fmt.Sprintf("    findings: %d\n", len(hostResults))
		for _, r := range hostResults {
			output += fmt.Sprintf("    - %s (severity: %s, cvss: %.1f)\n", r.Name, r.Severity, r.CVSS)
		}
	}
	return output, nil
}
