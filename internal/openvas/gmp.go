package openvas

import (
	"encoding/xml"
	"fmt"
	"strings"
)

type gmpRequest struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Content string     `xml:",innerxml"`
}

func (e *OpenVASEngine) sendCommand(cmd string) (string, error) {
	e.mu.RLock()
	connected := e.connected
	e.mu.RUnlock()

	if !connected {
		return "", fmt.Errorf("openvas not connected")
	}
	return e.sendCommandRaw(cmd)
}

func (e *OpenVASEngine) CreateTarget(name string, hosts []string, ports string) (string, error) {
	hostsStr := strings.Join(hosts, ",")
	cmd := fmt.Sprintf(`<create_target>
  <name>%s</name>
  <hosts>%s</hosts>
  <port_range>%s</port_range>
</create_target>`, name, hostsStr, ports)
	return e.sendCommand(cmd)
}

func (e *OpenVASEngine) DeleteTarget(targetID string) error {
	cmd := fmt.Sprintf(`<delete_target target_id="%s"/>`, targetID)
	_, err := e.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("delete target failed: %w", err)
	}
	return nil
}

func (e *OpenVASEngine) GetTargets() ([]OpenVASTarget, error) {
	cmd := `<get_targets/>`
	resp, err := e.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("get targets failed: %w", err)
	}

	var targets []OpenVASTarget
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		if strings.Contains(line, "<id>") && strings.Contains(line, "</id>") {
			id := extractXMLValue(line, "id")
			targets = append(targets, OpenVASTarget{ID: id})
		}
	}
	return targets, nil
}

func (e *OpenVASEngine) CreateTask(name, targetID, configID string) (string, error) {
	cmd := fmt.Sprintf(`<create_task>
  <name>%s</name>
  <target>%s</target>
  <config>%s</config>
</create_task>`, name, targetID, configID)
	return e.sendCommand(cmd)
}

func (e *OpenVASEngine) StartTask(taskID string) error {
	cmd := fmt.Sprintf(`<start_task task_id="%s"/>`, taskID)
	_, err := e.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("start task failed: %w", err)
	}
	return nil
}

func (e *OpenVASEngine) StopTask(taskID string) error {
	cmd := fmt.Sprintf(`<stop_task task_id="%s"/>`, taskID)
	_, err := e.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("stop task failed: %w", err)
	}
	return nil
}

func (e *OpenVASEngine) GetTasks() ([]OpenVASTask, error) {
	cmd := `<get_tasks/>`
	resp, err := e.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("get tasks failed: %w", err)
	}

	var tasks []OpenVASTask
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		if strings.Contains(line, "<id>") && strings.Contains(line, "</id>") {
			id := extractXMLValue(line, "id")
			tasks = append(tasks, OpenVASTask{ID: id})
		}
	}
	return tasks, nil
}

func (e *OpenVASEngine) GetTask(taskID string) (*OpenVASTask, error) {
	cmd := fmt.Sprintf(`<get_tasks task_id="%s"/>`, taskID)
	resp, err := e.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("get task failed: %w", err)
	}

	task := &OpenVASTask{ID: taskID}
	if status := extractXMLValue(resp, "status"); status != "" {
		task.Status = status
	}
	if name := extractXMLValue(resp, "name"); name != "" {
		task.Name = name
	}
	return task, nil
}

func (e *OpenVASEngine) DeleteTask(taskID string) error {
	cmd := fmt.Sprintf(`<delete_task task_id="%s"/>`, taskID)
	_, err := e.sendCommand(cmd)
	if err != nil {
		return fmt.Errorf("delete task failed: %w", err)
	}
	return nil
}

func (e *OpenVASEngine) GetReport(reportID string) (*OpenVASReport, error) {
	cmd := fmt.Sprintf(`<get_reports report_id="%s"/>`, reportID)
	resp, err := e.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("get report failed: %w", err)
	}

	report := &OpenVASReport{ID: reportID}
	if count := extractXMLValue(resp, "result_count"); count != "" {
		fmt.Sscanf(count, "%d", &report.ResultCount)
	}
	return report, nil
}

func (e *OpenVASEngine) GetResults(taskID string) ([]OpenVASResult, error) {
	cmd := fmt.Sprintf(`<get_results task_id="%s"/>`, taskID)
	resp, err := e.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("get results failed: %w", err)
	}

	var results []OpenVASResult
	lines := strings.Split(resp, "\n")
	current := OpenVASResult{}
	inResult := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "<result>") {
			inResult = true
			current = OpenVASResult{}
			continue
		}
		if strings.Contains(trimmed, "</result>") {
			if inResult {
				results = append(results, current)
				inResult = false
			}
			continue
		}
		if inResult {
			if strings.Contains(trimmed, "<name>") {
				current.Name = extractXMLValue(trimmed, "name")
			}
			if strings.Contains(trimmed, "<host>") {
				current.Host = extractXMLValue(trimmed, "host")
			}
			if strings.Contains(trimmed, "<severity>") {
				current.Severity = extractXMLValue(trimmed, "severity")
			}
			if strings.Contains(trimmed, "<description>") {
				current.Description = extractXMLValue(trimmed, "description")
			}
		}
	}
	return results, nil
}

func (e *OpenVASEngine) GetNVTs() ([]OpenVASNVT, error) {
	cmd := `<get_nvts/>`
	resp, err := e.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("get nvts failed: %w", err)
	}

	var nvts []OpenVASNVT
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		if strings.Contains(line, "<name>") && strings.Contains(line, "</name>") {
			nvt := OpenVASNVT{
				ID:   extractXMLValue(line, "id"),
				Name: extractXMLValue(line, "name"),
			}
			nvts = append(nvts, nvt)
		}
	}
	return nvts, nil
}

func (e *OpenVASEngine) GetNVT(nvtID string) (*OpenVASNVT, error) {
	cmd := fmt.Sprintf(`<get_nvts nvt_oid="%s"/>`, nvtID)
	resp, err := e.sendCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("get nvt failed: %w", err)
	}

	nvt := &OpenVASNVT{
		ID:      nvtID,
		Name:    extractXMLValue(resp, "name"),
		Family:  extractXMLValue(resp, "family"),
		Summary: extractXMLValue(resp, "summary"),
	}
	return nvt, nil
}

func (e *OpenVASEngine) GetConfigs() (string, error) {
	return e.sendCommand(`<get_configs/>`)
}

func (e *OpenVASEngine) GetFeeds() (string, error) {
	return e.sendCommand(`<get_feeds/>`)
}

func (e *OpenVASEngine) FeedSync() error {
	_, err := e.sendCommand(`<sync_feed/>`)
	if err != nil {
		return fmt.Errorf("feed sync failed: %w", err)
	}
	return nil
}

func (e *OpenVASEngine) GetVersion() (string, error) {
	return e.sendCommand(`<get_version/>`)
}

func (e *OpenVASEngine) GetAggregates() (string, error) {
	return e.sendCommand(`<get_aggregates/>`)
}

func extractXMLValue(xmlStr, tag string) string {
	openTag := fmt.Sprintf("<%s>", tag)
	closeTag := fmt.Sprintf("</%s>", tag)
	start := strings.Index(xmlStr, openTag)
	if start == -1 {
		return ""
	}
	start += len(openTag)
	end := strings.Index(xmlStr[start:], closeTag)
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(xmlStr[start : start+end])
}
