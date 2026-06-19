package spiderfoot

import (
	"fmt"
	"net/url"
	"os"
)

func (e *SpiderfootEngine) NewScan(scanName, target, moduleList string) (string, error) {
	data := url.Values{}
	data.Set("scanname", scanName)
	data.Set("target", target)
	data.Set("modulelist", moduleList)
	return e.apiPost("/scan", data)
}

func (e *SpiderfootEngine) GetScanStatus(scanID string) (string, error) {
	return e.apiGet(fmt.Sprintf("/scan/%s", scanID), url.Values{"status": {"true"}})
}

func (e *SpiderfootEngine) ListScans() (string, error) {
	return e.apiGet("/scan/", nil)
}

func (e *SpiderfootEngine) StopScan(scanID string) (string, error) {
	return e.apiGet(fmt.Sprintf("/scan/%s/stop", scanID), nil)
}

func (e *SpiderfootEngine) DeleteScan(scanID string) (string, error) {
	return e.apiGet(fmt.Sprintf("/scan/%s/delete", scanID), nil)
}

func (e *SpiderfootEngine) GetScanResults(scanID string) (string, error) {
	return e.apiGet(fmt.Sprintf("/scan/%s/results", scanID), nil)
}

func (e *SpiderfootEngine) GetScanResultsByType(scanID, resultType string) (string, error) {
	return e.apiGet(fmt.Sprintf("/scan/%s/results", scanID), url.Values{"type": {resultType}})
}

func (e *SpiderfootEngine) GetScanLog(scanID string) (string, error) {
	return e.apiGet(fmt.Sprintf("/scan/%s/log", scanID), nil)
}

func (e *SpiderfootEngine) ExportScanCSV(scanID, outputFile string) (string, error) {
	raw, err := e.apiGet(fmt.Sprintf("/scan/%s/export/csv", scanID), nil)
	if err != nil {
		return "", fmt.Errorf("ExportScanCSV failed: %w", err)
	}
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(raw), 0644); err != nil {
			return "", fmt.Errorf("failed to write CSV file: %w", err)
		}
	}
	return raw, nil
}

func (e *SpiderfootEngine) ExportScanJSON(scanID, outputFile string) (string, error) {
	raw, err := e.apiGet(fmt.Sprintf("/scan/%s/export/json", scanID), nil)
	if err != nil {
		return "", fmt.Errorf("ExportScanJSON failed: %w", err)
	}
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(raw), 0644); err != nil {
			return "", fmt.Errorf("failed to write JSON file: %w", err)
		}
	}
	return raw, nil
}
