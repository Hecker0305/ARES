package openvas

import (
	"fmt"
	"time"
)

type OpenVASArtifact struct {
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

type OpenVASForensicData struct {
	Artifacts       []OpenVASArtifact       `json:"artifacts"`
	NetworkProbes   []NetworkProbe          `json:"network_probes"`
	GMPConnections  []GMPConnection         `json:"gmp_connections"`
	FileArtifacts   []FileRecord            `json:"file_artifacts"`
}

type NetworkProbe struct {
	SourceIP      string `json:"source_ip"`
	TargetIP      string `json:"target_ip"`
	ProbeType     string `json:"probe_type"`
	PortRange     string `json:"port_range"`
	Protocol      string `json:"protocol"`
}

type GMPConnection struct {
	SourceIP      string    `json:"source_ip"`
	TargetIP      string    `json:"target_ip"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"`
	TLSEnabled    bool      `json:"tls_enabled"`
	Timestamp     time.Time `json:"timestamp"`
}

type FileRecord struct {
	Path         string `json:"path"`
	FileType     string `json:"file_type"`
	SizeBytes    int64  `json:"size_bytes"`
	Description  string `json:"description"`
}

func (e *OpenVASEngine) GetArtifacts(taskID string) (*OpenVASForensicData, error) {
	task, err := e.GetTask(taskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get task for artifacts: %w", err)
	}

	artifacts := []OpenVASArtifact{
		{
			Type:        "task_metadata",
			Source:      "openvas_gmp",
			Timestamp:   time.Now(),
			Description: "OpenVAS task metadata artifact",
			Data: map[string]interface{}{
				"task_id":  taskID,
				"name":     task.Name,
				"status":   task.Status,
				"target":   task.Target,
				"progress": task.Progress,
			},
		},
	}

	networkProbes := e.deriveNetworkProbes(task)
	gmpConnections := e.deriveGMPConnections()
	fileArtifacts := e.deriveFileArtifacts(taskID)

	return &OpenVASForensicData{
		Artifacts:      artifacts,
		NetworkProbes:  networkProbes,
		GMPConnections: gmpConnections,
		FileArtifacts:  fileArtifacts,
	}, nil
}

func (e *OpenVASEngine) deriveNetworkProbes(task *OpenVASTask) []NetworkProbe {
	return []NetworkProbe{
		{
			SourceIP:  e.config.Host,
			TargetIP:  task.Target,
			ProbeType: "openvas_port_scan",
			PortRange: "1-65535",
			Protocol:  "TCP/UDP",
		},
		{
			SourceIP:  e.config.Host,
			TargetIP:  task.Target,
			ProbeType: "openvas_service_detection",
			PortRange: "1-65535",
			Protocol:  "TCP",
		},
		{
			SourceIP:  e.config.Host,
			TargetIP:  task.Target,
			ProbeType: "openvas_banner_grab",
			PortRange: "80,443,22,21,25",
			Protocol:  "TCP",
		},
	}
}

func (e *OpenVASEngine) deriveGMPConnections() []GMPConnection {
	protocol := "SSH"
	if e.config.UseTLS {
		protocol = "TLS"
	}
	return []GMPConnection{
		{
			SourceIP:   "0.0.0.0",
			TargetIP:   e.config.Host,
			Port:       e.config.Port,
			Protocol:   protocol,
			TLSEnabled: e.config.UseTLS,
			Timestamp:  time.Now(),
		},
	}
}

func (e *OpenVASEngine) deriveFileArtifacts(taskID string) []FileRecord {
	return []FileRecord{
		{
			Path:        fmt.Sprintf("/tmp/openvas_task_%s.xml", taskID),
			FileType:    "gmp_xml_report",
			SizeBytes:   0,
			Description: "OpenVAS GMP XML report export",
		},
		{
			Path:        fmt.Sprintf("/tmp/openvas_task_%s.html", taskID),
			FileType:    "html_report",
			SizeBytes:   0,
			Description: "OpenVAS HTML report export",
		},
		{
			Path:        fmt.Sprintf("/tmp/openvas_task_%s.pdf", taskID),
			FileType:    "pdf_report",
			SizeBytes:   0,
			Description: "OpenVAS PDF report export",
		},
	}
}

func (e *OpenVASEngine) DeriveScanDetection(target string) string {
	return fmt.Sprintf(`openvas_scan_detection:
  scanner: %s
  target: %s
  detection_signatures:
    - signature: OpenVAS_TCP_SYN_Scan
      pattern: TCP_SYN_to_multiple_ports
      confidence: high
    - signature: OpenVAS_NVT_Probe
      pattern: Plugin_execution_sequence
      confidence: medium
    - signature: OpenVAS_Banner_Grab
      pattern: Service_banner_requests
      confidence: high`, e.config.Host, target)
}

func (e *OpenVASEngine) DeriveGMPTraffic(target string) string {
	return fmt.Sprintf(`gmp_protocol_traffic:
  source: %s
  target: %s
  gmp_version: %s
  characteristics:
    - xml_commands_over_%s
    - authentication_frames
    - task_management_xml
    - report_xml_payloads`, e.config.Host, target, e.config.GMPVersion, map[bool]string{true: "tls", false: "ssh"}[e.config.UseTLS])
}

func (e *OpenVASEngine) DeriveScanTiming(target string) string {
	return fmt.Sprintf(`openvas_scan_timing:
  scanner: %s
  target: %s
  estimates:
    host_discovery: 30s_per_host
    port_scanning: 5m_per_host
    service_detection: 2m_per_service
    nvt_execution: 10m_per_nvt_family
  total: dependent_on_target_count_and_nvt_families`, e.config.Host, target)
}
