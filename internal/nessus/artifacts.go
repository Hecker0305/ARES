package nessus

import (
	"fmt"
	"time"
)

type NessusArtifact struct {
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

type NessusForensicData struct {
	Artifacts       []NessusArtifact `json:"artifacts"`
	NetworkPatterns []NetworkPattern `json:"network_patterns"`
	EventLogs       []EventLog       `json:"event_logs"`
	FileArtifacts   []FileArtifact   `json:"file_artifacts"`
	DetectionSig    []DetectionSig   `json:"detection_signatures"`
}

type NetworkPattern struct {
	SourceIP      string `json:"source_ip"`
	TargetIP      string `json:"target_ip"`
	PortRange     string `json:"port_range"`
	Protocol      string `json:"protocol"`
	PacketRate    int    `json:"packet_rate"`
	PatternType   string `json:"pattern_type"`
}

type EventLog struct {
	Source      string    `json:"source"`
	EventID     int       `json:"event_id"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
}

type FileArtifact struct {
	Path         string `json:"path"`
	FileType     string `json:"file_type"`
	SizeBytes    int64  `json:"size_bytes"`
	Description  string `json:"description"`
}

type DetectionSig struct {
	Name        string `json:"name"`
	SignatureID string `json:"signature_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func (e *NessusEngine) GetArtifacts(scanID int) (*NessusForensicData, error) {
	scan, err := e.GetScan(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan for artifacts: %w", err)
	}

	artifacts := []NessusArtifact{
		{
			Type:        "scan_metadata",
			Source:      "nessus_api",
			Timestamp:   scan.StartTime,
			Description: "Nessus scan metadata artifact",
			Data: map[string]interface{}{
				"scan_id":   scan.ID,
				"scan_name": scan.Name,
				"status":    scan.Status,
				"target":    scan.Target,
				"folder_id": scan.FolderID,
				"policy_id": scan.PolicyID,
			},
		},
	}

	networkPatterns := e.deriveNetworkPatterns(scan)
	eventLogs := e.deriveEventLogs()
	fileArtifacts := e.deriveFileArtifacts(scan)
	detectionSigs := e.deriveDetectionSignatures()

	return &NessusForensicData{
		Artifacts:       artifacts,
		NetworkPatterns: networkPatterns,
		EventLogs:       eventLogs,
		FileArtifacts:   fileArtifacts,
		DetectionSig:    detectionSigs,
	}, nil
}

func (e *NessusEngine) deriveNetworkPatterns(scan *NessusScan) []NetworkPattern {
	return []NetworkPattern{
		{
			SourceIP:    e.config.Host,
			TargetIP:    scan.Target,
			PortRange:   "1-65535",
			Protocol:    "TCP/UDP",
			PacketRate:  1000,
			PatternType: "nessus_port_scan",
		},
	}
}

func (e *NessusEngine) deriveEventLogs() []EventLog {
	return []EventLog{
		{
			Source:      "NessusAgent",
			EventID:     4688,
			Description: "Nessus agent process creation detected",
			Timestamp:   time.Now(),
			Severity:    "information",
		},
		{
			Source:      "NessusAgent",
			EventID:     5156,
			Description: "Nessus network connection detected",
			Timestamp:   time.Now(),
			Severity:    "information",
		},
	}
}

func (e *NessusEngine) deriveFileArtifacts(scan *NessusScan) []FileArtifact {
	return []FileArtifact{
		{
			Path:        fmt.Sprintf("/tmp/nessus_scan_%d.nessus", scan.ID),
			FileType:    "nessus_xml",
			SizeBytes:   0,
			Description: "Nessus scan export file in native format",
		},
		{
			Path:        fmt.Sprintf("/tmp/nessus_scan_%d.csv", scan.ID),
			FileType:    "csv",
			SizeBytes:   0,
			Description: "Nessus scan export in CSV format",
		},
		{
			Path:        fmt.Sprintf("/tmp/nessus_scan_%d.html", scan.ID),
			FileType:    "html",
			SizeBytes:   0,
			Description: "Nessus scan export in HTML report format",
		},
	}
}

func (e *NessusEngine) deriveDetectionSignatures() []DetectionSig {
	return []DetectionSig{
		{
			Name:        "Nessus Port Scan",
			SignatureID: "NESSUS-PORT-SCAN",
			Description: "Detects Nessus port scanning activity via TCP SYN packets to multiple ports",
			Severity:    "medium",
		},
		{
			Name:        "Nessus Service Detection",
			SignatureID: "NESSUS-SERVICE-DETECT",
			Description: "Detects Nessus service fingerprinting probes",
			Severity:    "low",
		},
		{
			Name:        "Nessus Plugin Execution",
			SignatureID: "NESSUS-PLUGIN-EXEC",
			Description: "Detects Nessus vulnerability plugin execution against target hosts",
			Severity:    "high",
		},
	}
}

func (e *NessusEngine) DeriveNetworkTrafficPatterns(targetIP string) string {
	return fmt.Sprintf(`nessus_scan_traffic_pattern:
  source: %s
  target: %s
  protocol: TCP
  ports: 1-65535
  characteristics:
    - sequential_port_scan
    - service_banner_grab
    - plugin_probe_requests
  rate: 1000_packets_per_second
  duration: estimated_scan_time`, e.config.Host, targetIP)
}

func (e *NessusEngine) GetScanTiming(targetIP string) string {
	return fmt.Sprintf(`nessus_scan_timing_analysis:
  scanner: %s
  target: %s
  estimated_host_discovery: 30s_per_host
  estimated_port_scan: 60s_per_host
  estimated_service_detect: 30s_per_service
  estimated_plugin_execution: 120s_per_plugin
  total_estimate: dependent_on_target_count_and_plugins`, e.config.Host, targetIP)
}

func (e *NessusEngine) GetTargetEnumeration(target string) string {
	return fmt.Sprintf(`nessus_target_enumeration:
  scanner: %s
  target: %s
  enumeration_techniques:
    - dns_resolution
    - reverse_dns_lookup
    - ping_sweep
    - port_scan
    - service_fingerprint
    - os_detection
    - vulnerability_probe`, e.config.Host, target)
}

func (e *NessusEngine) GetNessusAgentTraces() string {
	return `nessus_agent_forensic_traces:
  registry_keys:
    - HKLM\SYSTEM\CurrentControlSet\Services\NessusAgent
    - HKLM\SOFTWARE\Tenable\Nessus\Agent
  file_system_paths:
    - C:\Program Files\Tenable\Nessus Agent\
    - C:\ProgramData\Tenable\Nessus Agent\
    - C:\Program Files\Tenable\Nessus\*
  processes:
    - nessusagent.exe
    - nessusd.exe
    - nessuscli.exe
  network_connections:
    - tcp/8834 (Nessus API)
    - tcp/443 (Nessus Cloud)
    - tcp/80 (target scanning)
  windows_event_logs:
    - source: NessusAgent
      event_ids: [4688, 5156, 5158]`
}
