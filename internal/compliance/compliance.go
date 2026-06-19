package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// N1 — Rules of Engagement Engine
type RoEEngine struct {
	config RoEConfig
}

type RoEConfig struct {
	StartTime        string   `json:"start_time"`
	EndTime          string   `json:"end_time"`
	AllowedDays      []string `json:"allowed_days"`
	MaxRatePerSec    int      `json:"max_rate_per_sec"`
	ExcludedTargets  []string `json:"excluded_targets"`
	NotificationURL  string   `json:"notification_url"`
	AutoStopOnImpact bool     `json:"auto_stop_on_impact"`
}

func NewRoEEngine(configPath string) (*RoEEngine, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read RoE: %w", err)
	}
	var cfg RoEConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse RoE: %w", err)
	}
	return &RoEEngine{config: cfg}, nil
}

func (r *RoEEngine) IsWithinWindow() bool {
	now := time.Now()
	weekday := now.Weekday().String()
	allowed := false
	for _, d := range r.config.AllowedDays {
		if strings.EqualFold(d, weekday) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}

	startParts := strings.Split(r.config.StartTime, ":")
	endParts := strings.Split(r.config.EndTime, ":")
	currentMin := now.Hour()*60 + now.Minute()

	if len(startParts) >= 2 {
		startMin := toInt(startParts[0])*60 + toInt(startParts[1])
		endMin := toInt(endParts[0])*60 + toInt(endParts[1])
		return currentMin >= startMin && currentMin <= endMin
	}
	return true
}

func (r *RoEEngine) IsTargetExcluded(target string) bool {
	for _, e := range r.config.ExcludedTargets {
		if strings.Contains(target, e) {
			return true
		}
	}
	return false
}

// N2 — GDPR PII Detection
type PIIDetector struct {
	patterns []PIEPattern
}

type PIEPattern struct {
	Name     string
	Pattern  string
	Severity string
}

func NewPIIDetector() *PIIDetector {
	return &PIIDetector{
		patterns: []PIEPattern{
			{Name: "Email", Pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Severity: "medium"},
			{Name: "Phone", Pattern: `\+?1?\d{10,15}`, Severity: "high"},
			{Name: "SSN", Pattern: `\d{3}-\d{2}-\d{4}`, Severity: "critical"},
			{Name: "CreditCard", Pattern: `\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}`, Severity: "critical"},
		},
	}
}

func (p *PIIDetector) ScanForPII(data string) []PIEFinding {
	var findings []PIEFinding
	for _, pat := range p.patterns {
		if strings.Contains(data, "@") && pat.Name == "Email" {
			idx := strings.Index(data, "@")
			start := 0
			if idx > 20 {
				start = idx - 20
			}
			end := idx + 20
			if end > len(data) {
				end = len(data)
			}
			findings = append(findings, PIEFinding{
				Type:     pat.Name,
				Severity: pat.Severity,
				Context:  data[start:end],
			})
		}
	}
	return findings
}

type PIEFinding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Context  string `json:"context"`
}

// N3 — Legal Chain of Custody
type ChainOfCustody struct {
	entries []COCEntry
}

type COCEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	Operator   string    `json:"operator"`
	EvidenceID string    `json:"evidence_id"`
	Hash       string    `json:"hash"`
}

func NewChainOfCustody() *ChainOfCustody {
	return &ChainOfCustody{
		entries: make([]COCEntry, 0),
	}
}

func (c *ChainOfCustody) RecordAccess(evidenceID, operator, action string) {
	c.entries = append(c.entries, COCEntry{
		Timestamp:  time.Now(),
		Action:     action,
		Operator:   operator,
		EvidenceID: evidenceID,
	})
}

func (c *ChainOfCustody) Export() string {
	data, _ := json.MarshalIndent(c.entries, "", "  ")
	return string(data)
}

// N5 — Threat Modeling Automation
type ThreatModel struct {
	SystemName string      `json:"system_name"`
	Components []Component `json:"components"`
	Threats    []Threat    `json:"threats"`
	DataFlows  []DataFlow  `json:"data_flows"`
}

type Component struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	TrustZone string `json:"trust_zone"`
}

type Threat struct {
	ID             string `json:"id"`
	STRIDECategory string `json:"stride_category"`
	Description    string `json:"description"`
	Component      string `json:"component"`
}

type DataFlow struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Protocol    string   `json:"protocol"`
	DataTypes   []string `json:"data_types"`
}

type ThreatModeler struct{}

func NewThreatModeler() *ThreatModeler {
	return &ThreatModeler{}
}

func (t *ThreatModeler) AnalyzeSTRIDE(component Component) []Threat {
	var threats []Threat
	strideTypes := []string{"Spoofing", "Tampering", "Repudiation", "Info Disclosure", "DoS", "Elevation"}
	for _, s := range strideTypes {
		threats = append(threats, Threat{
			ID:             fmt.Sprintf("STRIDE-%s-%s", s[:3], component.Name),
			STRIDECategory: s,
			Description:    fmt.Sprintf("Potential %s attack on %s", s, component.Name),
			Component:      component.Name,
		})
	}
	return threats
}

func toInt(s string) int {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
