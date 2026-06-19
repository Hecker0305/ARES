package types

import (
	"fmt"
	"time"
)

type TrustLevel int

const (
	TrustUntrusted TrustLevel = 0
	TrustLow       TrustLevel = 1
	TrustMedium    TrustLevel = 2
	TrustHigh      TrustLevel = 3
	TrustVerified  TrustLevel = 4
)

type Taint int

const (
	TaintClean   Taint = 0
	TaintLLM     Taint = 1
	TaintNetwork Taint = 2
	TaintFile    Taint = 3
	TaintBrowser Taint = 4
	TaintPayload Taint = 5
	TaintReplay  Taint = 6
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type FindingStatus string

const (
	StatusDiscovered FindingStatus = "discovered"
	StatusTesting    FindingStatus = "testing"
	StatusVerified   FindingStatus = "verified"
	StatusFalsePos   FindingStatus = "false_positive"
	StatusChained    FindingStatus = "chained"
	StatusEscalated  FindingStatus = "escalated"
	StatusReported   FindingStatus = "reported"
)

type Target struct {
	ID           string            `json:"id"`
	Host         string            `json:"host"`
	IPs          []string          `json:"ips,omitempty"`
	Ports        []int             `json:"ports,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	Services     []string          `json:"services,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Trust        TrustLevel        `json:"trust"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

func NewTarget(id, host string) (*Target, error) {
	if id == "" {
		return nil, fmt.Errorf("target ID is required")
	}
	if host == "" {
		return nil, fmt.Errorf("target host is required")
	}
	return &Target{
		ID:           id,
		Host:         host,
		IPs:          make([]string, 0),
		Ports:        make([]int, 0),
		Technologies: make([]string, 0),
		Services:     make([]string, 0),
		Metadata:     make(map[string]string),
		DiscoveredAt: time.Now(),
	}, nil
}

func (t *Target) Validate() error {
	if t == nil {
		return fmt.Errorf("target is nil")
	}
	if t.ID == "" {
		return fmt.Errorf("target ID is required")
	}
	if t.Host == "" {
		return fmt.Errorf("target host is required")
	}
	return nil
}

type Finding struct {
	ID              string            `json:"id"`
	TargetID        string            `json:"target_id"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	VulnType        string            `json:"vuln_type"`
	Severity        Severity          `json:"severity"`
	Status          FindingStatus     `json:"status"`
	Confidence      float64           `json:"confidence"`
	CVSS            float64           `json:"cvss,omitempty"`
	CWE             string            `json:"cwe,omitempty"`
	CVE             string            `json:"cve,omitempty"`
	Endpoint        string            `json:"endpoint,omitempty"`
	Parameter       string            `json:"parameter,omitempty"`
	Payload         string            `json:"payload,omitempty"`
	ExtractionProof string            `json:"extraction_proof,omitempty"`
	Remediation     string            `json:"remediation,omitempty"`
	Taint           Taint             `json:"taint"`
	Provenance      []ProvenanceEntry `json:"provenance,omitempty"`
	Evidence        []EvidenceRef     `json:"evidence,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

func NewFinding(id, targetID, title, vulnType string, severity Severity) (*Finding, error) {
	if id == "" {
		return nil, fmt.Errorf("finding ID is required")
	}
	if targetID == "" {
		return nil, fmt.Errorf("target ID is required")
	}
	if title == "" {
		return nil, fmt.Errorf("finding title is required")
	}
	if vulnType == "" {
		return nil, fmt.Errorf("vulnerability type is required")
	}
	now := time.Now()
	return &Finding{
		ID:         id,
		TargetID:   targetID,
		Title:      title,
		VulnType:   vulnType,
		Severity:   severity,
		Status:     StatusDiscovered,
		Confidence: 0.0,
		Provenance: make([]ProvenanceEntry, 0),
		Evidence:   make([]EvidenceRef, 0),
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

func (f *Finding) Validate() error {
	if f == nil {
		return fmt.Errorf("finding is nil")
	}
	if f.ID == "" {
		return fmt.Errorf("finding ID is required")
	}
	if f.TargetID == "" {
		return fmt.Errorf("target ID is required")
	}
	if f.Title == "" {
		return fmt.Errorf("finding title is required")
	}
	if f.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	return nil
}

type EvidenceRef struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Location string `json:"location"`
	Hash     string `json:"hash"`
}

func NewEvidenceRef(id, eType, location string) (*EvidenceRef, error) {
	if id == "" {
		return nil, fmt.Errorf("evidence ID is required")
	}
	if eType == "" {
		return nil, fmt.Errorf("evidence type is required")
	}
	return &EvidenceRef{
		ID:       id,
		Type:     eType,
		Location: location,
	}, nil
}

type ProvenanceEntry struct {
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Tool      string    `json:"tool,omitempty"`
	Verifier  string    `json:"verifier,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	TraceID   string    `json:"trace_id,omitempty"`
}

func (p *ProvenanceEntry) Validate() error {
	if p == nil {
		return fmt.Errorf("provenance entry is nil")
	}
	if p.Agent == "" {
		return fmt.Errorf("provenance agent is required")
	}
	if p.Action == "" {
		return fmt.Errorf("provenance action is required")
	}
	return nil
}

type Credential struct {
	ID           string            `json:"id"`
	TargetID     string            `json:"target_id"`
	Username     string            `json:"username,omitempty"`
	Password     string            `json:"password,omitempty"`
	Hash         string            `json:"hash,omitempty"`
	Token        string            `json:"token,omitempty"`
	Key          string            `json:"key,omitempty"`
	Service      string            `json:"service"`
	Source       string            `json:"source"`
	Confidence   float64           `json:"confidence"`
	Taint        Taint             `json:"taint"`
	Provenance   []ProvenanceEntry `json:"provenance,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

func NewCredential(id, targetID, service, source string) (*Credential, error) {
	if id == "" {
		return nil, fmt.Errorf("credential ID is required")
	}
	if targetID == "" {
		return nil, fmt.Errorf("target ID is required")
	}
	if service == "" {
		return nil, fmt.Errorf("service is required")
	}
	if source == "" {
		return nil, fmt.Errorf("source is required")
	}
	return &Credential{
		ID:           id,
		TargetID:     targetID,
		Service:      service,
		Source:       source,
		Provenance:   make([]ProvenanceEntry, 0),
		DiscoveredAt: time.Now(),
	}, nil
}

type Session struct {
	ID         string            `json:"id"`
	TargetID   string            `json:"target_id"`
	Token      string            `json:"token,omitempty"`
	Cookies    map[string]string `json:"cookies,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Provenance []ProvenanceEntry `json:"provenance,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

func NewSession(id, targetID string) (*Session, error) {
	if id == "" {
		return nil, fmt.Errorf("session ID is required")
	}
	if targetID == "" {
		return nil, fmt.Errorf("target ID is required")
	}
	now := time.Now()
	return &Session{
		ID:         id,
		TargetID:   targetID,
		Cookies:    make(map[string]string),
		Headers:    make(map[string]string),
		Provenance: make([]ProvenanceEntry, 0),
		CreatedAt:  now,
	}, nil
}

type AttackPath struct {
	ID         string            `json:"id"`
	TargetID   string            `json:"target_id"`
	Steps      []AttackStep      `json:"steps"`
	Score      float64           `json:"score"`
	Impact     string            `json:"impact"`
	Provenance []ProvenanceEntry `json:"provenance,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

func NewAttackPath(id, targetID string) (*AttackPath, error) {
	if id == "" {
		return nil, fmt.Errorf("attack path ID is required")
	}
	if targetID == "" {
		return nil, fmt.Errorf("target ID is required")
	}
	return &AttackPath{
		ID:         id,
		TargetID:   targetID,
		Steps:      make([]AttackStep, 0),
		Provenance: make([]ProvenanceEntry, 0),
		CreatedAt:  time.Now(),
	}, nil
}

type AttackStep struct {
	Order      int     `json:"order"`
	Technique  string  `json:"techn<think>"`
	FindingID  string  `json:"finding_id,omitempty"`
	Credential string  `json:"credential_id,omitempty"`
	Confidence float64 `json:"confidence"`
	Status     string  `json:"status"`
}

func (a *AttackStep) Validate() error {
	if a == nil {
		return fmt.Errorf("attack step is nil")
	}
	if a.Technique == "" {
		return fmt.Errorf("technique is required")
	}
	return nil
}

type Policy struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Effect    string   `json:"effect"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Targets   []string `json:"targets,omitempty"`
	Priority  int      `json:"priority"`
}

func NewPolicy(id, name, effect string) (*Policy, error) {
	if id == "" {
		return nil, fmt.Errorf("policy ID is required")
	}
	if name == "" {
		return nil, fmt.Errorf("policy name is required")
	}
	if effect == "" {
		return nil, fmt.Errorf("policy effect is required")
	}
	return &Policy{
		ID:        id,
		Name:      name,
		Effect:    effect,
		Actions:   make([]string, 0),
		Resources: make([]string, 0),
		Targets:   make([]string, 0),
	}, nil
}

type ReplayArtifact struct {
	ID        string           `json:"id"`
	SessionID string           `json:"session_id"`
	Actions   []RecordedAction `json:"actions"`
	Hash      string           `json:"hash"`
	CreatedAt time.Time        `json:"created_at"`
}

func NewReplayArtifact(id, sessionID string) (*ReplayArtifact, error) {
	if id == "" {
		return nil, fmt.Errorf("replay artifact ID is required")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("session ID is required")
	}
	return &ReplayArtifact{
		ID:        id,
		SessionID: sessionID,
		Actions:   make([]RecordedAction, 0),
		CreatedAt: time.Now(),
	}, nil
}

type RecordedAction struct {
	Order    int               `json:"order"`
	Type     string            `json:"type"`
	Request  string            `json:"request,omitempty"`
	Response string            `json:"response,omitempty"`
	Duration time.Duration     `json:"duration"`
	Tags     map[string]string `json:"tags,omitempty"`
}

func (r *RecordedAction) Validate() error {
	if r == nil {
		return fmt.Errorf("recorded action is nil")
	}
	if r.Type == "" {
		return fmt.Errorf("action type is required")
	}
	return nil
}

type ExploitResult struct {
	ID           string            `json:"id"`
	FindingID    string            `json:"finding_id"`
	Success      bool              `json:"success"`
	Output       string            `json:"output"`
	Evidence     string            `json:"evidence"`
	Confidence   float64           `json:"confidence"`
	Reproducible bool              `json:"reproducible"`
	Provenance   []ProvenanceEntry `json:"provenance,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

func NewExploitResult(id, findingID string) (*ExploitResult, error) {
	if id == "" {
		return nil, fmt.Errorf("exploit result ID is required")
	}
	if findingID == "" {
		return nil, fmt.Errorf("finding ID is required")
	}
	return &ExploitResult{
		ID:         id,
		FindingID:  findingID,
		Provenance: make([]ProvenanceEntry, 0),
		CreatedAt:  time.Now(),
	}, nil
}

type ResourceBudget struct {
	MaxTokens     int64 `json:"max_tokens"`
	MaxMemoryMB   int64 `json:"max_memory_mb"`
	MaxGoroutines int   `json:"max_goroutines"`
	MaxExecutions int   `json:"max_executions"`
	MaxReplays    int   `json:"max_replays"`
	MaxBrowserOps int   `json:"max_browser_ops"`
}

func (r *ResourceBudget) Validate() error {
	if r == nil {
		return fmt.Errorf("resource budget is nil")
	}
	if r.MaxTokens < 0 {
		return fmt.Errorf("max tokens must be non-negative")
	}
	if r.MaxMemoryMB < 0 {
		return fmt.Errorf("max memory must be non-negative")
	}
	if r.MaxGoroutines < 0 {
		return fmt.Errorf("max goroutines must be non-negative")
	}
	return nil
}

type Capability struct {
	Agent        string   `json:"agent"`
	Capabilities []string `json:"capabilities"`
	Denied       []string `json:"denied"`
}

func NewCapability(agent string) (*Capability, error) {
	if agent == "" {
		return nil, fmt.Errorf("agent is required")
	}
	return &Capability{
		Agent:        agent,
		Capabilities: make([]string, 0),
		Denied:       make([]string, 0),
	}, nil
}

type CapabilitySet struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

func NewCapabilitySet() *CapabilitySet {
	return &CapabilitySet{
		Allow: make([]string, 0),
		Deny:  make([]string, 0),
	}
}
