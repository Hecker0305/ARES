package agent

import (
	"sync"
	"time"

	"github.com/ares/engine/internal/scanctx"
)

type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Info     Severity = "Info"
)

// Finding represents a confirmed or unverified vulnerability.
type Finding struct {
	ID              string
	Title           string
	Severity        Severity
	Endpoint        string
	Description     string
	Impact          string
	CVSSScore       float64
	CVSSVector      string
	CWEID           string
	CVEID           string
	PoCSteps        []string
	PoCCode         string
	ExtractionProof string
	EvidencePath    string
	MITRETactic     string
	MITRETechnique  string
	Confidence      float64
	Confirmed       bool
	Timestamp       time.Time
}

// AuditEntry is a timestamped log of a tool action.
type AuditEntry struct {
	Timestamp time.Time
	Tool      string
	Command   string
	Output    string
}

// ScanContext holds all state for a single scan — scoped so parallel scans never share data.
type ScanContext struct {
	mu                 sync.Mutex
	TerminalState      *TerminalState
	ScanID             string
	Target             string
	StartTime          time.Time
	LiveHosts          []string
	OpenPorts          map[string][]int
	Endpoints          []string
	TechStack          []string
	ConfirmedFindings  []Finding
	UnverifiedFindings []Finding
	AuditLog           []AuditEntry
	Notes              []string
	OnFinding          func(Finding)
	Credentials        *scanctx.CredentialSet
	Trace              scanctx.ScanTrace
}

func NewScanContext(scanID, target string) *ScanContext {
	return &ScanContext{
		ScanID:        scanID,
		Target:        target,
		StartTime:     time.Now(),
		OpenPorts:     make(map[string][]int),
		TerminalState: NewTerminalState(),
	}
}

func (sc *ScanContext) AddFinding(f Finding) {
	sc.mu.Lock()
	if f.Confirmed {
		sc.ConfirmedFindings = append(sc.ConfirmedFindings, f)
	} else {
		sc.UnverifiedFindings = append(sc.UnverifiedFindings, f)
	}
	cb := sc.OnFinding
	sc.mu.Unlock()
	if cb != nil {
		cb(f)
	}
}

func (sc *ScanContext) AddFindingDedup(f Finding) bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, existing := range sc.ConfirmedFindings {
		if existing.ID == f.ID {
			return false
		}
	}
	for _, existing := range sc.UnverifiedFindings {
		if existing.ID == f.ID {
			return false
		}
	}
	if f.Confirmed {
		sc.ConfirmedFindings = append(sc.ConfirmedFindings, f)
	} else {
		sc.UnverifiedFindings = append(sc.UnverifiedFindings, f)
	}
	return true
}

func (sc *ScanContext) Log(tool, cmd, output string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.AuditLog = append(sc.AuditLog, AuditEntry{
		Timestamp: time.Now(),
		Tool:      tool,
		Command:   cmd,
		Output:    output,
	})
}

func (sc *ScanContext) AddHost(host string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.LiveHosts = append(sc.LiveHosts, host)
}

func (sc *ScanContext) AddEndpoints(endpoints []string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Endpoints = append(sc.Endpoints, endpoints...)
}

func (sc *ScanContext) AddNote(note string) int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Notes = append(sc.Notes, note)
	return len(sc.Notes) - 1
}

func (sc *ScanContext) GetFindings() []Finding {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	total := len(sc.ConfirmedFindings) + len(sc.UnverifiedFindings)
	result := make([]Finding, 0, total)
	result = append(result, sc.ConfirmedFindings...)
	result = append(result, sc.UnverifiedFindings...)
	return result
}

func (sc *ScanContext) GetAuditLog() []AuditEntry {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	result := make([]AuditEntry, len(sc.AuditLog))
	copy(result, sc.AuditLog)
	return result
}

func (sc *ScanContext) GetLiveHosts() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	result := make([]string, len(sc.LiveHosts))
	copy(result, sc.LiveHosts)
	return result
}

func (sc *ScanContext) GetEndpoints() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	result := make([]string, len(sc.Endpoints))
	copy(result, sc.Endpoints)
	return result
}

func (sc *ScanContext) GetNotes() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	result := make([]string, len(sc.Notes))
	copy(result, sc.Notes)
	return result
}
