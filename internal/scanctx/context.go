package scanctx

import (
	"sync"
	"time"
)

const maxAuditLog = 10000

type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Info     Severity = "Info"
)

type Finding struct {
	ID              string
	Title           string
	Severity        Severity
	Endpoint        string
	Description     string
	Impact          string
	CVSSScore       float64
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

type AuditEntry struct {
	Timestamp time.Time
	Tool      string
	Command   string
	Output    string
}

type CredentialSet struct {
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Token    string            `json:"token,omitempty"`
	Cookie   string            `json:"cookie,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	AuthFlow string            `json:"authFlow,omitempty"`
	LoginURL string            `json:"loginUrl,omitempty"`
}

type ScanTrace interface {
	AddToolCall(name, params string, duration time.Duration, err string)
	AddLLMCall(prompt, completion, total int, latency time.Duration, model string, cost float64)
	EndIteration(num int, phase string, toolCalls, llmCalls int, duration time.Duration, decision string)
	MarkDone()
	Summary() map[string]interface{}
}

type ScanContext struct {
	mu          sync.RWMutex
	ScanID      string
	Target      string
	StartTime   time.Time
	LiveHosts   []string
	OpenPorts   map[string][]int
	Endpoints   []string
	TechStack   []string
	AuditLog    []AuditEntry
	Notes       []string
	Credentials *CredentialSet
	Trace       ScanTrace
}

func NewScanContext(scanID, target string) *ScanContext {
	return &ScanContext{
		ScanID:    scanID,
		Target:    target,
		StartTime: time.Now(),
	}
}

func NewScanContextWithTrace(scanID, target string, trace ScanTrace) *ScanContext {
	return &ScanContext{
		ScanID:    scanID,
		Target:    target,
		StartTime: time.Now(),
		Trace:     trace,
	}
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
	if len(sc.AuditLog) > maxAuditLog {
		sc.AuditLog = sc.AuditLog[len(sc.AuditLog)-maxAuditLog:]
	}
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

func (sc *ScanContext) AddTechStack(tech string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.TechStack = append(sc.TechStack, tech)
}
