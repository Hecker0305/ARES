package agent

import (
	"strings"

	"github.com/ares/engine/internal/scanctx"
)

type Phase = scanctx.Phase

const (
	PhaseRecon       Phase = scanctx.PhaseRecon
	PhaseDiscovery   Phase = scanctx.PhaseDiscovery
	PhaseVulnScan    Phase = scanctx.PhaseVulnScan
	PhaseExploit     Phase = scanctx.PhaseExploit
	PhasePostExploit Phase = scanctx.PhasePostExploit
	PhaseReport      Phase = scanctx.PhaseReport
)

type ScanState struct {
	Phase      Phase
	Iteration  int
	Targets    []string
	Findings   []FindingData
	Rejections map[string]int
	CommandSeq int
	PrevCmd    string
	Status     string
	Error      string

	TerminalCalls      int
	InjectionTested    bool
	DirBustingDone     bool
	ScannerUsed        bool
	EmptyResponseCount int
	NoToolCount        int
	FinishAttempts     int
	StuckCounter       int
	UniqueToolsUsed    map[string]bool
}

type FindingData struct {
	Type        string
	Target      string
	Payload     string
	VulnType    string
	Severity    string
	Confidence  float64
	RawResponse string
	Timestamp   string
	Error       string
}

func NewScanState(targets []string) *ScanState {
	if targets == nil {
		targets = []string{}
	}
	return &ScanState{
		Phase:           PhaseRecon,
		Targets:         targets,
		Findings:        []FindingData{},
		Rejections:      make(map[string]int),
		UniqueToolsUsed: make(map[string]bool),
	}
}

func (s *ScanState) NextPhase() Phase {
	switch s.Phase {
	case PhaseRecon:
		return PhaseDiscovery
	case PhaseDiscovery:
		return PhaseVulnScan
	case PhaseVulnScan:
		return PhaseExploit
	case PhaseExploit:
		return PhasePostExploit
	case PhasePostExploit:
		return PhaseReport
	case PhaseReport:
		return PhaseReport
	default:
		return s.Phase
	}
}

func (s *ScanState) AdvancePhase() {
	s.Phase = s.NextPhase()
}

func (s *ScanState) IncrementIteration() {
	s.Iteration++
}

func (s *ScanState) RecordFinding(f FindingData) {
	s.Findings = append(s.Findings, f)
}

func (s *ScanState) ReInjectTargets(cmd string) string {
	if len(s.Targets) == 0 {
		return cmd
	}
	targetList := strings.Join(s.Targets, ", ")
	return cmd + " [TARGETS: " + targetList + "]"
}

func (s *ScanState) CheckStuck(maxIterations int) bool {
	return s.Iteration >= maxIterations
}

func (s *ScanState) MarkExecuted(cmd string) {
	s.PrevCmd = cmd
	s.CommandSeq++
}
