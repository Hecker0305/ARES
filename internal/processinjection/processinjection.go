package processinjection

import (
	"fmt"
	"strings"
)

type ArtifactType int

const (
	ArtifactEventLog  ArtifactType = iota
	ArtifactRegistry
	ArtifactFileSystem
	ArtifactNetwork
	ArtifactMemory
	ArtifactPrefetch
	ArtifactModule
)

func (a ArtifactType) String() string {
	switch a {
	case ArtifactEventLog:
		return "EventLog"
	case ArtifactRegistry:
		return "Registry"
	case ArtifactFileSystem:
		return "FileSystem"
	case ArtifactNetwork:
		return "Network"
	case ArtifactMemory:
		return "Memory"
	case ArtifactPrefetch:
		return "Prefetch"
	case ArtifactModule:
		return "Module"
	default:
		return "Unknown"
	}
}

type ForensicArtifact struct {
	Type         ArtifactType
	Description  string
	Location     string
	SysmonEventID int
	Notes        string
}

type InjectionCommands struct {
	PowerShell string
	CMD        string
	CSharp     string
}

type InjectionTechnique struct {
	ID              string
	Name            string
	Description     string
	Win32APIsUsed   []string
	RiskLevel       string
	Commands        InjectionCommands
	Artifacts       []ForensicArtifact
}

type InjectionEngine struct {
	techniques []InjectionTechnique
}

func NewInjectionEngine() *InjectionEngine {
	e := &InjectionEngine{}
	e.registerAll()
	return e
}

func (e *InjectionEngine) registerAll() {
	all := append([]InjectionTechnique{}, techniques...)
	all = append(all, advancedTechniques...)
	e.techniques = all
}

func (e *InjectionEngine) Execute(techniqueID string, targetPID int, payload []byte) (string, error) {
	for _, t := range e.techniques {
		if t.ID == techniqueID {
			cmd := t.Commands.PowerShell
			if cmd == "" {
				cmd = t.Commands.CMD
			}
			cmd = strings.ReplaceAll(cmd, "{{PID}}", fmt.Sprintf("%d", targetPID))
			return cmd, nil
		}
	}
	return "", fmt.Errorf("technique %q not found", techniqueID)
}

func (e *InjectionEngine) ListTechniques() []InjectionTechnique {
	out := make([]InjectionTechnique, len(e.techniques))
	copy(out, e.techniques)
	return out
}

func (e *InjectionEngine) GetArtifacts(techniqueID string) []ForensicArtifact {
	for _, t := range e.techniques {
		if t.ID == techniqueID {
			out := make([]ForensicArtifact, len(t.Artifacts))
			copy(out, t.Artifacts)
			return out
		}
	}
	return nil
}

func (e *InjectionEngine) FindTargetProcess(name string) (int, error) {
	return 0, fmt.Errorf("process %q not found (mock: use Get-Process %s to find PID)", name, name)
}

func (e *InjectionEngine) ValidateTechnique(techniqueID string) bool {
	for _, t := range e.techniques {
		if t.ID == techniqueID {
			return true
		}
	}
	return false
}
