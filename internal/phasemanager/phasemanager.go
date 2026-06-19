package phasemanager

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ares/engine/internal/scanctx"
)

type Status int

const (
	Pending Status = iota
	Active
	Completed
	Skipped
	Failed
)

func (s Status) String() string {
	switch s {
	case Pending:
		return "pending"
	case Active:
		return "active"
	case Completed:
		return "completed"
	case Skipped:
		return "skipped"
	case Failed:
		return "failed"
	default:
		return "unknown"
	}
}

type PhaseState struct {
	Info   scanctx.Phase22Info
	Status Status
}

type Manager struct {
	mu             sync.RWMutex
	orderedPhases  []scanctx.Phase22
	phaseStates    map[scanctx.Phase22]*PhaseState
	selectedPhases map[scanctx.Phase22]bool
	currentIndex   int
	onPhaseChange  func(oldPhase, newPhase scanctx.Phase22)
	scanMode       scanctx.ScanMode
	prerequisites  map[scanctx.Phase22][]scanctx.Phase22
}

func New() *Manager {
	ordered := make([]scanctx.Phase22, len(scanctx.AllPhases22))
	selected := make(map[scanctx.Phase22]bool)
	states := make(map[scanctx.Phase22]*PhaseState)
	prereqs := make(map[scanctx.Phase22][]scanctx.Phase22)

	for i, p := range scanctx.AllPhases22 {
		ordered[i] = p.ID
		if p.DefaultOn {
			selected[p.ID] = true
		}
		states[p.ID] = &PhaseState{
			Info:   p,
			Status: Pending,
		}
		if i > 0 {
			prereqs[p.ID] = []scanctx.Phase22{ordered[i-1]}
		}
	}

	return &Manager{
		selectedPhases: selected,
		orderedPhases:  ordered,
		phaseStates:    states,
		currentIndex:   0,
		scanMode:       scanctx.ModeSingleTarget,
		prerequisites:  prereqs,
	}
}

func (m *Manager) SetPrerequisites(phase scanctx.Phase22, deps []scanctx.Phase22) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prerequisites[phase] = deps
}

func (m *Manager) SetScanMode(mode scanctx.ScanMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanMode = mode
}

func (m *Manager) ScanMode() scanctx.ScanMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scanMode
}

func (m *Manager) SelectPhase(id scanctx.Phase22) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.selectedPhases[id] = true
}

func (m *Manager) DeselectPhase(id scanctx.Phase22) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.selectedPhases, id)
}

func (m *Manager) SetSelectedPhases(ids []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.selectedPhases = make(map[scanctx.Phase22]bool)
	for _, id := range ids {
		m.selectedPhases[scanctx.Phase22(id)] = true
	}
}

func (m *Manager) IsSelected(id scanctx.Phase22) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.selectedPhases[id]
}

func (m *Manager) SelectedPhases() []scanctx.Phase22 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []scanctx.Phase22
	for _, id := range m.orderedPhases {
		if m.selectedPhases[id] {
			result = append(result, id)
		}
	}
	return result
}

func (m *Manager) SelectedPhaseInfos() []scanctx.Phase22Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []scanctx.Phase22Info
	for _, id := range m.orderedPhases {
		if m.selectedPhases[id] {
			if ps, ok := m.phaseStates[id]; ok {
				result = append(result, ps.Info)
			}
		}
	}
	return result
}

func (m *Manager) CurrentPhase() PhaseState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	selected := m.selectedPhases
	ordered := m.orderedPhases
	idx := m.currentIndex

	count := -1
	for _, id := range ordered {
		if selected[id] {
			count++
		}
		if count == idx {
			if ps, ok := m.phaseStates[id]; ok {
				return *ps
			}
			return PhaseState{}
		}
	}
	return PhaseState{}
}

func (m *Manager) CurrentPhaseID() scanctx.Phase22 {
	ps := m.CurrentPhase()
	return ps.Info.ID
}

func (m *Manager) validatePhaseTransition(targetIdx int) error {
	selected := m.selectedPhases
	ordered := m.orderedPhases

	if targetIdx <= m.currentIndex {
		return nil
	}

	if targetIdx > m.currentIndex+1 {
		return fmt.Errorf("phase skip not allowed: current=%d target=%d", m.currentIndex, targetIdx)
	}

	targetID := ordered[targetIdx]
	if deps, ok := m.prerequisites[targetID]; ok {
		for _, dep := range deps {
			if !selected[dep] {
				continue
			}
			if ps, exists := m.phaseStates[dep]; exists {
				if ps.Status != Completed && ps.Status != Skipped {
					return fmt.Errorf("prerequisite phase %s not completed (status: %s)", dep, ps.Status)
				}
			}
		}
	}

	return nil
}

func (m *Manager) SetOnPhaseChange(fn func(oldPhase, newPhase scanctx.Phase22)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPhaseChange = fn
}

func (m *Manager) AdvancePhase() error {
	m.mu.Lock()

	selected := m.selectedPhases
	ordered := m.orderedPhases
	idx := m.currentIndex

	count := -1
	var oldPhase scanctx.Phase22
	for _, id := range ordered {
		if selected[id] {
			count++
		}
		if count == idx {
			oldPhase = id
			if ps, ok := m.phaseStates[id]; ok && (ps.Status == Pending || ps.Status == Active) {
				ps.Status = Completed
			}
			break
		}
	}

	nextIdx := idx + 1
	if err := m.validatePhaseTransition(nextIdx); err != nil {
		m.mu.Unlock()
		return err
	}

	m.currentIndex = nextIdx

	var newPhase scanctx.Phase22
	count = -1
	for _, id := range ordered {
		if selected[id] {
			count++
		}
		if count == nextIdx {
			newPhase = id
			if ps, ok := m.phaseStates[id]; ok && ps.Status == Pending {
				ps.Status = Active
			}
			break
		}
	}

	callback := m.onPhaseChange
	m.mu.Unlock()

	if callback != nil && newPhase != "" {
		callback(oldPhase, newPhase)
	}

	return nil
}

func (m *Manager) SetPhaseStatus(id scanctx.Phase22, status Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ps, ok := m.phaseStates[id]; ok {
		ps.Status = status
	}
}

func (m *Manager) PhaseStatus(id scanctx.Phase22) Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ps, ok := m.phaseStates[id]; ok {
		return ps.Status
	}
	return Pending
}

func (m *Manager) AllPhaseStates() []PhaseState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []PhaseState
	for _, id := range m.orderedPhases {
		if ps, ok := m.phaseStates[id]; ok {
			result = append(result, *ps)
		}
	}
	return result
}

func (m *Manager) AllEnabledPhaseStates() []PhaseState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []PhaseState
	for _, id := range m.orderedPhases {
		if m.selectedPhases[id] {
			if ps, ok := m.phaseStates[id]; ok {
				result = append(result, *ps)
			}
		}
	}
	return result
}

func (m *Manager) Progress() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	total := 0
	done := 0
	for _, id := range m.orderedPhases {
		if m.selectedPhases[id] {
			total++
			if ps, ok := m.phaseStates[id]; ok {
				if ps.Status == Completed || ps.Status == Skipped || ps.Status == Failed {
					done++
				}
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(done) / float64(total)
}

func (m *Manager) SystemPromptSection() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\nSCAN MODE: %s\n", m.scanMode))
	sb.WriteString("\nSELECTED METHODOLOGY PHASES (22-phase model):\n")

	for i, id := range m.orderedPhases {
		if !m.selectedPhases[id] {
			continue
		}
		ps := m.phaseStates[id]
		marker := "[ ]"
		statusStr := ""
		switch ps.Status {
		case Active:
			marker = "[>]"
			statusStr = " ACTIVE"
		case Completed:
			marker = "[✓]"
			statusStr = " DONE"
		case Skipped:
			marker = "[-]"
			statusStr = " SKIPPED"
		case Failed:
			marker = "[!]"
			statusStr = " FAILED"
		}

		count := 0
		for j := 0; j <= i; j++ {
			if m.selectedPhases[m.orderedPhases[j]] {
				count++
			}
		}

		sb.WriteString(fmt.Sprintf("  %s Phase %02d: %s%s\n", marker, count, ps.Info.Label, statusStr))
	}

	sb.WriteString("\nExecute phases sequentially. Focus on the active phase.")
	sb.WriteString(" When you complete a phase, call the next phase's tasks.")
	sb.WriteString(" Do not skip ahead to future phases.")

	return sb.String()
}

func (m *Manager) PhaseIndex() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentIndex
}

func (m *Manager) SetPhaseIndex(idx int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validatePhaseTransition(idx); err != nil {
		return err
	}
	m.currentIndex = idx
	return nil
}

func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentIndex = 0
	for _, ps := range m.phaseStates {
		ps.Status = Pending
	}
}

func (m *Manager) ActivateCurrentPhase() {
	m.mu.Lock()
	defer m.mu.Unlock()

	selected := m.selectedPhases
	ordered := m.orderedPhases
	idx := m.currentIndex

	count := -1
	for _, id := range ordered {
		if selected[id] {
			count++
		}
		if count == idx {
			if ps, ok := m.phaseStates[id]; ok && ps.Status == Pending {
				ps.Status = Active
			}
			return
		}
	}
}

func (m *Manager) ResumeFromPhase(phaseName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	found := false
	for i, id := range m.orderedPhases {
		if string(id) == phaseName {
			m.currentIndex = i
			found = true
		}
		if found {
			break
		}
		if ps, ok := m.phaseStates[id]; ok {
			ps.Status = Completed
		}
	}
	if found {
		if ps, ok := m.phaseStates[m.orderedPhases[m.currentIndex]]; ok {
			ps.Status = Active
		}
	}
}

func (m *Manager) SelectedPhaseIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []string
	for _, id := range m.orderedPhases {
		if m.selectedPhases[id] {
			result = append(result, string(id))
		}
	}
	return result
}
