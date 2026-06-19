package tui

import (
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const maxEventBuffer = 1000

var (
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Bold(true)

	severityCritical = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FF0000")).
				Bold(true)

	severityHigh = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6600"))

	severityMedium = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFF00"))

	severityLow = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FFFF"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))
)

type FindingStyle struct {
	Type      string
	Severity  string
	Target    string
	Timestamp string
}

func (f FindingStyle) String() string {
	style := severityLow
	switch f.Severity {
	case "critical":
		style = severityCritical
	case "high":
		style = severityHigh
	case "medium":
		style = severityMedium
	case "low":
		style = severityLow
	}
	return style.Render(fmt.Sprintf("[%s] %s @ %s", f.Severity, f.Type, f.Target))
}

type TUIModel struct {
	activeScans   int
	totalFindings int
	scanStatus    map[string]string
	events        []TUIEvent
	maxEvents     int
	mu            sync.RWMutex
}

type TUIEvent struct {
	Type      string
	Message   string
	Timestamp time.Time
	Details   map[string]string
}

func NewTUIModel() *TUIModel {
	return &TUIModel{
		scanStatus: make(map[string]string),
		events:     make([]TUIEvent, 0, maxEventBuffer),
		maxEvents:  maxEventBuffer,
	}
}

func (m *TUIModel) SetMaxEvents(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n > 0 {
		m.maxEvents = n
		if len(m.events) > m.maxEvents {
			m.events = m.events[len(m.events)-m.maxEvents:]
		}
	}
}

func (m *TUIModel) UpdateScan(id, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanStatus[id] = status
	m.addEventLocked("scan_update", status, map[string]string{"scan_id": id, "status": status})
}

func (m *TUIModel) AddFinding(finding FindingStyle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalFindings++
	m.addEventLocked("finding", finding.String(), map[string]string{
		"type":     finding.Type,
		"severity": finding.Severity,
		"target":   finding.Target,
	})
}

func (m *TUIModel) addEventLocked(eventType, message string, details map[string]string) {
	m.events = append(m.events, TUIEvent{
		Type:      eventType,
		Message:   message,
		Timestamp: time.Now(),
		Details:   details,
	})
	if len(m.events) > m.maxEvents {
		drop := len(m.events) - m.maxEvents
		m.events = m.events[drop:]
	}
}

func (m *TUIModel) Summary() string {
	m.mu.RLock()
	activeScans := m.activeScans
	totalFindings := m.totalFindings
	events := make([]TUIEvent, len(m.events))
	copy(events, m.events)
	m.mu.RUnlock()

	var lines []string
	lines = append(lines, headerStyle.Render("Ares V2 Scanner"))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  Active Scans: %d", activeScans))
	lines = append(lines, fmt.Sprintf("  Total Findings: %d", totalFindings))
	lines = append(lines, "")

	lines = append(lines, "  [Recent Events]")
	start := len(events) - 5
	if start < 0 {
		start = 0
	}
	for i := len(events) - 1; i >= start; i-- {
		e := events[i]
		ts := e.Timestamp.Format("15:04:05")
		lines = append(lines, fmt.Sprintf("  %s | %s", ts, e.Message))
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m *TUIModel) Start() error {
	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui error: %w", err)
	}
	return nil
}

func (m *TUIModel) Init() tea.Cmd {
	return nil
}

func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *TUIModel) View() string {
	return m.Summary()
}

func (m *TUIModel) SetActiveScans(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeScans = n
}

func (m *TUIModel) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{
		"active_scans":   m.activeScans,
		"total_findings": m.totalFindings,
		"scan_status":    m.scanStatus,
	}
}

var _ tea.Model = (*TUIModel)(nil)
