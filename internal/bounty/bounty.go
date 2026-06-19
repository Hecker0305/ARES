package bounty

import "time"

type Report struct {
	ID         string           `json:"id"`
	Severity   string           `json:"severity"`
	Status     string           `json:"status"`
	CreatedAt  time.Time        `json:"created_at"`
	Report     ReportSub        `json:"report"`
	Provenance ReportProvenance `json:"provenance"`
}

type ReportSub struct {
	Title string `json:"title"`
}

type ReportProvenance struct {
	Platform   string `json:"platform"`
	Researcher string `json:"researcher"`
}

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) ListConfigs() []Config {
	return nil
}

type Config struct {
	Platform string `json:"platform"`
	Enabled  bool   `json:"enabled"`
	APIKey   string `json:"api_key,omitempty"`
}

func (m *Manager) MatchTarget(target string) []*Report {
	return nil
}

func (m *Manager) MatchFinding(title, description string) *Report {
	return nil
}

func (m *Manager) UpdateReportStatus(id, status, findingID string) {}
