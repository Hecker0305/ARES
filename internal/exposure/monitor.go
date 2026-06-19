package exposure

import (
	"sync"
	"time"
)

type ExposureType string

const (
	ExposureCredentialLeak ExposureType = "credential_leak"
	ExposureGitHubSecret   ExposureType = "github_secret"
	ExposureCertificate    ExposureType = "certificate"
	ExposureDomainTakeover ExposureType = "domain_takeover"
	ExposureCloudExposure  ExposureType = "cloud_exposure"
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type ExposureFinding struct {
	ID          string            `json:"id"`
	Type        ExposureType      `json:"type"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Target      string            `json:"target"`
	Details     map[string]string `json:"details,omitempty"`
	Discovered  time.Time         `json:"discovered"`
	Status      string            `json:"status"`
	Remediation string            `json:"remediation,omitempty"`
}

type ExposureMonitor struct {
	mu       sync.RWMutex
	findings []ExposureFinding
	services []MonitorService
	interval time.Duration
	stopCh   chan struct{}
}

type MonitorService interface {
	Name() string
	Run() ([]ExposureFinding, error)
	Interval() time.Duration
}

func New(interval time.Duration) *ExposureMonitor {
	return &ExposureMonitor{
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (m *ExposureMonitor) AddService(s MonitorService) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services = append(m.services, s)
}

func (m *ExposureMonitor) Start() {
	for _, s := range m.services {
		go m.runService(s)
	}
}

func (m *ExposureMonitor) Stop() {
	close(m.stopCh)
}

func (m *ExposureMonitor) runService(s MonitorService) {
	ticker := time.NewTicker(s.Interval())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			findings, err := s.Run()
			if err != nil {
				continue
			}
			m.mu.Lock()
			m.findings = append(m.findings, findings...)
			m.mu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

func (m *ExposureMonitor) GetFindings() []ExposureFinding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ExposureFinding, len(m.findings))
	copy(result, m.findings)
	return result
}

func (m *ExposureMonitor) GetFindingsByType(t ExposureType) []ExposureFinding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []ExposureFinding
	for _, f := range m.findings {
		if f.Type == t {
			result = append(result, f)
		}
	}
	return result
}
