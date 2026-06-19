package compliancebuilder

import (
	"github.com/ares/engine/internal/uuid"
	"fmt"
	"sync"
	"time"
)

type Framework struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Description string    `json:"description"`
	Controls    []Control `json:"controls"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Control struct {
	ID          string   `json:"id"`
	FrameworkID string   `json:"framework_id"`
	ControlID   string   `json:"control_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Mapping     []string `json:"mapping,omitempty"`
	Tests       []string `json:"tests,omitempty"`
}

type ComplianceBuilder struct {
	mu         sync.RWMutex
	frameworks map[string]*Framework
}

func New() *ComplianceBuilder {
	b := &ComplianceBuilder{
		frameworks: make(map[string]*Framework),
	}
	b.seedDefaults()
	return b
}

func (b *ComplianceBuilder) seedDefaults() {
	b.frameworks["soc2"] = &Framework{
		ID:          "soc2",
		Name:        "SOC 2",
		Version:     "2024",
		Description: "Service Organization Control 2 - Trust Services Criteria",
		CreatedAt:   time.Now(),
		Controls: []Control{
			{ControlID: "CC1.1", Title: "Control Environment", Category: "Security", Severity: "high"},
			{ControlID: "CC2.1", Title: "Communication and Information", Category: "Security", Severity: "medium"},
			{ControlID: "CC3.1", Title: "Risk Assessment", Category: "Security", Severity: "high"},
			{ControlID: "CC4.1", Title: "Monitoring Activities", Category: "Security", Severity: "medium"},
			{ControlID: "CC5.1", Title: "Control Activities", Category: "Security", Severity: "high"},
			{ControlID: "CC6.1", Title: "Logical and Physical Access", Category: "Security", Severity: "critical"},
			{ControlID: "CC7.1", Title: "System Operations", Category: "Availability", Severity: "high"},
			{ControlID: "CC8.1", Title: "Change Management", Category: "Security", Severity: "high"},
		},
	}

	b.frameworks["iso27001"] = &Framework{
		ID:          "iso27001",
		Name:        "ISO 27001",
		Version:     "2022",
		Description: "Information Security Management System Standard",
		CreatedAt:   time.Now(),
		Controls: []Control{
			{ControlID: "A.5.1", Title: "Information Security Policy", Category: "Governance", Severity: "high"},
			{ControlID: "A.6.1", Title: "Organization of Information Security", Category: "Governance", Severity: "medium"},
			{ControlID: "A.7.1", Title: "Human Resource Security", Category: "HR", Severity: "medium"},
			{ControlID: "A.8.1", Title: "Asset Management", Category: "Asset Management", Severity: "high"},
			{ControlID: "A.9.1", Title: "Access Control", Category: "Access Control", Severity: "critical"},
			{ControlID: "A.10.1", Title: "Cryptography", Category: "Cryptography", Severity: "high"},
			{ControlID: "A.12.1", Title: "Operations Security", Category: "Operations", Severity: "high"},
			{ControlID: "A.16.1", Title: "Incident Management", Category: "Incident Response", Severity: "critical"},
		},
	}

	b.frameworks["pci-dss"] = &Framework{
		ID:          "pci-dss",
		Name:        "PCI DSS",
		Version:     "4.0",
		Description: "Payment Card Industry Data Security Standard",
		CreatedAt:   time.Now(),
		Controls: []Control{
			{ControlID: "1.1", Title: "Firewall Configuration", Category: "Network Security", Severity: "critical"},
			{ControlID: "2.1", Title: "Secure Configurations", Category: "System Hardening", Severity: "high"},
			{ControlID: "3.1", Title: "Protect Stored Cardholder Data", Category: "Data Protection", Severity: "critical"},
			{ControlID: "4.1", Title: "Encrypt Transmission", Category: "Encryption", Severity: "critical"},
			{ControlID: "5.1", Title: "Protect Against Malware", Category: "Malware Protection", Severity: "high"},
			{ControlID: "6.1", Title: "Secure Development", Category: "Application Security", Severity: "high"},
			{ControlID: "7.1", Title: "Access Control", Category: "Access Control", Severity: "high"},
			{ControlID: "8.1", Title: "Authentication", Category: "Identity Management", Severity: "critical"},
			{ControlID: "10.1", Title: "Audit Logging", Category: "Logging", Severity: "high"},
			{ControlID: "11.1", Title: "Security Testing", Category: "Testing", Severity: "high"},
		},
	}

	b.frameworks["hipaa"] = &Framework{
		ID:          "hipaa",
		Name:        "HIPAA",
		Version:     "2024",
		Description: "Health Insurance Portability and Accountability Act",
		CreatedAt:   time.Now(),
		Controls: []Control{
			{ControlID: "164.308", Title: "Security Management Process", Category: "Administrative", Severity: "critical"},
			{ControlID: "164.310", Title: "Physical Safeguards", Category: "Physical", Severity: "high"},
			{ControlID: "164.312", Title: "Technical Safeguards", Category: "Technical", Severity: "critical"},
			{ControlID: "164.314", Title: "Organizational Requirements", Category: "Administrative", Severity: "medium"},
		},
	}
}

func (b *ComplianceBuilder) CreateFramework(f Framework) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if f.ID == "" {
		f.ID = uuid.New()
	}
	f.CreatedAt = time.Now()
	f.UpdatedAt = time.Now()

	for i := range f.Controls {
		if f.Controls[i].ID == "" {
			f.Controls[i].ID = uuid.New()
		}
		f.Controls[i].FrameworkID = f.ID
	}

	b.frameworks[f.ID] = &f
	return f.ID, nil
}

func (b *ComplianceBuilder) GetFramework(id string) *Framework {
	b.mu.RLock()
	defer b.mu.RUnlock()
	fw := b.frameworks[id]
	if fw == nil {
		return nil
	}
	return fw
}

func (b *ComplianceBuilder) ListFrameworks() []*Framework {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]*Framework, 0, len(b.frameworks))
	for _, fw := range b.frameworks {
		result = append(result, fw)
	}
	return result
}

func (b *ComplianceBuilder) UpdateFramework(id string, updates Framework) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	fw, ok := b.frameworks[id]
	if !ok {
		return false
	}

	if updates.Name != "" {
		fw.Name = updates.Name
	}
	if updates.Description != "" {
		fw.Description = updates.Description
	}
	if updates.Version != "" {
		fw.Version = updates.Version
	}
	if updates.Controls != nil {
		fw.Controls = updates.Controls
	}
	fw.UpdatedAt = time.Now()
	return true
}

func (b *ComplianceBuilder) DeleteFramework(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.frameworks[id]
	if !ok {
		return false
	}
	delete(b.frameworks, id)
	return true
}

func (b *ComplianceBuilder) AddControl(frameworkID string, control Control) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	fw, ok := b.frameworks[frameworkID]
	if !ok {
		return "", fmt.Errorf("framework %s not found", frameworkID)
	}

	if control.ID == "" {
		control.ID = uuid.New()
	}
	control.FrameworkID = frameworkID
	fw.Controls = append(fw.Controls, control)
	fw.UpdatedAt = time.Now()
	return control.ID, nil
}
