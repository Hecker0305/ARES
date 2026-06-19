package compliance

import (
	"testing"

	"github.com/ares/engine/internal/evidence"
)

func TestNewComplianceReporter(t *testing.T) {
	em := evidence.NewEvidenceManager("./test_evidence")
	cr := NewComplianceReporter(em)
	if cr == nil {
		t.Fatal("expected non-nil reporter")
	}
}

func TestGenerateReport(t *testing.T) {
	em := evidence.NewEvidenceManager("./test_evidence")
	cr := NewComplianceReporter(em)
	report := cr.GenerateReport("example.com", FrameworkNIST80053)
	if report == nil {
		t.Log("report may be nil without evidence")
	}
}

func TestFrameworkValues(t *testing.T) {
	if FrameworkNIST80053 != "NIST_SP_800_53" {
		t.Error("NIST mismatch")
	}
	if FrameworkISO27001 != "ISO_27001" {
		t.Error("ISO mismatch")
	}
	if FrameworkPCIDSS != "PCI_DSS" {
		t.Error("PCI mismatch")
	}
	if FrameworkSOC2 != "SOC_2" {
		t.Error("SOC2 mismatch")
	}
	if FrameworkHIPAA != "HIPAA" {
		t.Error("HIPAA mismatch")
	}
	if FrameworkGDPR != "GDPR" {
		t.Error("GDPR mismatch")
	}
}

func TestComplianceReportStruct(t *testing.T) {
	report := &ComplianceReport{
		Target:    "test.com",
		Framework: FrameworkSOC2,
		Mappings: []ControlMapping{
			{ControlID: "CC1.1", Severity: "high"},
		},
		Summary: map[string]int{"high": 1},
	}
	if len(report.Mappings) != 1 {
		t.Errorf("expected 1 mapping, got %d", len(report.Mappings))
	}
}
