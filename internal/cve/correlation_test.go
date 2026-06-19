package cve

import (
	"testing"
)

func TestCorrelateString(t *testing.T) {
	cves := CorrelateString("apache 2.4.49")
	t.Logf("Found %d CVEs for apache 2.4.49", len(cves))
}

func TestCorrelateStringEmpty(t *testing.T) {
	cves := CorrelateString("")
	if len(cves) != 0 {
		t.Errorf("expected 0 CVEs for empty string, got %d", len(cves))
	}
}

func TestCorrelateStringKnownSoftware(t *testing.T) {
	cves := CorrelateString("nginx")
	t.Logf("Found %d CVEs for nginx", len(cves))
}

func TestSystemPromptSection(t *testing.T) {
	cves := []CVEEntry{
		{ID: "CVE-2024-0001", CVSS: 9.8, EPSS: 0.5, KEV: true, Description: "Test CVE"},
	}
	section := SystemPromptSection(cves)
	if section == "" {
		t.Error("expected non-empty prompt section")
	}
}

func TestSystemPromptSectionEmpty(t *testing.T) {
	section := SystemPromptSection(nil)
	if section != "" {
		t.Errorf("expected empty section, got %s", section)
	}
}

func TestCVEEntryFields(t *testing.T) {
	entry := CVEEntry{
		ID:               "CVE-2024-0002",
		CVSS:             7.5,
		Severity:         "High",
		Description:      "Test CVE with all fields",
		EPSS:             0.8,
		KEV:              true,
		NucleiTag:        "test-cve-2024",
		PoCCommand:       "nuclei -t cves/test.yaml",
		Affected:         "test-software",
		AffectedProducts: []string{"product-a", "product-b"},
		CWEs:             []string{"CWE-79", "CWE-89"},
	}
	if !entry.KEV {
		t.Error("expected KEV true")
	}
	if entry.EPSS != 0.8 {
		t.Errorf("expected EPSS 0.8, got %f", entry.EPSS)
	}
	if len(entry.CWEs) != 2 {
		t.Errorf("expected 2 CWEs, got %d", len(entry.CWEs))
	}
	if entry.Severity != "High" {
		t.Errorf("expected High, got %s", entry.Severity)
	}
}
