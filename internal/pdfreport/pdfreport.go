package pdfreport

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Finding is a vulnerability finding for report generation.
type Finding struct {
	ID          string
	Title       string
	Severity    string
	CVSS        float64
	Endpoint    string
	Method      string
	Description string
	PoC         string
	Impact      string
	Remediation string
	Evidence    map[string]string
	MITRE       string
	Timestamp   time.Time
}

// ScanMeta contains scan metadata for the report.
type ScanMeta struct {
	ScanID         string
	Target         string
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	Tester         string
	CompanyName    string
	CompanyLogo    string
	Classification string
	Version        string
}

// Generator produces branded PDF reports.
type Generator struct {
	meta     ScanMeta
	findings []Finding
	summary  string
}

// New creates a new PDF report generator.
func New(meta ScanMeta) *Generator {
	return &Generator{
		meta:     meta,
		findings: make([]Finding, 0),
	}
}

// AddFindings adds findings to the report.
func (g *Generator) AddFindings(findings []Finding) {
	g.findings = append(g.findings, findings...)
}

// SetSummary sets the executive summary.
func (g *Generator) SetSummary(summary string) {
	g.summary = summary
}

// GenerateText generates a text-formatted report (PDF-ready structure).
func (g *Generator) GenerateText() string {
	var sb strings.Builder

	// Cover page
	sb.WriteString(g.coverPage())
	sb.WriteString("\n\n")

	// Table of contents
	sb.WriteString(g.tableOfContents())
	sb.WriteString("\n\n")

	// Executive summary
	sb.WriteString(g.executiveSummary())
	sb.WriteString("\n\n")

	// Methodology
	sb.WriteString(g.methodology())
	sb.WriteString("\n\n")

	// Findings summary
	sb.WriteString(g.findingsSummary())
	sb.WriteString("\n\n")

	// Detailed findings
	sb.WriteString(g.detailedFindings())
	sb.WriteString("\n\n")

	// Remediation roadmap
	sb.WriteString(g.remediationRoadmap())
	sb.WriteString("\n\n")

	// Appendix
	sb.WriteString(g.appendix())

	return sb.String()
}

// SaveToFile writes the report to a file.
func (g *Generator) SaveToFile(path string) error {
	content := g.GenerateText()
	return os.WriteFile(path, []byte(content), 0644)
}

func (g *Generator) coverPage() string {
	return fmt.Sprintf(`================================================================================
                    PENETRATION TEST REPORT
================================================================================

  Target:          %s
  Scan ID:         %s
  Classification:  %s
  Date:            %s
  Prepared by:     %s
  Company:         %s

================================================================================
                    CONFIDENTIAL - %s
================================================================================`,
		g.meta.Target,
		g.meta.ScanID,
		g.meta.Classification,
		g.meta.StartTime.Format("January 2, 2006"),
		g.meta.Tester,
		g.meta.CompanyName,
		g.meta.Classification,
	)
}

func (g *Generator) tableOfContents() string {
	return `--------------------------------------------------------------------------------
                        TABLE OF CONTENTS
--------------------------------------------------------------------------------

  1. Executive Summary
  2. Methodology
  3. Findings Summary
  4. Detailed Findings
  5. Remediation Roadmap
  6. Appendix

--------------------------------------------------------------------------------`
}

func (g *Generator) executiveSummary() string {
	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, f := range g.findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}

	return fmt.Sprintf(`--------------------------------------------------------------------------------
  1. EXECUTIVE SUMMARY
--------------------------------------------------------------------------------

  Engagement Overview
  -------------------
  Target:          %s
  Duration:        %s
  Total Findings:  %d

  Risk Distribution
  -----------------
  Critical:  %d
  High:      %d
  Medium:    %d
  Low:       %d

  Overall Risk Rating: %s

  Summary
  -------
  %s

  Key Recommendations
  -------------------
  1. Address all Critical findings immediately
  2. Remediate High findings within 30 days
  3. Review and fix Medium findings within 90 days
  4. Monitor Low findings for trend analysis`,
		g.meta.Target,
		g.meta.Duration.Round(time.Minute),
		len(g.findings),
		critical,
		high,
		medium,
		low,
		g.overallRisk(critical, high, medium, low),
		g.summary,
	)
}

func (g *Generator) methodology() string {
	return `--------------------------------------------------------------------------------
  2. METHODOLOGY
--------------------------------------------------------------------------------

  Testing Approach
  ----------------
  This assessment follows industry-standard methodologies including:
  - OWASP Testing Guide v4
  - PTES (Penetration Testing Execution Standard)
  - NIST SP 800-115
  - MITRE ATT&CK Framework

  Phases Executed
  ---------------
  1. Reconnaissance & Information Gathering
  2. Threat Modeling & Attack Surface Mapping
  3. Vulnerability Analysis
  4. Business Logic Testing (BOLA, IDOR, Auth)
  5. Exploitation & Proof of Concept
  6. Post-Exploitation & Lateral Movement
  7. Reporting & Remediation Guidance

  Tools & Techniques
  ------------------
  - AI-driven autonomous testing engine
  - Manual verification and exploit validation
  - Business logic workflow analysis
  - Multi-role authorization testing
  - API security assessment (REST, GraphQL)
  - Authentication & session management testing

--------------------------------------------------------------------------------`
}

func (g *Generator) findingsSummary() string {
	var sb strings.Builder
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("  3. FINDINGS SUMMARY\n")
	sb.WriteString("--------------------------------------------------------------------------------\n\n")
	sb.WriteString(fmt.Sprintf("  %-6s  %-40s  %-8s  %-6s\n", "ID", "Title", "Severity", "CVSS"))
	sb.WriteString("  " + strings.Repeat("-", 80) + "\n")

	for _, f := range g.findings {
		title := f.Title
		if len(title) > 40 {
			title = title[:37] + "..."
		}
		sb.WriteString(fmt.Sprintf("  %-6s  %-40s  %-8s  %.1f\n", f.ID, title, strings.ToUpper(f.Severity), f.CVSS))
	}

	sb.WriteString("\n")
	return sb.String()
}

func (g *Generator) detailedFindings() string {
	var sb strings.Builder
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("  4. DETAILED FINDINGS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n\n")

	for i, f := range g.findings {
		sb.WriteString(fmt.Sprintf(`  [%s] %s
  Severity:    %s (CVSS %.1f)
  MITRE:       %s
  Endpoint:    %s %s
  Timestamp:   %s

  Description
  -----------
  %s

  Proof of Concept
  ----------------
  %s

  Impact
  ------
  %s

  Remediation
  -----------
  %s
`,
			f.ID, f.Title,
			strings.ToUpper(f.Severity), f.CVSS,
			f.MITRE,
			f.Method, f.Endpoint,
			f.Timestamp.Format("2006-01-02 15:04:05"),
			f.Description,
			f.PoC,
			f.Impact,
			f.Remediation,
		))

		if len(f.Evidence) > 0 {
			sb.WriteString("  Evidence\n")
			sb.WriteString("  --------\n")
			for k, v := range f.Evidence {
				sb.WriteString(fmt.Sprintf("    %s: %s\n", k, v))
			}
			sb.WriteString("\n")
		}

		if i < len(g.findings)-1 {
			sb.WriteString("  " + strings.Repeat("-", 76) + "\n\n")
		}
	}

	return sb.String()
}

func (g *Generator) remediationRoadmap() string {
	var sb strings.Builder
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("  5. REMEDIATION ROADMAP\n")
	sb.WriteString("--------------------------------------------------------------------------------\n\n")

	sb.WriteString("  Immediate (0-7 days)\n")
	sb.WriteString("  --------------------\n")
	for _, f := range g.findings {
		if f.Severity == "critical" {
			sb.WriteString(fmt.Sprintf("  [ ] %s - %s\n", f.ID, f.Title))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("  Short-term (7-30 days)\n")
	sb.WriteString("  ----------------------\n")
	for _, f := range g.findings {
		if f.Severity == "high" {
			sb.WriteString(fmt.Sprintf("  [ ] %s - %s\n", f.ID, f.Title))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("  Medium-term (30-90 days)\n")
	sb.WriteString("  ------------------------\n")
	for _, f := range g.findings {
		if f.Severity == "medium" {
			sb.WriteString(fmt.Sprintf("  [ ] %s - %s\n", f.ID, f.Title))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("  Long-term (90+ days)\n")
	sb.WriteString("  --------------------\n")
	for _, f := range g.findings {
		if f.Severity == "low" {
			sb.WriteString(fmt.Sprintf("  [ ] %s - %s\n", f.ID, f.Title))
		}
	}
	sb.WriteString("\n")

	return sb.String()
}

func (g *Generator) appendix() string {
	return fmt.Sprintf(`--------------------------------------------------------------------------------
  6. APPENDIX
--------------------------------------------------------------------------------

  A. Scan Configuration
  ---------------------
  Target:          %s
  Start Time:      %s
  End Time:        %s
  Duration:        %s

  B. Compliance Mapping
  ---------------------
  This report supports compliance requirements for:
  - PCI-DSS Requirement 11.3 (Penetration Testing)
  - SOC 2 CC7.1 (System Monitoring)
  - ISO 27001 A.12.6.1 (Technical Vulnerability Management)
  - HIPAA 164.308(a)(8) (Evaluation)
  - NIST CSF DE.CM (Security Continuous Monitoring)

  C. MITRE ATT&CK Techniques Tested
  ----------------------------------
  T1190 - Exploit Public-Facing Application
  T1078 - Valid Accounts
  T1110 - Brute Force
  T1190 - Business Logic Flaws

  D. Report Version History
  -------------------------
  Version 1.0 - Initial Report - %s

================================================================================
                    END OF REPORT
================================================================================
`,
		g.meta.Target,
		g.meta.StartTime.Format("2006-01-02 15:04:05"),
		g.meta.EndTime.Format("2006-01-02 15:04:05"),
		g.meta.Duration.Round(time.Minute),
		time.Now().Format("2006-01-02"),
	)
}

func (g *Generator) overallRisk(critical, high, medium, low int) string {
	if critical > 0 {
		return "CRITICAL"
	}
	if high > 0 {
		return "HIGH"
	}
	if medium > 0 {
		return "MEDIUM"
	}
	if low > 0 {
		return "LOW"
	}
	return "INFORMATIONAL"
}
