package explain

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ares/engine/internal/chainer"
	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/verifier"
)

type DataClassification int

const (
	DataPublic DataClassification = iota
	DataInternal
	DataConfidential
	DataRestricted
)

type ExploitNarrative struct {
	FindingID      string                   `json:"finding_id"`
	Title          string                   `json:"title"`
	Severity       string                   `json:"severity"`
	Target         string                   `json:"target"`
	ReasoningChain []ReasoningStep          `json:"reasoning_chain"`
	AttackPath     string                   `json:"attack_path"`
	BusinessImpact string                   `json:"business_impact"`
	Confidence     float64                  `json:"confidence"`
	Evidence       string                   `json:"evidence"`
	Reproducible   bool                     `json:"reproducible"`
	Remediation    string                   `json:"remediation"`
	CreatedAt      time.Time                `json:"created_at"`
	Classification DataClassification       `json:"classification"`
	ChainCVSS      *chainer.ChainCVSSReport `json:"chain_cvss,omitempty"`
}

type ReasoningStep struct {
	Step        int     `json:"step"`
	Observation string  `json:"observation"`
	Conclusion  string  `json:"conclusion"`
	Confidence  float64 `json:"confidence"`
}

type Generator struct {
	graph            *graph.AttackGraph
	chainer          *chainer.Chainer
	verifier         *verifier.Engine
	allowExternalLLM bool
}

func New(g *graph.AttackGraph, c *chainer.Chainer, v *verifier.Engine) *Generator {
	return &Generator{
		graph:            g,
		chainer:          c,
		verifier:         v,
		allowExternalLLM: false,
	}
}

func (gen *Generator) SetAllowExternalLLM(allow bool) {
	gen.allowExternalLLM = allow
}

var (
	ipPattern            = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	emailPattern         = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	credPattern          = regexp.MustCompile(`(?i)(password|secret|token|api_key|apikey|access_key|private_key)\s*[:=]\s*\S+`)
	awsKeyPattern        = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	genericSecretPattern = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9\-._~+/]+=*)`)
)

func RedactSensitiveData(input string) string {
	result := input
	result = ipPattern.ReplaceAllString(result, "[REDACTED_IP]")
	result = emailPattern.ReplaceAllString(result, "[REDACTED_EMAIL]")
	result = credPattern.ReplaceAllString(result, "[REDACTED_CREDENTIAL]")
	result = awsKeyPattern.ReplaceAllString(result, "[REDACTED_AWS_KEY]")
	result = genericSecretPattern.ReplaceAllString(result, "[REDACTED_TOKEN]")
	return result
}

func ClassifyData(narrative ExploitNarrative) DataClassification {
	if strings.Contains(strings.ToLower(narrative.Evidence), "password") ||
		strings.Contains(strings.ToLower(narrative.Evidence), "credential") ||
		strings.Contains(strings.ToLower(narrative.Evidence), "token") ||
		strings.Contains(strings.ToLower(narrative.Evidence), "secret") {
		return DataRestricted
	}
	if narrative.Severity == "Critical" {
		return DataConfidential
	}
	if narrative.Severity == "High" {
		return DataInternal
	}
	return DataPublic
}

func (gen *Generator) GenerateNarrative(vulnType, target, payload, evidence string, confidence float64) ExploitNarrative {
	steps := gen.buildReasoningChain(vulnType, target, payload)
	attackPath := gen.buildAttackPath(vulnType)
	impact := gen.describeBusinessImpact(vulnType)
	remediation := gen.suggestRemediation(vulnType)

	severity := gen.classifySeverity(vulnType)
	if confidence < 0.3 {
		severity = "Low"
	} else if confidence < 0.6 && severity == "Critical" {
		severity = "High"
	}

	if gen.graph != nil {
		adjacentEdges := gen.graph.GetOutgoing(target)
		for _, edge := range adjacentEdges {
			node := gen.graph.GetNode(edge.TargetID)
			if node == nil {
				continue
			}
			if node.Type == graph.NodeVuln {
				steps = append(steps, ReasoningStep{
					Step:        len(steps) + 1,
					Observation: fmt.Sprintf("Related vulnerability: %s", node.Label),
					Conclusion:  "Potential attack chain exists",
					Confidence:  0.7,
				})
				if node.Score > 0.8 && severity != "Critical" {
					severity = "Critical"
				}
			}
		}
	}

	if gen.verifier != nil {
		verHistory := gen.verifier.GetHistory()
		for _, vr := range verHistory {
			if vr.Verdict == verifier.VerdictConfirmed && strings.Contains(vr.Evidence, target) {
				steps = append(steps, ReasoningStep{
					Step:        len(steps) + 1,
					Observation: fmt.Sprintf("Verified via %s (confidence: %.0f%%)", vr.Method, vr.Confidence*100),
					Conclusion:  "Finding independently verified",
					Confidence:  vr.Confidence,
				})
			}
		}
	}

	narrative := ExploitNarrative{
		Title:          fmt.Sprintf("%s on %s", vulnType, target),
		Severity:       severity,
		Target:         target,
		ReasoningChain: steps,
		AttackPath:     attackPath,
		BusinessImpact: impact,
		Confidence:     confidence,
		Evidence:       evidence,
		Reproducible:   confidence >= 0.8,
		Remediation:    remediation,
		CreatedAt:      time.Now(),
	}
	narrative.Classification = ClassifyData(narrative)

	if gen.chainer != nil {
		for _, chain := range gen.chainer.HighValueChains(0.3) {
			for _, step := range chain.Steps {
				if step.Type == vulnType || strings.Contains(chain.Summary, vulnType) {
					r := gen.chainer.ProduceCVSSReport(chain)
					narrative.ChainCVSS = &r
					break
				}
			}
			if narrative.ChainCVSS != nil {
				break
			}
		}
	}

	return narrative
}

func (gen *Generator) buildReasoningChain(vulnType, target, payload string) []ReasoningStep {
	steps := []ReasoningStep{
		{
			Step:        1,
			Observation: fmt.Sprintf("Testing %s vulnerability on target %s", vulnType, target),
			Conclusion:  "Automated scanning detected potential vulnerability class",
			Confidence:  0.5,
		},
	}

	if payload != "" {
		steps = append(steps, ReasoningStep{
			Step:        2,
			Observation: fmt.Sprintf("Tested with payload: %s", truncate(payload, 50)),
			Conclusion:  "Payload was transmitted to target for verification",
			Confidence:  0.5,
		})
	}

	return steps
}

func (gen *Generator) buildAttackPath(vulnType string) string {
	chains := gen.chainer.HighValueChains(0.5)
	for _, chain := range chains {
		for _, step := range chain.Steps {
			if step.Type == vulnType {
				return chain.Summary
			}
		}
	}

	paths := map[string]string{
		"sqli": fmt.Sprintf("SQLi -> Database Access -> Credential Extraction -> Lateral Movement -> Data Exfiltration"),
		"xss":  fmt.Sprintf("XSS -> Session Hijacking -> Admin Access -> PII Theft -> Privilege Escalation"),
		"ssrf": fmt.Sprintf("SSRF -> Metadata Service -> Cloud Credentials -> Resource Compromise"),
		"lfi":  fmt.Sprintf("LFI -> Configuration Files -> Credentials -> RCE"),
		"rce":  fmt.Sprintf("RCE -> Full Host Compromise -> Credential Dumping -> Lateral Movement"),
	}

	if path, ok := paths[vulnType]; ok {
		return path
	}
	return fmt.Sprintf("%s -> Privilege Escalation -> Impact Assessment", vulnType)
}

func (gen *Generator) describeBusinessImpact(vulnType string) string {
	impacts := map[string]string{
		"sqli": "Complete database compromise leading to PII theft, financial fraud, and regulatory penalties (GDPR: up to 4% of global revenue, CCPA: up to $7,500 per record)",
		"xss":  "Account takeover, session hijacking, malware distribution, and brand reputation damage affecting all application users",
		"ssrf": "Internal network compromise, cloud metadata exposure, and potential access to sensitive infrastructure components",
		"lfi":  "Sensitive file disclosure including application source code, configuration files, and credentials leading to further compromise",
		"rce":  "Complete system compromise by attacker, leading to ransomware deployment, data theft, or use as a pivot point",
		"idor": "Unauthorized access to other users' private data, leading to privacy violations and regulatory non-compliance",
	}
	if impact, ok := impacts[vulnType]; ok {
		return impact
	}
	return "Security vulnerability that could lead to data breach, system compromise, or service disruption"
}

func (gen *Generator) suggestRemediation(vulnType string) string {
	remediations := map[string]string{
		"sqli": "1. Use parameterized queries / prepared statements\n2. Apply strict input validation\n3. Use ORM frameworks\n4. Implement WAF rules\n5. Conduct code review",
		"xss":  "1. Implement Content Security Policy (CSP)\n2. Apply context-aware output encoding\n3. Use HTTP-only cookies\n4. Validate and sanitize all inputs\n5. Use trusted templating engines",
		"ssrf": "1. Implement URL allowlist\n2. Block private IP ranges\n3. Disable unnecessary URL schemes\n4. Use network segmentation\n5. Validate and sanitize redirect targets",
		"lfi":  "1. Use a whitelist of allowed files\n2. Disable unnecessary file inclusion\n3. Apply principle of least privilege\n4. Use database for file storage\n5. Implement input validation",
		"rce":  "1. Apply security patches immediately\n2. Remove unnecessary services\n3. Implement application allowlisting\n4. Run with least privilege\n5. Use runtime application self-protection",
	}
	if rem, ok := remediations[vulnType]; ok {
		return rem
	}
	return "1. Apply security patches\n2. Review and harden configuration\n3. Implement security monitoring\n4. Conduct penetration testing"
}

func (gen *Generator) classifySeverity(vulnType string) string {
	severities := map[string]string{
		"rce":           "Critical",
		"sqli":          "Critical",
		"ssrf":          "High",
		"lfi":           "High",
		"xss":           "Medium",
		"idor":          "Medium",
		"csrf":          "Medium",
		"open_redirect": "Low",
	}
	if s, ok := severities[vulnType]; ok {
		return s
	}
	return "Medium"
}

func (gen *Generator) FindingsSummary(findings []ExploitNarrative) string {
	var sb strings.Builder
	sb.WriteString("# EXPLOIT NARRATIVE SUMMARY\n\n")

	bySeverity := map[string][]string{}
	for _, f := range findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f.Title)
	}

	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		if items, ok := bySeverity[sev]; ok {
			sb.WriteString(fmt.Sprintf("## %s Severity (%d)\n", sev, len(items)))
			for _, item := range items {
				sb.WriteString(fmt.Sprintf("- %s\n", item))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (gen *Generator) FullReport(findings []ExploitNarrative) string {
	var sb strings.Builder
	sb.WriteString("# ARES EXPLOIT NARRATIVE REPORT\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("## Finding %d: %s\n\n", i+1, f.Title))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
		sb.WriteString(fmt.Sprintf("- **Target:** %s\n", f.Target))
		sb.WriteString(fmt.Sprintf("- **Confidence:** %.0f%%\n", f.Confidence*100))
		sb.WriteString(fmt.Sprintf("- **Reproducible:** %v\n", f.Reproducible))
		sb.WriteString(fmt.Sprintf("- **Classification:** %s\n\n", classificationLabel(f.Classification)))

		sb.WriteString("### Reasoning Chain\n\n")
		for _, step := range f.ReasoningChain {
			sb.WriteString(fmt.Sprintf("**Step %d:** %s\n", step.Step, step.Observation))
			sb.WriteString(fmt.Sprintf("-> %s (confidence: %.0f%%)\n\n", step.Conclusion, step.Confidence*100))
		}

		sb.WriteString("### Attack Path\n\n")
		sb.WriteString(fmt.Sprintf("%s\n\n", f.AttackPath))

		sb.WriteString("### Business Impact\n\n")
		sb.WriteString(fmt.Sprintf("%s\n\n", f.BusinessImpact))

		sb.WriteString("### Evidence\n\n")
		sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", truncate(RedactSensitiveData(f.Evidence), 500)))

		sb.WriteString("### Remediation\n\n")
		sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", f.Remediation))

		if f.ChainCVSS != nil {
			sb.WriteString("### Chain CVSS Score\n\n")
			sb.WriteString(fmt.Sprintf("- **Chain Score:** %.2f/10\n", f.ChainCVSS.ChainScore))
			sb.WriteString(fmt.Sprintf("- **Mean Step Score:** %.2f\n", f.ChainCVSS.MeanScore))
			if f.ChainCVSS.Vector != "" {
				sb.WriteString(fmt.Sprintf("- **CVSS Vector:** %s\n", f.ChainCVSS.Vector))
			}
			if f.ChainCVSS.LastStepScore > 0 {
				sb.WriteString(fmt.Sprintf("- **Last Step Score:** %.1f\n", f.ChainCVSS.LastStepScore))
			}
			sb.WriteString(fmt.Sprintf("- **Length Penalty:** %.2f\n", f.ChainCVSS.LengthPenalty))
			sb.WriteString(fmt.Sprintf("- **Diversity Penalty:** %.2f\n", f.ChainCVSS.DiversityPenalty))
			sb.WriteString("\n")
		}

		sb.WriteString("---\n\n")
	}

	return sb.String()
}

func (gen *Generator) PrepareForExternalLLM(narrative ExploitNarrative) string {
	if !gen.allowExternalLLM {
		return ""
	}

	safeNarrative := narrative
	safeNarrative.Evidence = RedactSensitiveData(narrative.Evidence)
	safeNarrative.Target = RedactSensitiveData(narrative.Target)
	for i := range safeNarrative.ReasoningChain {
		safeNarrative.ReasoningChain[i].Observation = RedactSensitiveData(safeNarrative.ReasoningChain[i].Observation)
		safeNarrative.ReasoningChain[i].Conclusion = RedactSensitiveData(safeNarrative.ReasoningChain[i].Conclusion)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Vulnerability: %s\n", safeNarrative.Title))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", safeNarrative.Severity))
	sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n", safeNarrative.Confidence*100))
	sb.WriteString(fmt.Sprintf("Attack Path: %s\n", safeNarrative.AttackPath))
	sb.WriteString(fmt.Sprintf("Business Impact: %s\n", safeNarrative.BusinessImpact))
	sb.WriteString(fmt.Sprintf("Evidence (redacted): %s\n", safeNarrative.Evidence))
	sb.WriteString(fmt.Sprintf("Remediation: %s\n", safeNarrative.Remediation))

	return sb.String()
}

func classificationLabel(c DataClassification) string {
	switch c {
	case DataPublic:
		return "Public"
	case DataInternal:
		return "Internal"
	case DataConfidential:
		return "Confidential"
	case DataRestricted:
		return "Restricted"
	default:
		return "Unknown"
	}
}

func truncate(s string, maxLen int) string {
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	return string(r[:maxLen]) + "..."
}
