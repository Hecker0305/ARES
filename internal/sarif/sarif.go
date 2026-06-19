package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri,omitempty"`
	Organization   string `json:"organization,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription *Message        `json:"shortDescription,omitempty"`
	FullDescription  *Message        `json:"fullDescription,omitempty"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       *RuleProperties `json:"properties,omitempty"`
}

type RuleProperties struct {
	Tags      []string `json:"tags,omitempty"`
	Precision string   `json:"precision,omitempty"`
	Problem   string   `json:"problem,omitempty"`
}

type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex,omitempty"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations,omitempty"`
	RelatedLocations    []Location        `json:"relatedLocations,omitempty"`
	Stacks              []Stack           `json:"stacks,omitempty"`
	CodeFlows           []CodeFlow        `json:"codeFlows,omitempty"`
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          *ResultProperties `json:"properties,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
	Message          *Message          `json:"message,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
}

type ArtifactLocation struct {
	URI         string   `json:"uri"`
	URIBaseID   string   `json:"uriBaseId,omitempty"`
	Description *Message `json:"description,omitempty"`
}

type Region struct {
	StartLine   int      `json:"startLine,omitempty"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	CharOffset  int      `json:"charOffset,omitempty"`
	CharLength  int      `json:"charLength,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

type Snippet struct {
	Text string `json:"text"`
}

type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

type Stack struct {
	Message *Message     `json:"message,omitempty"`
	Frames  []StackFrame `json:"frames"`
}

type StackFrame struct {
	Location *Location `json:"location,omitempty"`
	Message  *Message  `json:"message,omitempty"`
}

type CodeFlow struct {
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

type ThreadFlow struct {
	Locations []ThreadFlowLocation `json:"locations"`
}

type ThreadFlowLocation struct {
	Location Location `json:"location"`
}

type ResultProperties struct {
	Severity    string   `json:"severity,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Timestamp   string   `json:"timestamp,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type FindingClassification string

const (
	ClassificationVulnerability FindingClassification = "vulnerability"
	ClassificationMisconfig     FindingClassification = "misconfiguration"
	ClassificationInfo          FindingClassification = "informational"
)

type Finding struct {
	ID             string
	Type           string
	Severity       string
	Target         string
	Payload        string
	Evidence       string
	Confidence     float64
	Remediation    string
	CWE            string
	CVE            string
	Timestamp      time.Time
	FilePath       string
	Line           int
	Classification FindingClassification
}

type Generator struct {
	toolName    string
	toolVersion string
	findings    []Finding
}

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|auth|credential)\s*[:=]\s*["']?[\w@#$%^&*]+["']?`),
	regexp.MustCompile(`(?i)(?:bearer|basic)\s+[A-Za-z0-9+/=]{10,}`),
	regexp.MustCompile(`(?:\$where|javascript:|eval\(|exec\(|system\(|popen\()([^)]*)`),
	regexp.MustCompile(`(?i)(?:union\s+select|drop\s+table|;\s*(?:delete|insert|update)\s)`),
}

func NewGenerator(toolName, toolVersion string) *Generator {
	return &Generator{
		toolName:    toolName,
		toolVersion: toolVersion,
	}
}

func (g *Generator) AddFinding(f Finding) {
	g.findings = append(g.findings, f)
}

func (g *Generator) AddFindings(findings []Finding) {
	g.findings = append(g.findings, findings...)
}

func (g *Generator) Generate() ([]byte, error) {
	report := Report{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []Run{g.buildRun()},
	}

	return json.MarshalIndent(report, "", "  ")
}

func (g *Generator) buildRun() Run {
	rules := g.buildRules()
	results := g.buildResults()

	return Run{
		Tool: Tool{
			Driver: Driver{
				Name:           g.toolName,
				Version:        g.toolVersion,
				InformationURI: "https://github.com/ares/engine",
				Organization:   "ARES Security",
				Rules:          rules,
			},
		},
		Results: results,
	}
}

func (g *Generator) buildRules() []Rule {
	ruleMap := make(map[string]Rule)

	for _, f := range g.findings {
		if _, exists := ruleMap[f.Type]; !exists {
			ruleMap[f.Type] = Rule{
				ID:   f.Type,
				Name: humanReadableName(f.Type),
				ShortDescription: &Message{
					Text: fmt.Sprintf("%s vulnerability detected", f.Type),
				},
				FullDescription: &Message{
					Text: fmt.Sprintf("A %s vulnerability was identified during automated security testing. This finding requires immediate review and remediation.", f.Type),
				},
				HelpURI: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(f.CWE, "CWE-")),
				Properties: &RuleProperties{
					Tags:      []string{"security", "vulnerability", f.Severity},
					Precision: "high",
				},
			}
		}
	}

	var rules []Rule
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}
	return rules
}

func (g *Generator) buildResults() []Result {
	var results []Result

	for i, f := range g.findings {
		sanitizedEvidence := sanitizePayload(f.Evidence)
		sanitizedPayload := sanitizePayload(f.Payload)

		result := Result{
			RuleID: f.Type,
			Level:  severityToLevel(f.Severity),
			Message: Message{
				Text: fmt.Sprintf("%s: %s (Severity: %s, Confidence: %.0f%%)", f.Type, sanitizedEvidence, f.Severity, f.Confidence*100),
			},
			Locations: []Location{},
			Properties: &ResultProperties{
				Severity:    f.Severity,
				CWE:         f.CWE,
				CVE:         f.CVE,
				Confidence:  f.Confidence,
				Evidence:    sanitizedEvidence,
				Remediation: f.Remediation,
				Timestamp:   f.Timestamp.Format(time.RFC3339),
				Tags:        []string{f.Severity, f.Type, string(f.Classification)},
			},
		}

		if f.FilePath != "" {
			loc := Location{
				PhysicalLocation: &PhysicalLocation{
					ArtifactLocation: &ArtifactLocation{
						URI: f.FilePath,
					},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &Region{
					StartLine: f.Line,
				}
			}
			result.Locations = append(result.Locations, loc)
		}

		if f.Target != "" {
			result.Locations = append(result.Locations, Location{
				LogicalLocations: []LogicalLocation{
					{
						Name: f.Target,
						Kind: "url",
					},
				},
			})
		}

		if sanitizedPayload != "" {
			result.Fingerprints = map[string]string{
				"payloadHash": fingerprint(sanitizedPayload),
			}
		}

		result.RuleIndex = i
		results = append(results, result)
	}

	return results
}

func sanitizePayload(input string) string {
	sanitized := input
	for _, pattern := range sensitivePatterns {
		sanitized = pattern.ReplaceAllString(sanitized, "[REDACTED: sensitive data]")
	}
	if len(sanitized) > 1000 {
		sanitized = sanitized[:1000] + "...[truncated]"
	}
	return sanitized
}

func severityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	case "info":
		return "none"
	default:
		return "warning"
	}
}

func humanReadableName(vulnType string) string {
	names := map[string]string{
		"sqli":                "SQL Injection",
		"xss":                 "Cross-Site Scripting",
		"ssrf":                "Server-Side Request Forgery",
		"rce":                 "Remote Code Execution",
		"idor":                "Insecure Direct Object Reference",
		"csrf":                "Cross-Site Request Forgery",
		"lfi":                 "Local File Inclusion",
		"rfi":                 "Remote File Inclusion",
		"xxe":                 "XML External Entity",
		"ssti":                "Server-Side Template Injection",
		"nosqli":              "NoSQL Injection",
		"deserial":            "Insecure Deserialization",
		"traversal":           "Path Traversal",
		"oauth":               "OAuth/OIDC Misconfiguration",
		"prototype_pollution": "Prototype Pollution",
	}

	if name, ok := names[vulnType]; ok {
		return name
	}

	parts := strings.Split(vulnType, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ")
}

func fingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
