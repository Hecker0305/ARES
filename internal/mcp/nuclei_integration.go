package mcp

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type NucleiIntegration struct {
	binaryPath    string
	templatesPath string
}

type NucleiResult struct {
	TemplateID   string `json:"template-id"`
	TemplatePath string `json:"template-path"`
	Info         struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference,omitempty"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results,omitempty"`
	Request          string   `json:"request,omitempty"`
	Response         string   `json:"response,omitempty"`
	Timestamp        string   `json:"timestamp,omitempty"`
	CurlCommand      string   `json:"curl-command,omitempty"`
}

type NucleiScanOptions struct {
	Target          string   `json:"target"`
	Templates       []string `json:"templates,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	ExcludeTags     []string `json:"exclude_tags,omitempty"`
	RateLimit       int      `json:"rate_limit,omitempty"`
	Concurrency     int      `json:"concurrency,omitempty"`
	Timeout         int      `json:"timeout,omitempty"`
	Retries         int      `json:"retries,omitempty"`
	FollowRedirects bool     `json:"follow_redirects,omitempty"`
}

func NewNucleiIntegration(binaryPath, templatesPath string) *NucleiIntegration {
	return &NucleiIntegration{
		binaryPath:    binaryPath,
		templatesPath: templatesPath,
	}
}

func (n *NucleiIntegration) RunScan(opts NucleiScanOptions) ([]NucleiResult, error) {
	args := []string{
		"-target", opts.Target,
		"-json",
		"-silent",
	}

	if opts.Templates != nil && len(opts.Templates) > 0 {
		args = append(args, "-t")
		args = append(args, opts.Templates...)
	} else if n.templatesPath != "" {
		args = append(args, "-t", n.templatesPath)
	}

	if opts.Severity != "" {
		args = append(args, "-severity", opts.Severity)
	}
	if opts.Tags != nil && len(opts.Tags) > 0 {
		args = append(args, "-tags", strings.Join(opts.Tags, ","))
	}
	if opts.ExcludeTags != nil && len(opts.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(opts.ExcludeTags, ","))
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", opts.RateLimit))
	}
	if opts.Concurrency > 0 {
		args = append(args, "-concurrency", fmt.Sprintf("%d", opts.Concurrency))
	}
	if opts.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", opts.Timeout))
	}
	if opts.Retries > 0 {
		args = append(args, "-retries", fmt.Sprintf("%d", opts.Retries))
	}
	if opts.FollowRedirects {
		args = append(args, "-follow-redirects")
	}

	cmd := exec.Command(n.binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("nuclei scan failed: %w", err)
		}
	}

	return n.parseResults(string(output))
}

func (n *NucleiIntegration) RunScanWithTemplates(target string, templates []string) ([]NucleiResult, error) {
	return n.RunScan(NucleiScanOptions{
		Target:    target,
		Templates: templates,
	})
}

func (n *NucleiIntegration) RunScanBySeverity(target, severity string) ([]NucleiResult, error) {
	return n.RunScan(NucleiScanOptions{
		Target:   target,
		Severity: severity,
	})
}

func (n *NucleiIntegration) parseResults(output string) ([]NucleiResult, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var results []NucleiResult

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

func (n *NucleiIntegration) FilterBySeverity(results []NucleiResult, severities ...string) []NucleiResult {
	sevMap := make(map[string]bool)
	for _, s := range severities {
		sevMap[strings.ToLower(s)] = true
	}

	var filtered []NucleiResult
	for _, r := range results {
		if sevMap[strings.ToLower(r.Info.Severity)] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (n *NucleiIntegration) FilterByTags(results []NucleiResult, tags ...string) []NucleiResult {
	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = true
	}

	var filtered []NucleiResult
	for _, r := range results {
		for _, t := range r.Info.Tags {
			if tagSet[strings.ToLower(t)] {
				filtered = append(filtered, r)
				break
			}
		}
	}
	return filtered
}

func (n *NucleiIntegration) Summary(results []NucleiResult) map[string]int {
	summary := make(map[string]int)
	for _, r := range results {
		sev := strings.ToLower(r.Info.Severity)
		if sev == "" {
			sev = "unknown"
		}
		summary[sev]++
	}
	return summary
}

func (n *NucleiIntegration) ListTemplates() ([]string, error) {
	if n.templatesPath == "" {
		return nil, fmt.Errorf("templates path not configured")
	}

	cmd := exec.Command(n.binaryPath, "-tl", "-t", n.templatesPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nuclei list templates failed: %w", err)
	}

	templates := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result []string
	for _, t := range templates {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result, nil
}

func (n *NucleiIntegration) UpdateTemplates() error {
	cmd := exec.Command(n.binaryPath, "-update-templates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nuclei update templates failed: %s", string(output))
	}
	return nil
}

func (n *NucleiIntegration) GetTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "nuclei_scan",
			Description: "Run a nuclei scan against a target",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"target":   {Type: "string", Description: "Target URL or domain"},
					"severity": {Type: "string", Description: "Filter by severity (info/low/medium/high/critical)"},
					"tags":     {Type: "string", Description: "Comma-separated template tags"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "nuclei_scan_templates",
			Description: "Run nuclei with specific templates",
			InputSchema: ToolInputSchema{
				Type: "object",
				Properties: map[string]ToolProperty{
					"target":    {Type: "string", Description: "Target URL or domain"},
					"templates": {Type: "array", Description: "Template paths or IDs"},
				},
				Required: []string{"target", "templates"},
			},
		},
		{
			Name:        "nuclei_list_templates",
			Description: "List available nuclei templates",
			InputSchema: ToolInputSchema{
				Type:       "object",
				Properties: map[string]ToolProperty{},
			},
		},
		{
			Name:        "nuclei_update_templates",
			Description: "Update nuclei templates to latest version",
			InputSchema: ToolInputSchema{
				Type:       "object",
				Properties: map[string]ToolProperty{},
			},
		},
	}
}
