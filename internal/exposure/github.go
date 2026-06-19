package exposure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type GitHubSecretScanner struct {
	token  string
	owner  string
	repo   string
	client *http.Client
}

func NewGitHubSecretScanner(token, owner, repo string) *GitHubSecretScanner {
	return &GitHubSecretScanner{
		token:  token,
		owner:  owner,
		repo:   repo,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GitHubSecretScanner) Name() string {
	return "github-secret-scanner"
}

func (g *GitHubSecretScanner) Interval() time.Duration {
	return 6 * time.Hour
}

type gitHubSecretAlert struct {
	ID         int    `json:"id"`
	SecretType string `json:"secret_type"`
	Secret     string `json:"secret"`
	CreatedAt  string `json:"created_at"`
	Validity   string `json:"validity"`
	PushDate   string `json:"push_date"`
}

type gitHubSecretResponse struct {
	TotalCount int                 `json:"total_count"`
	Alerts     []gitHubSecretAlert `json:"alerts"`
}

func (g *GitHubSecretScanner) Run() ([]ExposureFinding, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/secret-scanning/alerts", g.owner, g.repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("github request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api status: %d", resp.StatusCode)
	}

	var result gitHubSecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("github decode: %w", err)
	}

	var findings []ExposureFinding
	for _, alert := range result.Alerts {
		sev := SevHigh
		if alert.Validity == "expired" {
			sev = SevMedium
		}

		findings = append(findings, ExposureFinding{
			ID:          fmt.Sprintf("gh-secret-%d", alert.ID),
			Type:        ExposureGitHubSecret,
			Severity:    sev,
			Title:       fmt.Sprintf("GitHub Secret Exposed: %s", alert.SecretType),
			Description: fmt.Sprintf("Secret type %s exposed in %s/%s", alert.SecretType, g.owner, g.repo),
			Source:      fmt.Sprintf("github.com/%s/%s", g.owner, g.repo),
			Target:      fmt.Sprintf("%s/%s", g.owner, g.repo),
			Details: map[string]string{
				"secret_type": alert.SecretType,
				"push_date":   alert.PushDate,
				"validity":    alert.Validity,
				"alert_id":    fmt.Sprintf("%d", alert.ID),
			},
			Discovered:  time.Now(),
			Status:      "open",
			Remediation: "Rotate the exposed secret immediately and remove it from the repository history.",
		})
	}

	return findings, nil
}

type PublicGitHubScanner struct {
	client *http.Client
	target string
}

func NewPublicGitHubScanner(target string) *PublicGitHubScanner {
	return &PublicGitHubScanner{
		client: &http.Client{Timeout: 30 * time.Second},
		target: target,
	}
}

func (p *PublicGitHubScanner) Name() string {
	return "public-github-scanner"
}

func (p *PublicGitHubScanner) Interval() time.Duration {
	return 24 * time.Hour
}

func (p *PublicGitHubScanner) Run() ([]ExposureFinding, error) {
	url := fmt.Sprintf("https://api.github.com/search/code?q=%s+in:file", p.target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("search request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search api: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		TotalCount int `json:"total_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("search decode: %w", err)
	}

	if result.TotalCount > 0 {
		return []ExposureFinding{{
			ID:          fmt.Sprintf("pub-gh-%s", p.target),
			Type:        ExposureCredentialLeak,
			Severity:    SevHigh,
			Title:       "Public GitHub Exposure",
			Description: fmt.Sprintf("Target '%s' found in %d public GitHub code results", p.target, result.TotalCount),
			Source:      "GitHub Code Search",
			Target:      p.target,
			Details:     map[string]string{"match_count": fmt.Sprintf("%d", result.TotalCount)},
			Discovered:  time.Now(),
			Status:      "open",
		}}, nil
	}

	return nil, nil
}
