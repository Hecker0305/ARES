package exposure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type HaveIBeenPwned struct {
	apiKey string
	client *http.Client
	domain string
}

func NewHaveIBeenPwned(apiKey, domain string) *HaveIBeenPwned {
	return &HaveIBeenPwned{
		apiKey: apiKey,
		domain: domain,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (h *HaveIBeenPwned) Name() string {
	return "hibp-credential-monitor"
}

func (h *HaveIBeenPwned) Interval() time.Duration {
	return 24 * time.Hour
}

type hibpBreach struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	PwnCount     int      `json:"PwnCount"`
	Description  string   `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsFabricated bool     `json:"IsFabricated"`
	IsSensitive  bool     `json:"IsSensitive"`
	IsActive     bool     `json:"IsActive"`
	IsRetired    bool     `json:"IsRetired"`
	LogoPath     string   `json:"LogoPath"`
	AddedDate    string   `json:"AddedDate"`
	ModifiedDate string   `json:"ModifiedDate"`
}

func (h *HaveIBeenPwned) Run() ([]ExposureFinding, error) {
	u := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breaches?domain=%s", url.QueryEscape(h.domain))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("hibp request: %w", err)
	}
	req.Header.Set("hibp-api-key", h.apiKey)
	req.Header.Set("User-Agent", "Ares-Engine/2.0")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hibp api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hibp status: %d", resp.StatusCode)
	}

	var breaches []hibpBreach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, fmt.Errorf("hibp decode: %w", err)
	}

	var findings []ExposureFinding
	for _, b := range breaches {
		sev := SevHigh
		if b.IsSensitive {
			sev = SevCritical
		}

		findings = append(findings, ExposureFinding{
			ID:          fmt.Sprintf("hibp-%s", b.Name),
			Type:        ExposureCredentialLeak,
			Severity:    sev,
			Title:       fmt.Sprintf("Credential Breach: %s", b.Title),
			Description: truncateText(b.Description, 500),
			Source:      "Have I Been Pwned",
			Target:      h.domain,
			Details: map[string]string{
				"breach_name":  b.Name,
				"breach_date":  b.BreachDate,
				"pwn_count":    fmt.Sprintf("%d", b.PwnCount),
				"data_classes": fmt.Sprintf("%v", b.DataClasses),
				"is_verified":  fmt.Sprintf("%t", b.IsVerified),
				"is_sensitive": fmt.Sprintf("%t", b.IsSensitive),
			},
			Discovered:  time.Now(),
			Status:      "open",
			Remediation: "Force password resets for all affected accounts and enable MFA.",
		})
	}

	return findings, nil
}

type CredentialLeakDB struct {
	client  *http.Client
	sources []string
}

func NewCredentialLeakDB() *CredentialLeakDB {
	return &CredentialLeakDB{
		client:  &http.Client{Timeout: 15 * time.Second},
		sources: []string{},
	}
}

func (c *CredentialLeakDB) Name() string {
	return "credential-leak-db"
}

func (c *CredentialLeakDB) Interval() time.Duration {
	return 12 * time.Hour
}

func (c *CredentialLeakDB) Run() ([]ExposureFinding, error) {
	return nil, nil
}

func truncateText(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
