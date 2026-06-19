package exposure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CertificateMonitor struct {
	client  *http.Client
	domains []string
}

func NewCertificateMonitor(domains []string) *CertificateMonitor {
	return &CertificateMonitor{
		client:  &http.Client{Timeout: 30 * time.Second},
		domains: domains,
	}
}

func (c *CertificateMonitor) Name() string {
	return "certificate-monitor"
}

func (c *CertificateMonitor) Interval() time.Duration {
	return 24 * time.Hour
}

type crtShEntry struct {
	ID        int    `json:"id"`
	NameValue string `json:"name_value"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Issuer    string `json:"issuer_name"`
}

func (c *CertificateMonitor) Run() ([]ExposureFinding, error) {
	var findings []ExposureFinding

	for _, domain := range c.domains {
		domainFindings, err := c.checkDomain(domain)
		if err != nil {
			continue
		}
		findings = append(findings, domainFindings...)
	}

	return findings, nil
}

func (c *CertificateMonitor) checkDomain(domain string) ([]ExposureFinding, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	req.Header.Set("User-Agent", "Ares-Engine/2.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh status: %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh decode: %w", err)
	}

	var findings []ExposureFinding
	now := time.Now()

	seenCerts := make(map[string]bool)
	for _, entry := range entries {
		notAfter, err := time.Parse("2006-01-02T15:04:05", entry.NotAfter)
		if err != nil {
			continue
		}

		certKey := fmt.Sprintf("%s-%s", entry.NameValue, entry.NotAfter)
		if seenCerts[certKey] {
			continue
		}
		seenCerts[certKey] = true

		daysUntilExpiry := int(notAfter.Sub(now).Hours() / 24)

		if daysUntilExpiry < 0 {
			findings = append(findings, ExposureFinding{
				ID:          fmt.Sprintf("cert-expired-%s-%d", domain, entry.ID),
				Type:        ExposureCertificate,
				Severity:    SevCritical,
				Title:       fmt.Sprintf("SSL Certificate Expired: %s", entry.NameValue),
				Description: fmt.Sprintf("Certificate for %s expired on %s", entry.NameValue, notAfter.Format("2006-01-02")),
				Source:      "crt.sh",
				Target:      domain,
				Details: map[string]string{
					"subject":      entry.NameValue,
					"not_after":    notAfter.Format(time.RFC3339),
					"issuer":       entry.Issuer,
					"days_expired": fmt.Sprintf("%d", -daysUntilExpiry),
				},
				Discovered:  now,
				Status:      "open",
				Remediation: "Renew the SSL/TLS certificate immediately to prevent service disruption.",
			})
		} else if daysUntilExpiry <= 14 {
			findings = append(findings, ExposureFinding{
				ID:          fmt.Sprintf("cert-expiring-%s-%d", domain, entry.ID),
				Type:        ExposureCertificate,
				Severity:    SevHigh,
				Title:       fmt.Sprintf("SSL Certificate Expiring Soon: %s", entry.NameValue),
				Description: fmt.Sprintf("Certificate for %s expires in %d days on %s", entry.NameValue, daysUntilExpiry, notAfter.Format("2006-01-02")),
				Source:      "crt.sh",
				Target:      domain,
				Details: map[string]string{
					"subject":        entry.NameValue,
					"not_after":      notAfter.Format(time.RFC3339),
					"issuer":         entry.Issuer,
					"days_remaining": fmt.Sprintf("%d", daysUntilExpiry),
				},
				Discovered:  now,
				Status:      "open",
				Remediation: "Renew the certificate before it expires to avoid service disruption.",
			})
		}

		issuedDate, err := time.Parse("2006-01-02T15:04:05", entry.NotBefore)
		if err == nil {
			certAge := int(now.Sub(issuedDate).Hours() / 24)
			if certAge > 365 {
				findings = append(findings, ExposureFinding{
					ID:          fmt.Sprintf("cert-old-%s-%d", domain, entry.ID),
					Type:        ExposureCertificate,
					Severity:    SevLow,
					Title:       fmt.Sprintf("Aged SSL Certificate: %s", entry.NameValue),
					Description: fmt.Sprintf("Certificate for %s is %d days old", entry.NameValue, certAge),
					Source:      "crt.sh",
					Target:      domain,
					Details: map[string]string{
						"subject":       entry.NameValue,
						"not_before":    issuedDate.Format(time.RFC3339),
						"cert_age_days": fmt.Sprintf("%d", certAge),
					},
					Discovered:  now,
					Status:      "open",
					Remediation: "Consider rotating the certificate as a security best practice.",
				})
			}
		}
	}

	return findings, nil
}
