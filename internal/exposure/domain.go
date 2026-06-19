package exposure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type DomainTakeoverMonitor struct {
	client  *http.Client
	domains []string
}

func NewDomainTakeoverMonitor(domains []string) *DomainTakeoverMonitor {
	return &DomainTakeoverMonitor{
		client:  &http.Client{Timeout: 30 * time.Second},
		domains: domains,
	}
}

func (d *DomainTakeoverMonitor) Name() string {
	return "domain-takeover-monitor"
}

func (d *DomainTakeoverMonitor) Interval() time.Duration {
	return 12 * time.Hour
}

var takeoverFingerprints = []struct {
	Service    string
	Indicators []string
}{
	{"AWS S3", []string{"NoSuchBucket", "The specified bucket does not exist", "404 Not Found"}},
	{"Azure", []string{"404 Not Found", "The resource you are looking for has been removed"}},
	{"GitHub Pages", []string{"There isn't a GitHub Pages site here"}},
	{"Heroku", []string{"No such app", "Heroku | No such app"}},
	{"Netlify", []string{"Not Found - Request ID:", "Page Not Found"}},
	{"CloudFront", []string{"BadRequest", "The request could not be satisfied"}},
	{"Shopify", []string{"Sorry, this shop is currently unavailable"}},
	{"Bitbucket", []string{"Repository not found"}},
	{"Tumblr", []string{"There's nothing here"}},
	{"WordPress", []string{"Domain mapping not found"}},
	{"Squarespace", []string{"No Such Site"}},
	{"Cargo", []string{"404: There isn't a Cargo site here"}},
	{"Fly.io", []string{"404 Not Found"}},
	{"Surge.sh", []string{"project not found"}},
	{"Pantheon", []string{"The gods are angry"}},
}

func (d *DomainTakeoverMonitor) Run() ([]ExposureFinding, error) {
	var findings []ExposureFinding

	for _, domain := range d.domains {
		subdomains := d.enumerateSubdomains(domain)
		for _, sub := range subdomains {
			finding := d.checkSubdomain(sub)
			if finding != nil {
				findings = append(findings, *finding)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	return findings, nil
}

func (d *DomainTakeoverMonitor) enumerateSubdomains(domain string) []string {
	var subdomains []string

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return subdomains
	}
	req.Header.Set("User-Agent", "Ares-Engine/2.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return subdomains
	}
	defer resp.Body.Close()

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return subdomains
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" && strings.HasSuffix(name, "."+domain) && !seen[name] {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains
}

func (d *DomainTakeoverMonitor) checkSubdomain(subdomain string) *ExposureFinding {
	url := fmt.Sprintf("https://%s", subdomain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Ares-Engine/2.0")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := strings.ToLower(string(buf[:n]))

	for _, fp := range takeoverFingerprints {
		for _, indicator := range fp.Indicators {
			if strings.Contains(body, strings.ToLower(indicator)) || resp.StatusCode == http.StatusNotFound {
				return &ExposureFinding{
					ID:          fmt.Sprintf("takeover-%s", subdomain),
					Type:        ExposureDomainTakeover,
					Severity:    SevCritical,
					Title:       fmt.Sprintf("Subdomain Takeover Risk: %s", subdomain),
					Description: fmt.Sprintf("Subdomain %s appears vulnerable to takeover via %s", subdomain, fp.Service),
					Source:      fmt.Sprintf("https://%s", subdomain),
					Target:      subdomain,
					Details: map[string]string{
						"service":     fp.Service,
						"status_code": fmt.Sprintf("%d", resp.StatusCode),
						"fingerprint": indicator,
					},
					Discovered:  time.Now(),
					Status:      "open",
					Remediation: fmt.Sprintf("Remove the DNS record pointing to %s or claim the resource on %s", fp.Service, fp.Service),
				}
			}
		}
	}

	return nil
}
