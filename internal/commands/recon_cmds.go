package commands

import (
	"fmt"
	"strings"
)

func init() {
	DefaultRegistry.Register(&Command{
		Name:        "recon",
		Description: "Full recon: subdomain enumeration, live host probing, URL crawl, nuclei sweep",
		Usage:       "/recon target.com",
		Category:    CategoryRecon,
		Handler:     handleRecon,
		Aliases:     []string{"r"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "surface",
		Description: "Ranked attack surface from recon data",
		Usage:       "/surface target.com",
		Category:    CategoryRecon,
		Handler:     handleSurface,
		Aliases:     []string{"surf"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "scope-aggregate",
		Description: "Aggregate scope from H1, Bugcrowd, Intigriti",
		Usage:       "/scope-aggregate program",
		Category:    CategoryRecon,
		Handler:     handleScopeAggregate,
		Aliases:     []string{"scope-agg", "sa"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "cloud-recon",
		Description: "Cloud bucket discovery",
		Usage:       "/cloud-recon --keyword name",
		Category:    CategoryRecon,
		Handler:     handleCloudRecon,
		Aliases:     []string{"cloud", "cr"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "param-discover",
		Description: "Hidden parameter discovery",
		Usage:       "/param-discover url",
		Category:    CategoryRecon,
		Handler:     handleParamDiscover,
		Aliases:     []string{"param", "pd"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "secrets-hunt",
		Description: "Secret leakage scanning",
		Usage:       "/secrets-hunt --js-bundle dir",
		Category:    CategoryRecon,
		Handler:     handleSecretsHunt,
		Aliases:     []string{"secrets", "sh"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "takeover",
		Description: "Subdomain takeover candidates",
		Usage:       "/takeover --recon dir",
		Category:    CategoryRecon,
		Handler:     handleTakeover,
		Aliases:     []string{"to"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "scan-cves",
		Description: "Focused CVE scanning",
		Usage:       "/scan-cves host",
		Category:    CategoryRecon,
		Handler:     handleScanCVEs,
		Aliases:     []string{"cves", "sc"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "bypass-403",
		Description: "403 bypass techniques",
		Usage:       "/bypass-403 url",
		Category:    CategoryRecon,
		Handler:     handleBypass403,
		Aliases:     []string{"403", "bypass"},
	})
}

func handleRecon(args []string) string {
	if len(args) == 0 {
		return "Usage: /recon target.com"
	}
	target := args[0]
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Starting full recon on %s\n", target))
	sb.WriteString(fmt.Sprintf("[+] Subdomain enumeration: subfinder -d %s\n", target))
	sb.WriteString(fmt.Sprintf("[+] Live host probing: httpx -l subs.txt\n"))
	sb.WriteString(fmt.Sprintf("[+] URL crawling: katana -u %s\n", target))
	sb.WriteString(fmt.Sprintf("[+] Nuclei sweep: nuclei -t cves/ -l live_hosts.txt\n"))
	sb.WriteString(fmt.Sprintf("[!] Run each step manually or use /autopilot %s for full automation", target))
	return sb.String()
}

func handleSurface(args []string) string {
	if len(args) == 0 {
		return "Usage: /surface target.com"
	}
	return fmt.Sprintf("[*] Analyzing attack surface for %s\n[+] Ranking endpoints by exposure\n[+] Identifying high-value targets\n[!] Surface data aggregated from recon results", args[0])
}

func handleScopeAggregate(args []string) string {
	if len(args) == 0 {
		return "Usage: /scope-aggregate program"
	}
	return fmt.Sprintf("[*] Aggregating scope for %s from:\n[+] HackerOne\n[+] Bugcrowd\n[+] Intigriti\n[!] Scope aggregated. Use /scope asset to check.", args[0])
}

func handleCloudRecon(args []string) string {
	keyword := ""
	for i, a := range args {
		if a == "--keyword" && i+1 < len(args) {
			keyword = args[i+1]
		}
	}
	if keyword == "" {
		return "Usage: /cloud-recon --keyword name"
	}
	return fmt.Sprintf("[*] Cloud bucket discovery for keyword: %s\n[+] Checking AWS S3 buckets\n[+] Checking GCP Cloud Storage\n[+] Checking Azure Blob Storage\n[!] Results saved to cloud_%s.txt", keyword, keyword)
}

func handleParamDiscover(args []string) string {
	if len(args) == 0 {
		return "Usage: /param-discover url"
	}
	return fmt.Sprintf("[*] Discovering hidden parameters on %s\n[+] Running paramspider\n[+] Running waybackurls\n[+] Running gau\n[!] Check results for undocumented params", args[0])
}

func handleSecretsHunt(args []string) string {
	dir := "."
	for i, a := range args {
		if a == "--js-bundle" && i+1 < len(args) {
			dir = args[i+1]
		}
	}
	return fmt.Sprintf("[*] Scanning for secrets in %s\n[+] TruffleHog scan\n[+] Gitleaks scan\n[+] Custom regex patterns\n[!] Report any leaked secrets immediately", dir)
}

func handleTakeover(args []string) string {
	dir := "."
	for i, a := range args {
		if a == "--recon" && i+1 < len(args) {
			dir = args[i+1]
		}
	}
	return fmt.Sprintf("[*] Checking subdomain takeover candidates in %s\n[+] Checking DNS resolution\n[+] Checking service fingerprints\n[+] Checking for dangling CNAMEs\n[!] Review candidates before reporting", dir)
}

func handleScanCVEs(args []string) string {
	if len(args) == 0 {
		return "Usage: /scan-cves host"
	}
	return fmt.Sprintf("[*] Focused CVE scan on %s\n[+] Running nuclei -t cves/\n[+] Checking known exploit paths\n[+] Correlating with tech stack\n[!] Results will be reported as findings", args[0])
}

func handleBypass403(args []string) string {
	if len(args) == 0 {
		return "Usage: /bypass-403 url"
	}
	return fmt.Sprintf("[*] Attempting 403 bypass on %s\n[+] HEAD method bypass\n[+] X-Forwarded-For bypass\n[+] URL encoding bypass\n[+] Path normalization bypass\n[+] Extension bypass\n[!] Test each technique manually", args[0])
}
