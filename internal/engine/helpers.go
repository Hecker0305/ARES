package engine

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ares/engine/internal/security"
)

func TargetToHosts(target string) []string {
	if target == "" {
		return nil
	}

	if isIP(target) {
		return []string{target}
	}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err == nil && u.Host != "" {
			if ip := resolveHost(u.Host); ip != "" {
				return []string{ip}
			}
			return []string{u.Host}
		}
	}

	if strings.Contains(target, ".") {
		if ip := resolveHost(target); ip != "" {
			return []string{ip}
		}
		return []string{target}
	}

	return []string{target}
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func resolveHost(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	ip := ips[0]
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return ""
	}
	return ip.String()
}

func ExtractTechFromOutput(output string) []string {
	var tech []string

	patterns := map[string][]string{
		"nginx":         {"nginx", "nginx/"},
		"apache":        {"apache", "apache/"},
		"iis":           {"microsoft-iis", "iis/", "iis\\"},
		"nodejs":        {"node", "express", "nextjs", "nuxt"},
		"python":        {"python", "flask", "django", "fastapi"},
		"php":           {"php", "apache2", "fpm"},
		"java":          {"spring", "tomcat", "jetty", "jboss"},
		"dotnet":        {"asp.net", ".net", "iis", "kestrel"},
		"ruby":          {"rails", "ruby", "sinatra"},
		"golang":        {"gin", "echo", "go-"},
		"mongodb":       {"mongodb", "mongo"},
		"mysql":         {"mysql", "mariadb"},
		"postgresql":    {"postgres", "postgresql"},
		"redis":         {"redis"},
		"elasticsearch": {"elasticsearch"},
		"docker":        {"docker", "containerd"},
		"kubernetes":    {"kubernetes", "k8s"},
	}

	outputLower := strings.ToLower(output)

	for techName, keywords := range patterns {
		for _, kw := range keywords {
			if strings.Contains(outputLower, strings.ToLower(kw)) {
				tech = append(tech, techName)
				break
			}
		}
	}

	if strings.Contains(outputLower, "openssh") {
		tech = append(tech, "openssh")
	}

	versionPatterns := []string{
		`nginx[/\s]([\d.]+)`,
		`Apache[/\s]([\d.]+)`,
		`PHP[/\s]([\d.]+)`,
		`Node\.?js[/\s]([\d.]+)`,
		`Python[/\s]([\d.]+)`,
	}

	for _, pattern := range versionPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			tech = append(tech, matches[1])
		}
	}

	return dedupStrings(tech)
}

func BuildSystemPrompt(targets []string, instruction string) string {
	var sb strings.Builder

	sb.WriteString("You are ARES, an advanced autonomous security scanning engine.\n\n")

	if len(targets) > 0 {
		sb.WriteString("=== TARGETS ===\n")
		for i, t := range targets {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("  - ... and %d more targets\n", len(targets)-i))
				break
			}
			sb.WriteString(fmt.Sprintf("  - %s\n", security.SanitizeForLLM(t)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("=== CAPABILITIES ===\n")
	sb.WriteString("- Reconnaissance and enumeration\n")
	sb.WriteString("- Vulnerability scanning and exploitation\n")
	sb.WriteString("- Post-exploitation and privilege escalation\n")
	sb.WriteString("- Reporting and evidence collection\n\n")

	sb.WriteString("=== TOOLS ===\n")
	sb.WriteString("Available: nmap, nikto, nuclei, sqlmap, curl, wget, ffuf, dirb, xss payloads, custom exploits\n\n")

	if instruction != "" {
		sb.WriteString("=== INSTRUCTION ===\n")
		sb.WriteString(security.SanitizeForLLM(instruction))
		sb.WriteString("\n\n")
	}

	sb.WriteString("Proceed methodically. Prioritize high-severity findings. Report all evidence.\n")

	return sb.String()
}

func PhaseCommands(phase Phase, target string) []security.CommandSpec {
	switch phase {
	case PhaseRecon:
		return []security.CommandSpec{
			{Binary: "recon-ng", Args: []string{"-w", target}},
			{Binary: "theHarvester", Args: []string{"-d", target, "-b", "all"}},
			{Binary: "amass", Args: []string{"enum", "-d", target}},
		}

	case PhaseDiscovery:
		return []security.CommandSpec{
			{Binary: "nmap", Args: []string{"-sV", "-O", "-p-", target}},
			{Binary: "nmap", Args: []string{"--script=vuln", target}},
			{Binary: "nikto", Args: []string{"-h", target}},
		}

	case PhaseVulnScan:
		return []security.CommandSpec{
			{Binary: "nuclei", Args: []string{"-u", target, "-t", "cves,exposed-panels"}},
			{Binary: "nmap", Args: []string{"--script=banner", target}},
			{Binary: "whatweb", Args: []string{target}},
		}

	case PhaseExploit:
		return []security.CommandSpec{
			{Binary: "sqlmap", Args: []string{"-u", target, "--batch"}},
			{Binary: "xsser", Args: []string{"-u", target}},
		}

	case PhasePostExploit:
		return []security.CommandSpec{
			{Binary: "linpeas", Args: []string{target}},
		}

	case PhaseReport:
		return []security.CommandSpec{
			{Binary: "cat", Args: []string{fmt.Sprintf("findings_%s.txt", target)}},
		}

	default:
		return []security.CommandSpec{}
	}
}

func CanaryURL() string {
	canary := os.Getenv("ARES_CANARY_URL")
	if canary != "" {
		return canary
	}

	domain := os.Getenv("ARES_DOMAIN")
	if domain != "" {
		return fmt.Sprintf("http://%s", domain)
	}

	return "http://localhost:8181"
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

func NormalizeTarget(target string) string {
	target = strings.TrimSpace(target)

	if strings.Contains(target, "://") {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			idx := strings.Index(target, "://")
			target = "https://" + target[idx+3:]
		}
	} else if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	if u.Host == "" {
		return target
	}

	return u.String()
}

func IsPrivateNetwork(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, r := range privateRanges {
		_, network, err := net.ParseCIDR(r)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}

	return false
}

func TimeoutForPhase(phase Phase) time.Duration {
	switch phase {
	case PhaseRecon:
		return 5 * time.Minute
	case PhaseDiscovery:
		return 10 * time.Minute
	case PhaseVulnScan:
		return 15 * time.Minute
	case PhaseExploit:
		return 20 * time.Minute
	case PhasePostExploit:
		return 10 * time.Minute
	case PhaseReport:
		return 2 * time.Minute
	default:
		return 10 * time.Minute
	}
}
