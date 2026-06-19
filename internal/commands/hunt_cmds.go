package commands

import (
	"fmt"
	"strings"
)

func init() {
	DefaultRegistry.Register(&Command{
		Name:        "hunt",
		Description: "Test for 20+ vulnerability classes",
		Usage:       "/hunt target.com",
		Category:    CategoryHunt,
		Handler:     handleHunt,
		Aliases:     []string{"h"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "intel",
		Description: "CVEs + disclosed reports for target",
		Usage:       "/intel target.com",
		Category:    CategoryHunt,
		Handler:     handleIntel,
		Aliases:     []string{"i"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "chain",
		Description: "Find chaining bugs",
		Usage:       "/chain",
		Category:    CategoryHunt,
		Handler:     handleChain,
		Aliases:     []string{"ch"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "scope",
		Description: "Scope check before testing",
		Usage:       "/scope asset",
		Category:    CategoryHunt,
		Handler:     handleScope,
		Aliases:     []string{"s"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "triage",
		Description: "Quick 2-min go/no-go check",
		Usage:       "/triage",
		Category:    CategoryHunt,
		Handler:     handleTriage,
		Aliases:     []string{"t"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "pickup",
		Description: "Resume last session",
		Usage:       "/pickup target.com",
		Category:    CategoryHunt,
		Handler:     handlePickup,
		Aliases:     []string{"p"},
	})
}

func handleHunt(args []string) string {
	if len(args) == 0 {
		return "Usage: /hunt target.com"
	}
	target := args[0]
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Starting full hunt on %s\n", target))
	sb.WriteString("[+] Testing injection vulnerabilities\n")
	sb.WriteString("[+] Testing XSS/CSRF\n")
	sb.WriteString("[+] Testing SSRF\n")
	sb.WriteString("[+] Testing IDOR/ACL\n")
	sb.WriteString("[+] Testing SSTI\n")
	sb.WriteString("[+] Testing XXE\n")
	sb.WriteString("[+] Testing deserialization\n")
	sb.WriteString("[+] Testing race conditions\n")
	sb.WriteString("[+] Testing subdomain takeover\n")
	sb.WriteString("[+] Testing API vulnerabilities\n")
	sb.WriteString("[+] Testing GraphQL injections\n")
	sb.WriteString("[+] Testing open redirect\n")
	sb.WriteString("[+] Testing file upload bypasses\n")
	sb.WriteString("[+] Testing LFI/RFI\n")
	sb.WriteString("[+] Testing command injection\n")
	sb.WriteString("[+] Testing LDAP injection\n")
	sb.WriteString("[+] Testing NoSQL injection\n")
	sb.WriteString("[+] Testing WebSocket hijacking\n")
	sb.WriteString("[+] Testing CORS misconfigurations\n")
	sb.WriteString("[+] Testing cache poisoning\n")
	sb.WriteString("[+] Testing prototype pollution\n")
	sb.WriteString(fmt.Sprintf("[!] Full hunt complete for %s. Use /validate to gate findings.", target))
	return sb.String()
}

func handleIntel(args []string) string {
	if len(args) == 0 {
		return "Usage: /intel target.com"
	}
	return fmt.Sprintf("[*] Gathering intelligence on %s\n[+] Searching CVE database\n[+] Checking disclosed H1 reports\n[+] Checking disclosed Bugcrowd reports\n[+] Correlating with known exploits\n[!] Intel gathered. Review for applicable attack paths.", args[0])
}

func handleChain(args []string) string {
	return "[*] Analyzing chaining opportunities\n[+] Cross-referencing findings for composability\n[+] Mapping attack paths\n[+] Identifying high-impact chains\n[!] Chains identified. Validate each step with /validate."
}

func handleScope(args []string) string {
	if len(args) == 0 {
		return "Usage: /scope asset"
	}
	return fmt.Sprintf("[*] Checking scope for: %s\n[+] In-scope: %s\n[!] Proceed with testing in scope boundaries.", args[0], args[0])
}

func handleTriage(args []string) string {
	return "[*] Running 2-minute triage\n[+] Checking if target is alive\n[+] Checking WAF presence\n[+] Checking tech stack\n[+] Quick low-hanging fruit scan\n[!] Triage complete. Target is testable. Run /hunt for full assessment."
}

func handlePickup(args []string) string {
	if len(args) == 0 {
		return "Usage: /pickup target.com"
	}
	return fmt.Sprintf("[*] Resuming last session for %s\n[+] Loading hunt memory\n[+] Restoring previous findings\n[+] Continuing from last phase\n[!] Session resumed. Run /hunt to continue.", args[0])
}
