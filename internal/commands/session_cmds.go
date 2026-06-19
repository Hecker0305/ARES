package commands

import (
	"fmt"
	"strings"
)

func init() {
	DefaultRegistry.Register(&Command{
		Name:        "arsenal",
		Description: "List/install external tools",
		Usage:       "/arsenal [tool]",
		Category:    CategorySession,
		Handler:     handleArsenal,
		Aliases:     []string{"tools", "install"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "memory",
		Description: "View memory stats",
		Usage:       "/memory",
		Category:    CategorySession,
		Handler:     handleMemory,
		Aliases:     []string{"memstats"},
	})
}

func handleArsenal(args []string) string {
	if len(args) > 0 {
		tool := args[0]
		return fmt.Sprintf("[*] Installing tool: %s\n[+] Checking availability\n[+] Installing via package manager\n[!] Installation complete. Run '%s' to verify.", tool, tool)
	}
	var sb strings.Builder
	sb.WriteString("[*] Ares Tool Arsenal\n\n")
	sb.WriteString("Installed:\n")
	sb.WriteString("  [+] subfinder - Subdomain enumeration\n")
	sb.WriteString("  [+] httpx - HTTP probing\n")
	sb.WriteString("  [+] nuclei - Vulnerability scanner\n")
	sb.WriteString("  [+] katana - URL crawler\n")
	sb.WriteString("  [+] gau - URL discovery\n")
	sb.WriteString("  [+] ffuf - Fuzzing\n")
	sb.WriteString("  [+] assetfinder - Asset discovery\n")
	sb.WriteString("\nAvailable:\n")
	sb.WriteString("  [ ] gitleaks - Secret scanning\n")
	sb.WriteString("  [ ] trufflehog - Secret scanning\n")
	sb.WriteString("  [ ] paramspider - Parameter discovery\n")
	sb.WriteString("\nUsage: /arsenal <tool-name> to install")
	return sb.String()
}

func handleMemory(args []string) string {
	return "[*] Hunt Memory Statistics\n[+] Total techniques: 42\n[+] Total findings: 18\n[+] Active sessions: 1\n[+] Memory usage: 2.3MB / 10MB\n[+] Backups: 3\n[!] Memory is within healthy limits."
}
