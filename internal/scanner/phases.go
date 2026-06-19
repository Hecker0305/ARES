package scanner

import (
	"fmt"
	"os"
	"strings"

	"github.com/ares/engine/internal/security"
)

var SeclistsDir string

func init() {
	SeclistsDir = os.Getenv("ARES_SECLISTS_DIR")
	if SeclistsDir == "" {
		SeclistsDir = "/usr/share/seclists/"
	}
}

func SystemPromptHints(target string, oobURL string) string {
	var sb strings.Builder
	sb.WriteString("\n\n=== AVAILABLE KALI TOOLS (use via terminal_execute) ===\n")
	sb.WriteString("RECON     : subfinder, httpx, nmap, katana, waybackurls, amass, wafw00f, whatweb\n")
	sb.WriteString("DISCOVERY : ffuf, gobuster, feroxbuster, dirsearch\n")
	sb.WriteString("VULN SCAN : nuclei, sqlmap, dalfox, arjun, ghauri, wpscan\n")
	sb.WriteString("BROWSER   : chromium-browser --headless --screenshot <url>  (save to /tmp/screenshots/)\n")
	sb.WriteString("POST-EXPLOIT: linpeas.sh, winpeas.exe, enum4linux-ng, mimikatz\n")
	sb.WriteString("C2        : sliver-client (if installed)\n")
	sb.WriteString(fmt.Sprintf("OOB BLIND : use callback URL %s?id=<payload_id> to confirm blind SSRF/XXE/RCE\n", security.SanitizeForLLM(oobURL)))
	sb.WriteString("\nWordlists : " + SeclistsDir + "\n")
	sb.WriteString(fmt.Sprintf("Target    : %s\n", security.SanitizeForLLM(target)))
	sb.WriteString("Evidence  : save screenshots to /tmp/screenshots/<id>.png before calling report_vulnerability\n")
	return sb.String()
}
