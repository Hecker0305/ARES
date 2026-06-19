package scanctx

type Phase22 string

const (
	P01Recon               Phase22 = "reconnaissance"
	P02ManualVulnDiscovery Phase22 = "manual_vuln_discovery"
	P03DirectoryDiscovery  Phase22 = "directory_discovery"
	P04CORS                Phase22 = "cors_cookie_analysis"
	P05Auth                Phase22 = "auth_session_testing"
	P06Injection           Phase22 = "injection_testing"
	P07SSRF                Phase22 = "ssrf_testing"
	P08IDOR                Phase22 = "idor_access_control"
	P09APIGraphQL          Phase22 = "api_graphql"
	P10FileUpload          Phase22 = "file_upload_testing"
	P11Deserialization     Phase22 = "deserialization_rce"
	P12RaceConditions      Phase22 = "race_conditions"
	P13SubdomainTakeover   Phase22 = "subdomain_takeover"
	P14OpenRedirect        Phase22 = "open_redirect"
	P15EmailSecurity       Phase22 = "email_security"
	P16CloudInfra          Phase22 = "cloud_infrastructure"
	P17WebSocket           Phase22 = "websocket_testing"
	P18CMS                 Phase22 = "cms_specific"
	P19BrokenLinkHijack    Phase22 = "broken_link_hijacking"
	P20ExploitVerify       Phase22 = "exploit_verification"
	P21ZeroDay             Phase22 = "zero_day_discovery"
	P22FinalReport         Phase22 = "final_report"
	P23WebshellScan        Phase22 = "webshell_scan"
)

type Phase22Info struct {
	ID          Phase22 `json:"id"`
	Number      int     `json:"number"`
	Label       string  `json:"label"`
	Description string  `json:"description"`
	Group       string  `json:"group"`
	DefaultOn   bool    `json:"defaultOn"`
}

var AllPhases22 = []Phase22Info{
	{ID: P01Recon, Number: 1, Label: "Reconnaissance", Description: "Passive and active information gathering — DNS, subdomains, tech stack, WHOIS", Group: "Reconnaissance", DefaultOn: true},
	{ID: P02ManualVulnDiscovery, Number: 2, Label: "Manual Vuln Discovery", Description: "Manual testing for common web vulnerabilities with browser-assisted analysis", Group: "Discovery", DefaultOn: true},
	{ID: P03DirectoryDiscovery, Number: 3, Label: "Directory Discovery", Description: "Directory and file enumeration — hidden paths, backups, admin panels", Group: "Discovery", DefaultOn: true},
	{ID: P04CORS, Number: 4, Label: "CORS & Cookie Analysis", Description: "Cross-origin resource sharing misconfigurations and cookie security audit", Group: "Web Security", DefaultOn: true},
	{ID: P05Auth, Number: 5, Label: "Auth & Session Testing", Description: "Authentication bypass, session fixation, JWT analysis, OAuth flows", Group: "Authentication", DefaultOn: true},
	{ID: P06Injection, Number: 6, Label: "Injection Testing", Description: "SQL, NoSQL, command, template, LDAP injection testing", Group: "Injection", DefaultOn: true},
	{ID: P07SSRF, Number: 7, Label: "SSRF Testing", Description: "Server-side request forgery — cloud metadata, internal network probing", Group: "Server-Side", DefaultOn: true},
	{ID: P08IDOR, Number: 8, Label: "IDOR & Access Control", Description: "Insecure direct object references and privilege escalation checks", Group: "Access Control", DefaultOn: true},
	{ID: P09APIGraphQL, Number: 9, Label: "API & GraphQL", Description: "REST API fuzzing, GraphQL introspection, rate limit bypass, mass assignment", Group: "API", DefaultOn: true},
	{ID: P10FileUpload, Number: 10, Label: "File Upload Testing", Description: "Malicious file upload, mime-type bypass, double extension, zip slip", Group: "Input Validation", DefaultOn: false},
	{ID: P11Deserialization, Number: 11, Label: "Deserialization & RCE", Description: "Insecure deserialization, remote code execution vectors", Group: "Exploitation", DefaultOn: false},
	{ID: P12RaceConditions, Number: 12, Label: "Race Conditions", Description: "TOCTOU, concurrent request race windows, lock bypass", Group: "Logic", DefaultOn: false},
	{ID: P13SubdomainTakeover, Number: 13, Label: "Subdomain Takeover", Description: "DNS CNAME records pointing to unclaimed cloud services", Group: "Infrastructure", DefaultOn: false},
	{ID: P14OpenRedirect, Number: 14, Label: "Open Redirect", Description: "Unvalidated redirect parameters and phishing payload detection", Group: "Web Security", DefaultOn: false},
	{ID: P15EmailSecurity, Number: 15, Label: "Email Security", Description: "SPF/DKIM/DMARC analysis, email spoofing, SMTP open relay", Group: "Infrastructure", DefaultOn: false},
	{ID: P16CloudInfra, Number: 16, Label: "Cloud & Infrastructure", Description: "S3 bucket enumeration, cloud metadata, container escape checks", Group: "Infrastructure", DefaultOn: false},
	{ID: P17WebSocket, Number: 17, Label: "WebSocket Testing", Description: "WebSocket message fuzzing, origin validation, CSWSH attacks", Group: "API", DefaultOn: false},
	{ID: P18CMS, Number: 18, Label: "CMS-Specific Testing", Description: "WordPress, Joomla, Drupal plugin/core version checks and known CVEs", Group: "CMS", DefaultOn: false},
	{ID: P19BrokenLinkHijack, Number: 19, Label: "Broken Link Hijacking", Description: "Claimable external links, social media handles, unregistered domains", Group: "Supply Chain", DefaultOn: false},
	{ID: P20ExploitVerify, Number: 20, Label: "Exploit Verification", Description: "Manual PoC verification, payload refinement, false positive elimination", Group: "Exploitation", DefaultOn: false},
	{ID: P21ZeroDay, Number: 21, Label: "Zero-Day Discovery", Description: "Fuzzing, behavioral analysis, and novel vulnerability research", Group: "Research", DefaultOn: false},
	{ID: P22FinalReport, Number: 22, Label: "Final Report", Description: "Executive summary, findings consolidation, remediation plan, PDF generation", Group: "Reporting", DefaultOn: true},
	{ID: P23WebshellScan, Number: 23, Label: "Webshell Detection", Description: "Signature, entropy, behavioral, and network-based webshell detection across web roots and upload directories", Group: "Post-Exploitation", DefaultOn: false},
}

type ScanMode string

const (
	ModeSingleTarget ScanMode = "single_target_scan"
	ModeDAST         ScanMode = "dast_scan"
	ModeWildcard     ScanMode = "wildcard_scan"
)

type ScanModeInfo struct {
	ID          ScanMode `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	BestFor     string   `json:"bestFor"`
	Icon        string   `json:"icon"`
}

var ScanModes = []ScanModeInfo{
	{ID: ModeSingleTarget, Label: "Single Target", Description: "Focused testing of one URL or host. Full 23-phase methodology applied with auto PDF report generation.", BestFor: "Known URLs, quick assessments, specific hosts", Icon: "🎯"},
	{ID: ModeDAST, Label: "DAST", Description: "Browser-assisted dynamic testing for web applications. Crawls for URL discovery, parameter identification, Nuclei scanning, and manual exploitation phases.", BestFor: "Web app pentesting, auth flows, forms, runtime behavior", Icon: "🕸"},
	{ID: ModeWildcard, Label: "Wildcard / Multi-target", Description: "Passive and active subdomain enumeration with DNS resolution. Each discovered target receives full DAST-level testing across the attack surface.", BestFor: "Bug bounty programs, attack surface discovery", Icon: "🌐"},
}
