package scanctx

type Phase string

const (
	PhaseRecon       Phase = "recon"
	PhaseDiscovery   Phase = "discovery"
	PhaseVulnScan    Phase = "vuln_scan"
	PhaseExploit     Phase = "exploit"
	PhasePostExploit Phase = "post_exploit"
	PhaseReport      Phase = "report"
)
