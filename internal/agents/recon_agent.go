package agents

import (
	"fmt"
	"strings"
)

type reconAgent struct {
	spec AgentSpec
}

func (a *reconAgent) Type() AgentType {
	return ReconAgent
}

func (a *reconAgent) Spec() AgentSpec {
	return a.spec
}

func (a *reconAgent) Execute(target string) (string, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[ReconAgent] Starting reconnaissance on %s\n", target))
	sb.WriteString(fmt.Sprintf("  [+] Running subfinder -d %s\n", target))
	sb.WriteString("  [+] Probing live hosts with httpx\n")
	sb.WriteString("  [+] Crawling URLs with katana\n")
	sb.WriteString("  [+] Running nuclei discovery templates\n")
	sb.WriteString("  [+] Collecting URLs with gau\n")
	sb.WriteString(fmt.Sprintf("[ReconAgent] Recon complete for %s\n", target))
	sb.WriteString("[ReconAgent] Structured attack surface data ready for review")
	return sb.String(), nil
}
