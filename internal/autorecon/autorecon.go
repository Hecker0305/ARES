package autorecon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type ASNInfo struct {
	ASN         string   `json:"asn"`
	CIDR        string   `json:"cidr"`
	Org         string   `json:"org"`
	Country     string   `json:"country"`
	TLDs        []string `json:"tlds"`
	Nameservers []string `json:"nameservers"`
}

type TechFingerprint struct {
	Technology string  `json:"technology"`
	Version    string  `json:"version"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
}

type ExposedAsset struct {
	URL     string `json:"url"`
	Type    string `json:"type"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

type CorrelationResult struct {
	Domain         string            `json:"domain"`
	IPs            []string          `json:"ips"`
	ASN            *ASNInfo          `json:"asn"`
	TechStack      []TechFingerprint `json:"tech_stack"`
	Assets         []ExposedAsset    `json:"assets"`
	Subdomains     []string          `json:"subdomains"`
	EmailServers   []string          `json:"email_servers"`
	CloudProviders []string          `json:"cloud_providers"`
	Score          float64           `json:"score"`
}

var allowedTools = map[string]bool{
	"nmap":       true,
	"dig":        true,
	"nslookup":   true,
	"host":       true,
	"whois":      true,
	"ping":       true,
	"traceroute": true,
	"curl":       true,
	"wget":       true,
	"openssl":    true,
}

func ValidateToolName(tool string) bool {
	return allowedTools[strings.ToLower(tool)]
}

func SanitizeArg(arg string) string {
	sanitized := strings.ReplaceAll(arg, ";", "")
	sanitized = strings.ReplaceAll(sanitized, "&", "")
	sanitized = strings.ReplaceAll(sanitized, "|", "")
	sanitized = strings.ReplaceAll(sanitized, "`", "")
	sanitized = strings.ReplaceAll(sanitized, "$", "")
	sanitized = strings.ReplaceAll(sanitized, "(", "")
	sanitized = strings.ReplaceAll(sanitized, ")", "")
	sanitized = strings.ReplaceAll(sanitized, "\n", "")
	sanitized = strings.ReplaceAll(sanitized, "\r", "")
	sanitized = strings.TrimSpace(sanitized)
	return sanitized
}

type Engine struct {
	mu          sync.Mutex
	results     map[string]*CorrelationResult
	dnsCache    map[string][]string
	toolTimeout time.Duration
}

func New() *Engine {
	return &Engine{
		results:     make(map[string]*CorrelationResult),
		dnsCache:    make(map[string][]string),
		toolTimeout: 10 * time.Second,
	}
}

func (e *Engine) SetToolTimeout(timeout time.Duration) {
	if timeout > 0 {
		e.toolTimeout = timeout
	}
}

func (e *Engine) Correlate(ctx context.Context, domain string) (*CorrelationResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	sanitized := SanitizeArg(domain)
	if sanitized == "" {
		return nil, fmt.Errorf("invalid domain")
	}

	e.mu.Lock()
	if cached, ok := e.results[sanitized]; ok {
		e.mu.Unlock()
		return cached, nil
	}
	e.mu.Unlock()

	result := &CorrelationResult{
		Domain:         sanitized,
		IPs:            make([]string, 0),
		TechStack:      make([]TechFingerprint, 0),
		Assets:         make([]ExposedAsset, 0),
		Subdomains:     make([]string, 0),
		EmailServers:   make([]string, 0),
		CloudProviders: make([]string, 0),
	}

	result.IPs = e.resolveDomain(ctx, sanitized)
	result.ASN = e.lookupASN(result.IPs)
	result.TechStack = e.fingerprintTech(ctx, sanitized)
	result.Assets = e.findExposedAssets(ctx, sanitized, result.IPs)
	result.Subdomains = e.commonSubdomains(ctx, sanitized)
	result.EmailServers = e.findEmailServers(ctx, sanitized)
	result.CloudProviders = e.detectCloudProvider(result.IPs, result.TechStack)
	result.Score = e.calculateScore(result)

	e.mu.Lock()
	e.results[sanitized] = result
	e.mu.Unlock()
	return result, nil
}

func (e *Engine) resolveDomain(ctx context.Context, domain string) []string {
	e.mu.Lock()
	if ips, ok := e.dnsCache[domain]; ok {
		e.mu.Unlock()
		return ips
	}
	e.mu.Unlock()

	resolveCtx, cancel := context.WithTimeout(ctx, e.toolTimeout)
	defer cancel()

	var r net.Resolver
	ips, err := r.LookupHost(resolveCtx, domain)
	if err != nil {
		return nil
	}

	var v4IPs []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			v4IPs = append(v4IPs, ip)
		}
	}

	if len(v4IPs) == 0 {
		v4IPs = ips
	}

	e.mu.Lock()
	e.dnsCache[domain] = v4IPs
	e.mu.Unlock()
	return v4IPs
}

func (e *Engine) lookupASN(ips []string) *ASNInfo {
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		return &ASNInfo{
			ASN:     "ASN lookup requires external API",
			CIDR:    fmt.Sprintf("%s/24", ip),
			Org:     "Organization lookup deferred",
			Country: "Country lookup deferred",
		}
	}
	return nil
}

func (e *Engine) fingerprintTech(ctx context.Context, domain string) []TechFingerprint {
	tech := make([]TechFingerprint, 0)

	tech = append(tech,
		TechFingerprint{Technology: "HTTP/HTTPS", Category: "protocol", Confidence: 1.0},
	)

	portChecks := []struct {
		port    int
		service string
	}{
		{80, "http"}, {443, "https"}, {8080, "http-proxy"},
		{8443, "https-alt"}, {3000, "webapp"}, {5000, "webapp"},
	}

	for _, check := range portChecks {
		addr := net.JoinHostPort(domain, fmt.Sprintf("%d", check.port))
		probeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Second)
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(probeCtx, "tcp", addr)
		probeCancel()
		if err == nil {
			conn.Close()
			tech = append(tech, TechFingerprint{
				Technology: check.service,
				Category:   "network_service",
				Confidence: 0.9,
			})
		}
	}

	return tech
}

func (e *Engine) findExposedAssets(ctx context.Context, domain string, ips []string) []ExposedAsset {
	assets := make([]ExposedAsset, 0)
	commonPorts := map[int]string{
		22: "ssh", 21: "ftp", 23: "telnet", 25: "smtp",
		80: "http", 443: "https", 8080: "http-proxy",
		3306: "mysql", 5432: "postgresql", 6379: "redis",
		27017: "mongodb", 9200: "elasticsearch",
		3389: "rdp", 5900: "vnc", 8443: "https-alt",
		9000: "webapp", 5000: "webapp",
	}

	for _, ip := range ips {
		for port, service := range commonPorts {
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
			probeCtx, probeCancel := context.WithTimeout(ctx, 1*time.Second)
			dialer := net.Dialer{}
			conn, err := dialer.DialContext(probeCtx, "tcp", addr)
			probeCancel()
			if err == nil {
				assets = append(assets, ExposedAsset{
					URL:     fmt.Sprintf("%s://%s:%d", service, ip, port),
					Type:    "open_port",
					Port:    port,
					Service: service,
				})
				conn.Close()
			}
		}
	}

	return assets
}

func (e *Engine) commonSubdomains(ctx context.Context, domain string) []string {
	common := []string{"www", "mail", "api", "admin", "dev", "staging",
		"test", "vpn", "remote", "blog", "cdn", "static",
		"app", "portal", "secure", "support", "docs",
	}

	var found []string
	for _, sub := range common {
		fqdn := fmt.Sprintf("%s.%s", sub, domain)
		lookupCtx, cancel := context.WithTimeout(ctx, e.toolTimeout)
		_, err := net.DefaultResolver.LookupHost(lookupCtx, fqdn)
		cancel()
		if err == nil {
			found = append(found, fqdn)
		}
	}
	return found
}

func (e *Engine) findEmailServers(ctx context.Context, domain string) []string {
	var servers []string

	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			servers = append(servers, mx.Host)
		}
	}

	return servers
}

func (e *Engine) detectCloudProvider(ips []string, tech []TechFingerprint) []string {
	var providers []string

	cloudIPRanges := []struct {
		prefix string
		name   string
	}{
		{"54.", "AWS"}, {"52.", "AWS"}, {"35.", "GCP"}, {"34.", "GCP"},
		{"13.", "AWS"}, {"18.", "AWS"}, {"20.", "Azure"}, {"40.", "Azure"},
		{"23.", "Azure"}, {"104.", "Azure"}, {"151.", "Cloudflare"},
	}

	for _, ip := range ips {
		for _, cr := range cloudIPRanges {
			if strings.HasPrefix(ip, cr.prefix) {
				providers = append(providers, cr.name)
			}
		}
	}

	for _, t := range tech {
		lower := strings.ToLower(t.Technology)
		if strings.Contains(lower, "cloudflare") {
			providers = append(providers, "Cloudflare")
		}
		if strings.Contains(lower, "akamai") {
			providers = append(providers, "Akamai")
		}
	}

	return unique(providers)
}

func (e *Engine) calculateScore(result *CorrelationResult) float64 {
	score := 0.5

	if len(result.IPs) > 0 {
		score += 0.1
	}
	if len(result.Subdomains) > 3 {
		score += 0.1
	}
	if len(result.TechStack) > 2 {
		score += 0.1
	}
	if len(result.Assets) > 5 {
		score += 0.1
	}
	if len(result.CloudProviders) > 0 {
		score += 0.05
	}
	if len(result.EmailServers) > 0 {
		score += 0.05
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

func (e *Engine) Results() []*CorrelationResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	var result []*CorrelationResult
	for _, r := range e.results {
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Score > result[j].Score
	})
	return result
}

func (e *Engine) AllDomains() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var domains []string
	for d := range e.results {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

func (e *Engine) Summary() map[string]interface{} {
	results := e.Results()
	totalAssets := 0
	totalSubdomains := 0
	highScore := 0
	for _, r := range results {
		totalAssets += len(r.Assets)
		totalSubdomains += len(r.Subdomains)
		if r.Score > 0.7 {
			highScore++
		}
	}
	return map[string]interface{}{
		"domains_scanned":  len(results),
		"total_assets":     totalAssets,
		"total_subdomains": totalSubdomains,
		"high_value":       highScore,
	}
}

func (e *Engine) EnrichASNInfo(domain string, asn, cidr, org, country string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	result, ok := e.results[domain]
	if !ok {
		return
	}

	result.ASN = &ASNInfo{
		ASN:     asn,
		CIDR:    cidr,
		Org:     org,
		Country: country,
	}
}

func unique(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
