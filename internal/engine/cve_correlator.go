package engine

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
)

//go:embed cve_data.json
var cveDataFS embed.FS

type RankedCVE struct {
	ID          string
	Description string
	CVSS        float64
	EPSS        float64
	KEV         float64
	SynthScore  float64
	NucleiTag   string
	PoCCommand  string
	References  []string
}

type cveRecord struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSS        float64  `json:"cvss"`
	EPSS        float64  `json:"epss"`
	KEV         float64  `json:"kev"`
	NucleiTag   string   `json:"nuclei_tag"`
	PoCCommand  string   `json:"poc_command"`
	References  []string `json:"references"`
}

func loadDefaultCorpus() []RankedCVE {
	var records []cveRecord
	data, err := cveDataFS.ReadFile("cve_data.json")
	if err == nil {
		if err := json.Unmarshal(data, &records); err == nil {
			cves := make([]RankedCVE, len(records))
			for i, r := range records {
				cves[i] = RankedCVE{
					ID:          r.ID,
					Description: r.Description,
					CVSS:        r.CVSS,
					EPSS:        r.EPSS,
					KEV:         r.KEV,
					NucleiTag:   r.NucleiTag,
					PoCCommand:  r.PoCCommand,
					References:  r.References,
				}
			}
			return cves
		}
	}

	logger.Warn("Failed to load embedded CVE data, returning empty corpus", logger.Fields{"component": "CVECorrelator"})
	logger.Info("Configure ARES_CVE_FEED_URL to load CVE data from a live feed")
	return []RankedCVE{}
}

var cveIDRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func isValidCVE(id string) bool {
	return cveIDRe.MatchString(id)
}

func clampEPSS(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

type CVECorrelator struct {
	epssData   map[string]float64
	kevData    map[string]bool
	corpus     []RankedCVE
	cacheFile  string
	httpClient *http.Client
}

func NewCVECorrelator() *CVECorrelator {
	cacheDir := os.Getenv("ARES_CACHE_DIR")
	if cacheDir == "" {
		cacheDir, _ = os.UserHomeDir()
	}
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}

	return &CVECorrelator{
		epssData:   make(map[string]float64),
		kevData:    make(map[string]bool),
		corpus:     loadDefaultCorpus(),
		cacheFile:  filepath.Join(cacheDir, "cve_correlator_cache.json"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CVECorrelator) CorrelateWithScoring(techStack []string) []RankedCVE {
	joined := strings.ToLower(strings.Join(techStack, " "))

	var matches []RankedCVE
	for _, cve := range c.corpus {
		techMatches := strings.Contains(joined, strings.ToLower(cve.ID))

		if !techMatches && !strings.Contains(joined, "vulnerable") && !strings.Contains(joined, "exploit") {
			for _, ref := range cve.References {
				if strings.Contains(joined, ref) {
					techMatches = true
					break
				}
			}
		}

		if techMatches || c.matchesTechStack(techStack, cve) {
			scored := c.calculateSynthScore(cve)
			matches = append(matches, scored)
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].SynthScore > matches[j].SynthScore
	})

	return matches
}

func (c *CVECorrelator) matchesTechStack(techStack []string, cve RankedCVE) bool {
	lowerTechStack := make([]string, len(techStack))
	for i, t := range techStack {
		lowerTechStack[i] = strings.ToLower(t)
	}

	vulnKeywords := map[string][]string{
		"log4j":    {"log4j", "log4shell", "jndi"},
		"spring":   {"spring", "spring4shell", "cve-2022-22965"},
		"exchange": {"exchange", "proxylogon", "cve-2021-26855"},
		"big-ip":   {"big-ip", "f5", "cve-2022-1388"},
		"moveit":   {"moveit", "cve-2023-34362"},
	}

	for _, tech := range lowerTechStack {
		if keywords, ok := vulnKeywords[tech]; ok {
			for _, kw := range keywords {
				if strings.Contains(strings.ToLower(cve.ID), kw) || strings.Contains(strings.ToLower(cve.Description), kw) {
					return true
				}
			}
		}
	}

	return false
}

func (c *CVECorrelator) calculateSynthScore(cve RankedCVE) RankedCVE {
	epss := cve.EPSS
	if ep, ok := c.epssData[cve.ID]; ok {
		epss = ep
	}

	kev := 0.0
	if c.kevData[cve.ID] {
		kev = 1.0
	}

	severityWeight := cve.CVSS / 10.0

	synthScore := epss*0.6 + kev*0.3 + severityWeight*0.1

	cve.SynthScore = synthScore
	cve.EPSS = epss
	cve.KEV = kev

	return cve
}

func (c *CVECorrelator) FetchEPSS(ctx context.Context) error {
	epssURL := "https://api.first.org/data/v1/epss"

	logger.Info("Fetching EPSS data", logger.Fields{"component": "CVECorrelator", "url": epssURL})

	data, err := c.FetchFromNetwork(ctx, epssURL)
	if err != nil {
		logger.Warn("EPSS fetch failed, using fallback", logger.Fields{"component": "CVECorrelator", "error": err})
		epssData := map[string]float64{
			"CVE-2021-44228": 0.97, "CVE-2022-22965": 0.95, "CVE-2021-26855": 0.92,
			"CVE-2022-1388": 0.88, "CVE-2023-44487": 0.85, "CVE-2021-41773": 0.75,
			"CVE-2022-0847": 0.70, "CVE-2023-23397": 0.65, "CVE-2023-34362": 0.60,
			"CVE-2019-0708": 0.95,
		}
		c.epssData = epssData
		logger.Info("Loaded EPSS scores (fallback)", logger.Fields{"component": "CVECorrelator", "count": len(c.epssData)})
		return nil
	}

	if err := c.ParseEPSS(data); err != nil {
		logger.Warn("EPSS parse error, using fallback", logger.Fields{"component": "CVECorrelator", "error": err})
		epssData := map[string]float64{
			"CVE-2021-44228": 0.97, "CVE-2022-22965": 0.95, "CVE-2021-26855": 0.92,
			"CVE-2022-1388": 0.88, "CVE-2023-44487": 0.85, "CVE-2021-41773": 0.75,
			"CVE-2022-0847": 0.70, "CVE-2023-23397": 0.65, "CVE-2023-34362": 0.60,
			"CVE-2019-0708": 0.95,
		}
		c.epssData = epssData
		logger.Info("Loaded EPSS scores (fallback)", logger.Fields{"component": "CVECorrelator", "count": len(c.epssData)})
		return nil
	}

	logger.Info("Loaded EPSS scores from network", logger.Fields{"component": "CVECorrelator", "count": len(c.epssData)})
	return nil
}

func (c *CVECorrelator) FetchKEV(ctx context.Context) error {
	kevURL := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	logger.Info("Fetching CISA KEV data", logger.Fields{"component": "CVECorrelator", "url": kevURL})

	data, err := c.FetchFromNetwork(ctx, kevURL)
	if err != nil {
		logger.Warn("KEV fetch failed, using fallback", logger.Fields{"component": "CVECorrelator", "error": err})
		kevData := map[string]bool{
			"CVE-2021-44228": true, "CVE-2022-22965": true, "CVE-2021-26855": true,
			"CVE-2022-1388": true, "CVE-2023-23397": true, "CVE-2023-34362": true,
		}
		c.kevData = kevData
		logger.Info("Loaded KEV entries (fallback)", logger.Fields{"component": "CVECorrelator", "count": len(c.kevData)})
		return nil
	}

	if err := c.ParseKEV(data); err != nil {
		logger.Warn("KEV parse error, using fallback", logger.Fields{"component": "CVECorrelator", "error": err})
		kevData := map[string]bool{
			"CVE-2021-44228": true, "CVE-2022-22965": true, "CVE-2021-26855": true,
			"CVE-2022-1388": true, "CVE-2023-23397": true, "CVE-2023-34362": true,
		}
		c.kevData = kevData
		logger.Info("Loaded KEV entries (fallback)", logger.Fields{"component": "CVECorrelator", "count": len(c.kevData)})
		return nil
	}

	logger.Info("Loaded KEV entries from network", logger.Fields{"component": "CVECorrelator", "count": len(c.kevData)})
	return nil
}

func (c *CVECorrelator) BuildNucleiArgs(cves []RankedCVE) []string {
	if len(cves) == 0 {
		return []string{"-update"}
	}

	var tags []string
	for _, cve := range cves {
		if cve.NucleiTag != "" {
			tag := strings.TrimSpace(cve.NucleiTag)
			if tag != "" && !strings.ContainsAny(tag, "\n\r,") {
				tags = append(tags, tag)
			}
		}
	}

	if len(tags) == 0 {
		return []string{"-u", "TARGET", "-t", "cves"}
	}

	args := []string{"-u", "TARGET", "-id"}
	args = append(args, tags...)
	return args
}

func (c *CVECorrelator) SaveCache() error {
	data := struct {
		EPSS      map[string]float64 `json:"epss"`
		KEV       map[string]bool    `json:"kev"`
		Timestamp time.Time          `json:"timestamp"`
	}{
		EPSS:      c.epssData,
		KEV:       c.kevData,
		Timestamp: time.Now(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	if err := os.WriteFile(c.cacheFile, jsonData, 0600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}

	return nil
}

func (c *CVECorrelator) LoadCache() error {
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read cache: %w", err)
	}

	var cache struct {
		EPSS      map[string]float64 `json:"epss"`
		KEV       map[string]bool    `json:"kev"`
		Timestamp time.Time          `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &cache); err != nil {
		return fmt.Errorf("unmarshal cache: %w", err)
	}

	// Reject cache older than 7 days
	if time.Since(cache.Timestamp) > 7*24*time.Hour {
		logger.Warn("CVE cache expired, will refresh", logger.Fields{"component": "CVECorrelator", "age": time.Since(cache.Timestamp)})
		return nil
	}

	c.epssData = cache.EPSS
	c.kevData = cache.KEV

	return nil
}

func (c *CVECorrelator) SetEPSSData(data map[string]float64) {
	c.epssData = data
}

func (c *CVECorrelator) SetKEVData(data map[string]bool) {
	c.kevData = data
}

func (c *CVECorrelator) FetchFromNetwork(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS allowed for CVE data feeds")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "json") && !strings.Contains(contentType, "application/octet-stream") {
		return nil, fmt.Errorf("unexpected content type: %s", contentType)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return data, nil
}

func (c *CVECorrelator) ParseEPSS(data []byte) error {
	type epssItem struct {
		CVE  string `json:"cve"`
		EPSS string `json:"epss"`
	}
	type epssResponse struct {
		Data []epssItem `json:"data"`
	}

	var resp epssResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse EPSS: %w", err)
	}

	for _, e := range resp.Data {
		if !isValidCVE(e.CVE) {
			logger.Debug("Skipping invalid CVE ID in EPSS", logger.Fields{"component": "CVECorrelator", "cve_id": e.CVE})
			continue
		}
		epss, err := strconv.ParseFloat(e.EPSS, 64)
		if err != nil {
			logger.Warn("Failed to parse EPSS value", logger.Fields{"component": "CVECorrelator", "value": e.EPSS, "cve_id": e.CVE, "error": err})
			continue
		}
		c.epssData[e.CVE] = clampEPSS(epss)
	}

	return nil
}

func (c *CVECorrelator) ParseKEV(data []byte) error {
	type kevItem struct {
		CVEID string `json:"cveID"`
	}
	type kevResponse struct {
		Vulnerabilities []kevItem `json:"vulnerabilities"`
	}

	var resp kevResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse KEV: %w", err)
	}

	for _, e := range resp.Vulnerabilities {
		if !isValidCVE(e.CVEID) {
			logger.Debug("Skipping invalid CVE ID in KEV", logger.Fields{"component": "CVECorrelator", "cve_id": e.CVEID})
			continue
		}
		c.kevData[e.CVEID] = true
	}

	return nil
}

func (c *CVECorrelator) References() []string {
	return []string{
		"https://www.cvedetails.com/epss/",
		"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	}
}

func SearchNVDByKeyword(ctx context.Context, keyword string, maxResults int) ([]RankedCVE, error) {
	if maxResults <= 0 {
		maxResults = 10
	}
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=%d", url.QueryEscape(keyword), maxResults)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("nvd request: %w", err)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nvd status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("nvd read: %w", err)
	}
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CVSSMetricV2 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("nvd parse: %w", err)
	}
	var results []RankedCVE
	for _, v := range nvdResp.Vulnerabilities {
		cve := v.CVE
		var desc string
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		cvss := 0.0
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			cvss = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			cvss = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
		} else if len(cve.Metrics.CVSSMetricV2) > 0 {
			cvss = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		}
		results = append(results, RankedCVE{
			ID:          cve.ID,
			Description: desc,
			CVSS:        cvss,
			SynthScore:  cvss / 10.0,
		})
	}
	return results, nil
}
