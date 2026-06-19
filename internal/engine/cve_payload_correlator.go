package engine

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/security"
)

type CVERecord struct {
	CVEID        string
	EPSSScore    float64
	KEV          bool
	Severity     string
	TemplatePath string
	SynthScore   float64
}

type CVEPayloadCorrelator struct {
	mu              sync.RWMutex
	cveMap          map[string]*CVERecord
	rankedTemplates []*CVERecord
	templatesDir    string
	cacheDir        string
	httpClient      *http.Client
	lastRefresh     time.Time
	available       bool
}

var cveRegexp = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

func NewCVEPayloadCorrelator() *CVEPayloadCorrelator {
	templatesDir := os.Getenv("ARES_NUCLEI_TEMPLATES")
	if templatesDir == "" {
		home, _ := os.UserHomeDir()
		templatesDir = filepath.Join(home, "nuclei-templates")
	}
	cacheDir := os.Getenv("ARES_CVE_CACHE_DIR")
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".ares", "cve-cache")
	}

	// Validate templatesDir path to prevent path traversal
	if err := validateDirectoryPath(templatesDir); err != nil {
		logger.Error(fmt.Sprintf("[CVECorrelator] Invalid templates directory %s: %v", templatesDir, err))
		// Fallback to default directory
		home, _ := os.UserHomeDir()
		templatesDir = filepath.Join(home, "nuclei-templates")
	}

	// Validate cacheDir path to prevent path traversal
	if err := validateDirectoryPath(cacheDir); err != nil {
		logger.Error(fmt.Sprintf("[CVECorrelator] Invalid cache directory %s: %v", cacheDir, err))
		// Fallback to default directory
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".ares", "cve-cache")
	}

	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		logger.Error(fmt.Sprintf("[CVECorrelator] Failed to create cache dir %s: %v", cacheDir, err))
	}

	c := &CVEPayloadCorrelator{
		cveMap:       make(map[string]*CVERecord),
		templatesDir: templatesDir,
		cacheDir:     cacheDir,
		httpClient:   &http.Client{Timeout: 60 * time.Second},
	}

	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		logger.Error(fmt.Sprintf("[CVECorrelator] nuclei-templates not found at %s — CVE ranking disabled", templatesDir))
		return c
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.refresh(ctx); err != nil {
		logger.Error(fmt.Sprintf("[CVECorrelator] Initial load failed: %v", err))
		return c
	}

	c.available = true
	logger.Info(fmt.Sprintf("[CVECorrelator] Loaded %d ranked CVE templates", len(c.rankedTemplates)))

	if strings.ToLower(os.Getenv("ARES_CVE_REFRESH")) != "false" {
		go c.dailyRefresher()
	}
	return c
}

// validateDirectoryPath checks for path traversal attempts and returns an error if the path is unsafe
func validateDirectoryPath(path string) error {
	if path == "" {
		return fmt.Errorf("directory path is empty")
	}
	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal detected in directory path")
	}
	// Additional safety checks
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}
	// Ensure the path is not pointing to sensitive system directories
	sensitivePaths := []string{
		"/etc", "/var", "/usr", "/root", "/boot", "/lib", "/sbin", "/bin",
	}
	absPathLower := strings.ToLower(absPath)
	for _, sensitive := range sensitivePaths {
		if strings.HasPrefix(absPathLower, strings.ToLower(sensitive)) {
			return fmt.Errorf("directory path points to sensitive system directory: %s", sensitive)
		}
	}
	return nil
}

func (c *CVEPayloadCorrelator) TopTemplates(n int) []string {
	if !c.available {
		return c.fallbackTemplates(n)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var paths []string
	for _, rec := range c.rankedTemplates {
		if rec.TemplatePath != "" {
			paths = append(paths, rec.TemplatePath)
		}
		if len(paths) >= n {
			break
		}
	}
	if len(paths) == 0 {
		return c.fallbackTemplates(n)
	}
	return paths
}

func (c *CVEPayloadCorrelator) RankForTarget(framework, server string, n int) []string {
	if !c.available {
		return c.fallbackTemplates(n)
	}
	fw := strings.ToLower(framework)
	srv := strings.ToLower(server)
	c.mu.RLock()
	defer c.mu.RUnlock()
	var matched, generic []*CVERecord
	for _, rec := range c.rankedTemplates {
		tp := strings.ToLower(rec.TemplatePath)
		isRelevant := strings.Contains(tp, fw) || strings.Contains(tp, srv) ||
			strings.Contains(tp, "apache") || strings.Contains(tp, "nginx") || strings.Contains(tp, "iis")
		if fw == "" || isRelevant {
			matched = append(matched, rec)
		} else {
			generic = append(generic, rec)
		}
	}
	ordered := append(matched, generic...)
	var paths []string
	for _, rec := range ordered {
		if rec.TemplatePath != "" {
			paths = append(paths, rec.TemplatePath)
		}
		if len(paths) >= n {
			break
		}
	}
	return paths
}

func RunNucleiRanked(target, framework, server string, correlator *CVEPayloadCorrelator) string {
	if correlator == nil || !correlator.available {
		out, _ := runNucleiCmd(target, "cves/")
		return out
	}
	templates := correlator.RankForTarget(framework, server, 50)
	if len(templates) == 0 {
		out, _ := runNucleiCmd(target, "cves/")
		return out
	}
	out, _ := runNucleiCmd(target, strings.Join(templates, ","))
	return out
}

func runNucleiCmd(target, templates string) (string, error) {
	var stdout, stderr bytes.Buffer
	spec := security.CommandSpec{Binary: "nuclei", Args: []string{"-u", target, "-t", templates, "-severity", "critical,high,medium", "-silent", "-no-color", "-timeout", "60", "-rate-limit", "50"}}
	validated := security.ValidateCommand(spec)
	if validated.Err != nil {
		logger.Error(fmt.Sprintf("[CVECorrelator] Nuclei command validation failed: %v", validated.Err))
		return "", validated.Err
	}
	cmd := exec.Command(validated.Binary, validated.Args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

func (c *CVEPayloadCorrelator) refresh(ctx context.Context) error {
	epss, _ := c.loadEPSS(ctx)
	kev, _ := c.loadKEV(ctx)
	if err := c.indexTemplates(epss, kev); err != nil {
		return fmt.Errorf("template indexing: %w", err)
	}
	c.lastRefresh = time.Now()
	return nil
}

func (c *CVEPayloadCorrelator) loadEPSS(ctx context.Context) (map[string]float64, error) {
	cacheFile := filepath.Join(c.cacheDir, fmt.Sprintf("epss_%s.csv", time.Now().Format("2006-01-02")))
	if data, err := os.ReadFile(cacheFile); err == nil {
		return parseEPSSCSV(data), nil
	}
	url := fmt.Sprintf("https://epss.cyentia.com/epss_scores-%s.csv.gz", time.Now().Format("2006-01-02"))
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	data, err := io.ReadAll(io.LimitReader(gz, 50*1024*1024))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cacheFile, data, 0600); err != nil {
		logger.Error(fmt.Sprintf("[CVECorrelator] Failed to write EPSS cache: %v", err))
	}
	logger.Info(fmt.Sprintf("[CVECorrelator] EPSS downloaded (%d bytes)", len(data)))
	return parseEPSSCSV(data), nil
}

func parseEPSSCSV(data []byte) map[string]float64 {
	scores := make(map[string]float64)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.HasPrefix(strings.ToLower(line), "cve,") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(parts[0]))
		score, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err == nil {
			scores[cve] = score
		}
	}
	return scores
}

func (c *CVEPayloadCorrelator) loadKEV(ctx context.Context) (map[string]bool, error) {
	cacheFile := filepath.Join(c.cacheDir, "kev.json")
	if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		if data, err := os.ReadFile(cacheFile); err == nil {
			return parseKEVJSON(data), nil
		}
	}
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cacheFile, data, 0600); err != nil {
		logger.Error(fmt.Sprintf("[CVECorrelator] Failed to write KEV cache: %v", err))
	}
	logger.Info(fmt.Sprintf("[CVECorrelator] CISA KEV downloaded (%d bytes)", len(data)))
	return parseKEVJSON(data), nil
}

func parseKEVJSON(data []byte) map[string]bool {
	var catalog struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil
	}
	kev := make(map[string]bool, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		kev[strings.ToUpper(v.CveID)] = true
	}
	return kev
}

func (c *CVEPayloadCorrelator) indexTemplates(epss map[string]float64, kev map[string]bool) error {
	cvesDir := filepath.Join(c.templatesDir, "cves")
	if _, err := os.Stat(cvesDir); os.IsNotExist(err) {
		return fmt.Errorf("nuclei cves/ not found at %s", cvesDir)
	}
	newMap := make(map[string]*CVERecord)
	filepath.Walk(cvesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		cveIDs := cveRegexp.FindAllString(content, -1)
		if len(cveIDs) == 0 {
			return nil
		}
		severity := extractYAMLField(content, "severity")
		relPath, _ := filepath.Rel(c.templatesDir, path)
		for _, rawCVE := range cveIDs {
			cve := strings.ToUpper(rawCVE)
			rec := &CVERecord{CVEID: cve, Severity: severity, TemplatePath: relPath}
			if epss != nil {
				rec.EPSSScore = epss[cve]
			}
			if kev != nil {
				rec.KEV = kev[cve]
			}
			rec.SynthScore = synthScore(rec)
			if existing, ok := newMap[cve]; !ok || rec.SynthScore > existing.SynthScore {
				newMap[cve] = rec
			}
		}
		return nil
	})
	ranked := make([]*CVERecord, 0, len(newMap))
	for _, rec := range newMap {
		ranked = append(ranked, rec)
	}
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].SynthScore > ranked[j].SynthScore
	})
	c.mu.Lock()
	c.cveMap = newMap
	c.rankedTemplates = ranked
	c.mu.Unlock()
	logger.Info(fmt.Sprintf("[CVECorrelator] Indexed %d CVE templates", len(ranked)))
	return nil
}

func synthScore(rec *CVERecord) float64 {
	s := rec.EPSSScore * 0.6
	if rec.KEV {
		s += 0.30
	}
	switch strings.ToLower(rec.Severity) {
	case "critical":
		s += 0.10
	case "high":
		s += 0.07
	case "medium":
		s += 0.03
	}
	return s
}

func extractYAMLField(content, field string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		prefix := field + ":"
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

func (c *CVEPayloadCorrelator) fallbackTemplates(n int) []string {
	if _, err := os.Stat(filepath.Join(c.templatesDir, "cves")); err == nil {
		return []string{filepath.Join(c.templatesDir, "cves")}
	}
	return []string{"cves/"}
}

func (c *CVEPayloadCorrelator) dailyRefresher() {
	for {
		now := time.Now().UTC()
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 5, 0, 0, time.UTC)
		time.Sleep(time.Until(next))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		c.refresh(ctx)
		cancel()
	}
}
