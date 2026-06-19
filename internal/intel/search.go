package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var exploitDBRateLimiter = &RateLimiter{
	mu:          sync.Mutex{},
	lastReq:     time.Time{},
	minInterval: 2 * time.Second,
	maxRetries:  3,
}

type RateLimiter struct {
	mu          sync.Mutex
	lastReq     time.Time
	minInterval time.Duration
	maxRetries  int
}

func (rl *RateLimiter) Wait() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.lastReq)
	if elapsed < rl.minInterval {
		time.Sleep(rl.minInterval - elapsed)
	}
	rl.lastReq = time.Now()
}

func (rl *RateLimiter) Backoff(attempt int) {
	delay := time.Duration(attempt+1) * 5 * time.Second
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	time.Sleep(delay)
}

type CVESearch struct {
	client *http.Client
}

type CVEItem struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss"`
	Published   string   `json:"published"`
	References  []string `json:"references"`
}

type NVDResponse struct {
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
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
			Published  string `json:"published"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type ExploitDBEntry struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Type        string `json:"type"`
	Platform    string `json:"platform"`
	Author      string `json:"author"`
	Date        string `json:"date"`
	Description string `json:"description"`
}

type WebSearch struct {
	client *http.Client
}

func NewCVESearch() *CVESearch {
	return &CVESearch{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *CVESearch) Search(ctx context.Context, query string, limit int) ([]CVEItem, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	params := url.Values{
		"keywordSearch":  {query},
		"resultsPerPage": {fmt.Sprintf("%d", limit)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://services.nvd.nist.gov/rest/json/cves/2.0?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("cve: create request: %w", err)
	}
	req.Header.Set("User-Agent", "AresEngine/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cve: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cve: read: %w", err)
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("cve: parse: %w", err)
	}

	var items []CVEItem
	for _, v := range nvdResp.Vulnerabilities {
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		severity := "N/A"
		var cvss float64
		if len(v.CVE.Metrics.CVSSMetricV31) > 0 {
			cvss = v.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			severity = v.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		} else if len(v.CVE.Metrics.CVSSMetricV30) > 0 {
			cvss = v.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			severity = v.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
		}
		var refs []string
		for _, r := range v.CVE.References {
			refs = append(refs, r.URL)
		}
		items = append(items, CVEItem{
			ID:          v.CVE.ID,
			Description: desc,
			Severity:    severity,
			CVSS:        cvss,
			Published:   v.CVE.Published,
			References:  refs,
		})
	}
	return items, nil
}

func NewExploitDBSearch() *ExploitDBEntry {
	return &ExploitDBEntry{}
}

func SearchExploitDB(ctx context.Context, query string, limit int) ([]ExploitDBEntry, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	params := url.Values{
		"q": {query},
	}

	var lastErr error
	for attempt := 0; attempt <= exploitDBRateLimiter.maxRetries; attempt++ {
		if attempt > 0 {
			exploitDBRateLimiter.Backoff(attempt)
		}
		exploitDBRateLimiter.Wait()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://www.exploit-db.com/search?"+params.Encode(), nil)
		if err != nil {
			return nil, fmt.Errorf("exploitdb: create request: %w", err)
		}
		req.Header.Set("User-Agent", "AresEngine/1.0")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 429 {
			resp.Body.Close()
			lastErr = fmt.Errorf("rate limited by ExploitDB")
			continue
		}

		defer resp.Body.Close()

		var entries []ExploitDBEntry
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			entries = []ExploitDBEntry{
				{
					ID:          "N/A",
					Title:       fmt.Sprintf("Search results for: %s", query),
					Description: "See https://www.exploit-db.com for full results",
					Type:        "search",
					Platform:    "multiple",
					Date:        time.Now().Format("2006-01-02"),
				},
			}
		}
		if len(entries) > limit {
			entries = entries[:limit]
		}
		return entries, nil
	}

	return nil, fmt.Errorf("exploitdb: all retries exhausted: %w", lastErr)
}

func NewWebSearch() *WebSearch {
	return &WebSearch{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (w *WebSearch) Search(ctx context.Context, query, engine string) (string, error) {
	engine = strings.ToLower(engine)
	var searchURL string
	switch engine {
	case "google":
		searchURL = fmt.Sprintf("https://www.google.com/search?q=%s", url.QueryEscape(query))
	case "bing":
		searchURL = fmt.Sprintf("https://www.bing.com/search?q=%s", url.QueryEscape(query))
	case "duckduckgo":
		searchURL = fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(query))
	default:
		searchURL = fmt.Sprintf("https://www.google.com/search?q=%s", url.QueryEscape(query))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return "", fmt.Errorf("websearch: create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := w.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("websearch: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("websearch: read: %w", err)
	}

	text := string(body)
	lines := strings.Split(text, "\n")
	var results []string
	maxLines := 50
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && len(trimmed) > 30 {
			results = append(results, trimmed)
			if len(results) >= maxLines {
				break
			}
		}
	}
	return strings.Join(results, "\n"), nil
}

func FormatCVESearchResults(items []CVEItem) string {
	var b strings.Builder
	for _, item := range items {
		b.WriteString(fmt.Sprintf("[%s] CVSS %.1f (%s)\n", item.ID, item.CVSS, item.Severity))
		b.WriteString(fmt.Sprintf("  %s\n", item.Description))
		b.WriteString(fmt.Sprintf("  Published: %s\n", item.Published))
		for _, ref := range item.References {
			b.WriteString(fmt.Sprintf("  Ref: %s\n", ref))
		}
	}
	return b.String()
}

func FormatExploitResults(entries []ExploitDBEntry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("[%s] %s (%s/%s)\n", e.ID, e.Title, e.Type, e.Platform))
		if e.Description != "" {
			b.WriteString(fmt.Sprintf("  %s\n", e.Description))
		}
	}
	return b.String()
}
