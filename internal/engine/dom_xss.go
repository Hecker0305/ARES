package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
)

type DOMXSSResult struct {
	Confirmed bool
	Sink      string
	Evidence  string
	Payload   string
}

type DOMXSSScanner struct {
	sinks   []string
	markers []string
}

func NewDOMXSSScanner() *DOMXSSScanner {
	return &DOMXSSScanner{
		sinks: []string{
			"innerHTML",
			"outerHTML",
			"innerText",
			"document.write",
			"eval",
			"setTimeout",
			"setInterval",
			"Function",
			"location",
			"href",
			"src",
			"action",
			"formAction",
		},
		markers: []string{
			"ARES_XSS_1",
			"ARES_XSS_2",
			"ARES_XSS_3",
			"ARES_XSS_REFLECT",
			"ARES_XSS_COOKIE",
		},
	}
}

func (d *DOMXSSScanner) TestDOMXSS(ctx context.Context, url, payload string) (bool, string) {
	logger.Info(fmt.Sprintf("[DOMXSS] Testing URL: %s", url))

	markedPayload := d.injectMarkers(payload)
	sink := d.detectSink(url)

	logger.Info(fmt.Sprintf("[DOMXSS] Detected sink: %s", sink))
	logger.Info(fmt.Sprintf("[DOMXSS] Marked payload: %s", markedPayload))

	result := d.simulateBrowser(ctx, url, markedPayload)

	if result.Confirmed {
		logger.Info(fmt.Sprintf("[DOMXSS] XSS CONFIRMED at sink: %s", result.Sink))
		return true, result.Evidence
	}

	logger.Info("[DOMXSS] No XSS detected")
	return false, ""
}

func (d *DOMXSSScanner) injectMarkers(payload string) string {
	marked := payload

	markerCount := 0
	for _, marker := range d.markers {
		if strings.Contains(marked, marker) {
			continue
		}
		if markerCount >= 2 {
			break
		}
		marked = strings.Replace(marked, "<script>", "<script>var x='"+marker+"';", 1)
		markerCount++
	}

	if !strings.Contains(marked, "ARES_XSS") {
		marked = strings.Replace(marked, "<script>", "<script>var ares_marker='ARES_XSS_SAFE_TEST';", 1)
	}

	return marked
}

func (d *DOMXSSScanner) detectSink(url string) string {
	if strings.Contains(url, "#") {
		fragment := strings.Split(url, "#")[1]
		if strings.Contains(fragment, "=") || strings.Contains(fragment, "/") {
			return "location.hash"
		}
	}

	if strings.Contains(url, "callback") || strings.Contains(url, "cb") {
		return "callback"
	}

	if strings.Contains(url, "q=") || strings.Contains(url, "search=") {
		return "innerHTML"
	}

	if strings.Contains(url, "template=") || strings.Contains(url, "msg=") {
		return "innerHTML"
	}

	return "unknown"
}

func (d *DOMXSSScanner) simulateBrowser(ctx context.Context, targetURL, payload string) DOMXSSResult {
	result := DOMXSSResult{
		Payload:   payload,
		Sink:      d.detectSink(targetURL),
		Evidence:  "",
		Confirmed: false,
	}

	testURL := targetURL
	if strings.Contains(testURL, "=") {
		testURL = strings.Replace(testURL, strings.Split(testURL, "=")[1], payload, 1)
	} else if strings.Contains(testURL, "?") {
		testURL = testURL + "&q=" + payload
	} else {
		testURL = testURL + "?q=" + payload
	}

	client := &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}
	bodyStr := string(body)

	for _, marker := range d.markers {
		if strings.Contains(bodyStr, marker) {
			result.Confirmed = true
			result.Sink = d.detectSink(targetURL)
			result.Evidence = fmt.Sprintf("Marker '%s' reflected in response body", marker)
			return result
		}
	}

	if strings.Contains(bodyStr, payload) && (strings.Contains(bodyStr, "<script") || strings.Contains(bodyStr, "alert") || strings.Contains(bodyStr, "onerror") || strings.Contains(bodyStr, "onload")) {
		result.Confirmed = true
		result.Sink = d.detectSink(targetURL)
		result.Evidence = "Payload content reflected in response body"
		return result
	}

	if resp.StatusCode >= 500 {
		result.Evidence = "HTTP 500 error may indicate XSS injection"
		result.Sink = d.detectSink(targetURL)
	}

	return result
}

func (d *DOMXSSScanner) TestAllSinks(ctx context.Context, url string) []DOMXSSResult {
	var results []DOMXSSResult

	payloads := []string{
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"<body onload=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
	}

	for _, payload := range payloads {
		confirmed, evidence := d.TestDOMXSS(ctx, url, payload)
		results = append(results, DOMXSSResult{
			Confirmed: confirmed,
			Sink:      d.detectSink(url),
			Evidence:  evidence,
			Payload:   payload,
		})
	}

	return results
}

func (d *DOMXSSScanner) GetSinks() []string {
	return d.sinks
}

func (r *DOMXSSResult) String() string {
	return fmt.Sprintf("DOMXSS Result: Confirmed=%v, Sink=%s, Evidence=%s",
		r.Confirmed, r.Sink, r.Evidence)
}
