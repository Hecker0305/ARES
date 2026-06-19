package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/uuid"
)

type BrowserConfig struct {
	Timeout   time.Duration
	Headless  bool
	UserAgent string
	Proxy     string
	Incognito bool
	CSP       string
	DisableJS bool
}

type Page struct {
	URL        string
	Title      string
	Screenshot []byte
	Data       map[string]string
	Cookies    map[string]string
}

type Browser struct {
	cfg   BrowserConfig
	pages map[string]*Page
	mu    sync.RWMutex
}

func NewBrowser(cfg BrowserConfig) *Browser {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	if cfg.CSP == "" {
		cfg.CSP = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; font-src 'none'; media-src 'none'; object-src 'none';"
	}
	return &Browser{
		cfg:   cfg,
		pages: make(map[string]*Page),
	}
}

func (b *Browser) Navigate(ctx context.Context, u string) (*Page, error) {
	if _, err := security.SanitizeURL(u); err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	navCtx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()

	data, err := fetchURLWithContext(navCtx, u)
	if err != nil {
		return nil, fmt.Errorf("navigate to %s: %w", u, err)
	}

	title := extractTitle(data)
	page := &Page{
		URL:   u,
		Title: title,
		Data:  map[string]string{},
	}
	if len(b.pages) >= 100 {
		for u := range b.pages {
			delete(b.pages, u)
			break
		}
	}
	b.pages[u] = page
	return page, nil
}

func (b *Browser) Screenshot(ctx context.Context, _ string) ([]byte, error) {
	b.mu.RLock()
	var targetURL string
	urls := make([]string, 0, len(b.pages))
	for u := range b.pages {
		urls = append(urls, u)
	}
	b.mu.RUnlock()

	if len(urls) > 0 {
		sort.Strings(urls)
		targetURL = urls[0]
	}

	if targetURL == "" {
		return nil, fmt.Errorf("no page navigated — call Navigate first")
	}

	if err := security.ValidateURL(targetURL); err != nil {
		return nil, fmt.Errorf("invalid screenshot URL: %w", err)
	}

	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("headless screenshot not supported on Windows")
	}

	path := filepath.Join(os.TempDir(), uuid.New())
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("mkdir screenshots dir: %w", err)
	}

	sanitizedPath := filepath.Clean(path)
	if !strings.HasPrefix(sanitizedPath, os.TempDir()) {
		return nil, fmt.Errorf("screenshot path not in temp directory")
	}

	tmpDir := os.TempDir()
	args := []string{
		"--headless", "--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-javascript",
		"--disable-plugins",
		"--disable-extensions",
		"--js-flags=--no-expose-wasm",
	}
	if b.cfg.DisableJS {
		args = append(args, "--disable-javascript")
	}
	args = append(args, "--screenshot="+sanitizedPath, "--window-size=1920,1080", "--")
	args = append(args, targetURL)

	validated := security.ValidateCommand(security.CommandSpec{Binary: "chromium-browser"})
	if validated.Err != nil {
		return nil, fmt.Errorf("browser binary validation failed: %w", validated.Err)
	}
	browserPath := validated.Binary

	screenshotCtx, screenshotCancel := context.WithTimeout(ctx, 30*time.Second)
	defer screenshotCancel()

	cmd := exec.CommandContext(screenshotCtx, browserPath, args...)
	cmd.Dir = tmpDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("screenshot: %w (stderr: %s)", err, stderr.String())
	}

	data, err := os.ReadFile(sanitizedPath)
	if err != nil {
		return nil, fmt.Errorf("read screenshot: %w", err)
	}
	return data, nil
}

func (b *Browser) Evaluate(ctx context.Context, script string) (string, error) {
	b.mu.RLock()
	var targetURL string
	urls := make([]string, 0, len(b.pages))
	for u := range b.pages {
		urls = append(urls, u)
	}
	b.mu.RUnlock()

	if targetURL == "" {
		if len(urls) > 0 {
			sort.Strings(urls)
			targetURL = urls[0]
		} else {
			return "", fmt.Errorf("no page navigated")
		}
	}

	if err := validateScript(script); err != nil {
		return "", fmt.Errorf("script validation failed: %w", err)
	}

	return fmt.Sprintf("evaluate requested on %s: script length %d", targetURL[:min(len(targetURL), 100)], len(script)), nil
}

var dangerousJSPatterns = []string{
	"eval(", "Function(", "setTimeout(", "setInterval(",
	"document.write", "document.writeln", "innerHTML", "outerHTML",
	"insertAdjacentHTML", "document.cookie", "document.domain",
	"window.location", "location.href", "location.assign",
	"location.replace", "window.open", "open(",
	"__proto__", "constructor.prototype",
	"require(", "import(", "module.require",
	"child_process", "exec(", "execSync(", "spawn(",
	"fs.", "net.", "http.", "https.", "crypto.",
	"process.env", "process.exit", "process.kill",
	"XMLHttpRequest", "fetch(",
	"alert(", "confirm(", "prompt(",
}

func validateScript(script string) error {
	if script == "" {
		return fmt.Errorf("empty script")
	}
	if len(script) > 10000 {
		return fmt.Errorf("script exceeds maximum length (10000 chars)")
	}
	lower := strings.ToLower(script)
	for _, pattern := range dangerousJSPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return fmt.Errorf("dangerous JS pattern detected: %s", pattern)
		}
	}
	return nil
}

func (b *Browser) SetCookie(name, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.pages) == 0 {
		return nil
	}
	urls := make([]string, 0, len(b.pages))
	for u := range b.pages {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	page := b.pages[urls[0]]
	if page.Cookies == nil {
		page.Cookies = make(map[string]string)
	}
	page.Cookies[name] = value
	return nil
}

func (b *Browser) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for url := range b.pages {
		delete(b.pages, url)
	}

	return nil
}

type SessionManager struct {
	browser  *Browser
	sessions map[string]*Session
	mu       sync.RWMutex
}

type Session struct {
	ID      string
	Cookies map[string]string
	Headers map[string]string
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

func (m *SessionManager) NewSession() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return uuid.New()
	}
	id := "session_" + hex.EncodeToString(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = &Session{
		ID:      id,
		Cookies: make(map[string]string),
		Headers: make(map[string]string),
	}
	return id
}

func (m *SessionManager) GetSession(id string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.sessions[id]
	if s == nil {
		return nil
	}
	cp := *s
	cp.Cookies = make(map[string]string, len(s.Cookies))
	for k, v := range s.Cookies {
		cp.Cookies[k] = v
	}
	cp.Headers = make(map[string]string, len(s.Headers))
	for k, v := range s.Headers {
		cp.Headers[k] = v
	}
	return &cp
}

func (m *SessionManager) SetCookie(sessionID, name, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.Cookies[name] = value
	}
}

func (m *SessionManager) SetHeader(sessionID, name, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.Headers[name] = value
	}
}

type PageAgent struct {
	browser *Browser
	scripts map[string]string
}

func NewPageAgent(browser *Browser) *PageAgent {
	return &PageAgent{
		browser: browser,
		scripts: map[string]string{
			"controller": defaultControllerScript,
			"discovery":  defaultDiscoveryScript,
		},
	}
}

const defaultControllerScript = `
(function() {
    var routes = [];
    document.querySelectorAll('a[href], form[action]').forEach(function(el) {
        var href = el.href || el.action;
        if (href && href !== '#' && !href.startsWith('javascript')) {
            routes.push(href);
        }
    });
    return JSON.stringify({
        links: Array.from(new Set(routes)).slice(0, 50),
        title: document.title,
        forms: document.querySelectorAll('form').length,
        scripts: Array.from(document.querySelectorAll('script[src]')).map(function(s) { return s.src; })
    });
})();
`

const defaultDiscoveryScript = `
(function() {
    var endpoints = [];
    var patterns = [
        /\/api\/[a-zA-Z0-9_/-]+/g,
        /\/v\d+\/[a-zA-Z0-9_/-]+/g,
        /\/graphql/g
    ];
    document.querySelectorAll('script').forEach(function(s) {
        var src = s.src || '';
        patterns.forEach(function(p) {
            var matches = src.match(p);
            if (matches) {
                endpoints = endpoints.concat(matches);
            }
        });
    });
    var xhr = new XMLHttpRequest();
    var originalFetch = window.fetch;
    var capturedEndpoints = [];
    window.fetch = function(url) {
        capturedEndpoints.push(url);
        return originalFetch.apply(this, arguments);
    };
    setTimeout(function() {
        window.fetch = originalFetch;
    }, 2000);
    return JSON.stringify({
        endpoints: Array.from(new Set(endpoints)),
        captured: capturedEndpoints.slice(0, 20)
    });
})();
`

func (a *PageAgent) Run(scriptName string) (string, error) {
	script, ok := a.scripts[scriptName]
	if !ok {
		return "", fmt.Errorf("unknown script: %s", scriptName)
	}
	return script, nil
}

func (a *PageAgent) RegisterScript(name, script string) {
	a.scripts[name] = script
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (b *Browser) FetchURL(ctx context.Context, fetchURL string) (*HTTPResponse, error) {
	if err := security.ValidateURL(fetchURL); err != nil {
		return nil, fmt.Errorf("invalid fetch URL: %w", err)
	}

	parsed, err := url.Parse(fetchURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	host := parsed.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return nil, fmt.Errorf("destination %s resolves to private IP %s", host, ip.String())
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fetchURL, nil)
	if err != nil {
		return nil, err
	}

	b.mu.RLock()
	urls := make([]string, 0, len(b.pages))
	for u := range b.pages {
		urls = append(urls, u)
	}
	b.mu.RUnlock()

	if len(urls) > 0 {
		sort.Strings(urls)
		for _, u := range urls {
			b.mu.RLock()
			page, ok := b.pages[u]
			b.mu.RUnlock()
			if ok {
				for name, val := range page.Data {
					req.Header.Set(name, val)
				}
				break
			}
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			redirectURL := req.URL.String()
			if err := security.ValidateURL(redirectURL); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		headers := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		return &HTTPResponse{
			StatusCode: resp.StatusCode,
			Headers:    headers,
			BodyText:   fmt.Sprintf("read body error: %v", err),
		}, nil
	}
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		BodyText:   string(body),
	}, nil
}

type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	BodyText   string
}

func fetchURL(url string) (string, error) {
	return fetchURLWithContext(context.Background(), url)
}

func fetchURLWithContext(ctx context.Context, url string) (string, error) {
	if verdict := security.GetK().ValidateAction(ctx, security.ActionRequest{
		Type:   security.ActionHTTPRequest,
		URL:    url,
		Source: "browser.fetchURLWithContext",
	}); verdict.Decision != security.DecisionAllow {
		return "", fmt.Errorf("kernel denied URL fetch: %s", verdict.Reason)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			if ip := net.ParseIP(req.URL.Hostname()); ip != nil {
				if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
					return fmt.Errorf("redirect to private IP blocked")
				}
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	idx := strings.Index(lower, "<title")
	if idx == -1 {
		return ""
	}
	start := idx + 6
	end := strings.Index(body[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := body[start+1 : start+end]
	title = strings.ReplaceAll(title, ">", "")
	return strings.TrimSpace(title)
}

func parseURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.String()
	}
	return rawURL
}

func isURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

func safeFilename(name string) string {
	var result strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result.WriteRune(c)
		}
	}
	if result.Len() == 0 {
		result.WriteString("page")
	}
	return result.String()
}
