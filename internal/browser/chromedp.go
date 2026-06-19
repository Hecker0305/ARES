package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// XSSProbe defines an XSS test payload and how to detect execution.
type XSSProbe struct {
	Name     string
	Payload  string
	DetectJS string // JS expression to evaluate — returns "true" if XSS executed
}

var DefaultXSSProbes = []XSSProbe{
	{Name: "img_onerror", Payload: `"><img src=x onerror=window.__ARES_XSS__=1>`, DetectJS: `window.__ARES_XSS__ === 1 ? "true" : "false"`},
	{Name: "svg_onload", Payload: `'><svg onload=window.__ARES_XSS__=2>`, DetectJS: `window.__ARES_XSS__ === 2 ? "true" : "false"`},
	{Name: "body_onload", Payload: `"><body onload=window.__ARES_XSS__=3>`, DetectJS: `window.__ARES_XSS__ === 3 ? "true" : "false"`},
	{Name: "div_onmouseover", Payload: `"><div onmouseover=window.__ARES_XSS__=4>`, DetectJS: `window.__ARES_XSS__ === 4 ? "true" : "false"`},
	{Name: "script_alert", Payload: `"><script>window.__ARES_XSS__=5</script>`, DetectJS: `window.__ARES_XSS__ === 5 ? "true" : "false"`},
	{Name: "javascript_url", Payload: `javascript:window.__ARES_XSS__=6`, DetectJS: `window.__ARES_XSS__ === 6 ? "true" : "false"`},
	{Name: "onfocus_autofocus", Payload: `"><input onfocus=window.__ARES_XSS__=7 autofocus>`, DetectJS: `window.__ARES_XSS__ === 7 ? "true" : "false"`},
	{Name: "onerror_autofocus", Payload: `"><input onfocus=window.__ARES_XSS__=8 autofocus onerror=window.__ARES_XSS__=8>`, DetectJS: `window.__ARES_XSS__ === 8 ? "true" : "false"`},
	{Name: "details_on toggle", Payload: `"><details open ontoggle=window.__ARES_XSS__=9>`, DetectJS: `window.__ARES_XSS__ === 9 ? "true" : "false"`},
}

type DOMXSSResult struct {
	URL        string
	ProbeName  string
	Payload    string
	Executed   bool
	Confidence float64
	Reflected  string
	ConsoleLog []string
}

type ChromeBrowser struct {
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration
	mu      sync.Mutex
}

func NewChromeBrowser(timeout time.Duration) (*ChromeBrowser, error) {
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-extensions", true),
	)

	ctx, cancel := chromedp.NewContext(allocCtx)

	startupCtx, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer startupCancel()
	if err := chromedp.Run(startupCtx); err != nil {
		cancel()
		allocCancel()
		return nil, fmt.Errorf("browser startup: %w", err)
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &ChromeBrowser{
		ctx:     ctx,
		cancel:  func() { cancel(); allocCancel() },
		timeout: timeout,
	}, nil
}

func (b *ChromeBrowser) Screenshot(url string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1920, 1080),
		chromedp.Navigate(url),
		chromedp.FullScreenshot(&buf, 100),
	); err != nil {
		return nil, fmt.Errorf("screenshot %s: %w", url, err)
	}
	return buf, nil
}

func (b *ChromeBrowser) GetHTML(url string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var html string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.OuterHTML("html", &html),
	); err != nil {
		return "", fmt.Errorf("get html %s: %w", url, err)
	}
	return html, nil
}

func (b *ChromeBrowser) GetText(url string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var text string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Text("body", &text, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("get text %s: %w", url, err)
	}
	return strings.TrimSpace(text), nil
}

func (b *ChromeBrowser) Evaluate(url string, js string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var result string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Evaluate(js, &result),
	); err != nil {
		return "", fmt.Errorf("evaluate on %s: %w", url, err)
	}
	return result, nil
}

func (b *ChromeBrowser) Click(url string, selector string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var html string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		chromedp.Click(selector, chromedp.ByQuery),
		chromedp.OuterHTML("html", &html),
	); err != nil {
		return "", fmt.Errorf("click %s on %s: %w", selector, url, err)
	}
	return html, nil
}

func (b *ChromeBrowser) FillAndSubmit(url string, formSelector, submitSelector string, formData map[string]string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var tasks chromedp.Tasks
	tasks = append(tasks, chromedp.Navigate(url))
	tasks = append(tasks, chromedp.WaitVisible(formSelector, chromedp.ByQuery))

	for name, value := range formData {
		sel := formSelector + " [name=\"" + name + "\"]"
		tasks = append(tasks, chromedp.SetValue(sel, value, chromedp.ByQuery))
	}

	if submitSelector != "" {
		tasks = append(tasks, chromedp.Click(submitSelector, chromedp.ByQuery))
	}

	var html string
	tasks = append(tasks, chromedp.OuterHTML("html", &html))

	if err := chromedp.Run(ctx, tasks); err != nil {
		return "", fmt.Errorf("fill and submit on %s: %w", url, err)
	}
	return html, nil
}

func (b *ChromeBrowser) GetCookies(url string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var cookies []*network.Cookie
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			cookies, err = network.GetCookies().Do(ctx)
			return err
		}),
	); err != nil {
		return "", fmt.Errorf("get cookies for %s: %w", url, err)
	}

	data, err := json.Marshal(cookies)
	if err != nil {
		return "", fmt.Errorf("marshal cookies: %w", err)
	}
	return string(data), nil
}

func (b *ChromeBrowser) SetCookie(url, name, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			expr := cdp.TimeSinceEpoch(time.Now().Add(24 * time.Hour))
			return network.SetCookie(name, value).
				WithURL(url).
				WithExpires(&expr).
				Do(ctx)
		}),
	); err != nil {
		return fmt.Errorf("set cookie %s on %s: %w", name, url, err)
	}
	return nil
}

func (b *ChromeBrowser) DetectSPA(url string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	var result string
	js := `(function() {
		var hasRouter = !!(window.__ROUTER__ || window.__NUXT__ || window.__NEXT_ROOT__ || window.__REACT_DEVTOOLS_GLOBAL_HOOK__);
		var hasPushState = typeof history.pushState === 'function' && history.pushState.toString().indexOf('[native code]') === -1;
		var routerScripts = Array.from(document.querySelectorAll('script[src]')).filter(function(s) {
			return /(react|vue|angular|svelte|router|history|browser|app)\.(min\.)?js/i.test(s.src);
		}).length > 0;
		var appRoot = !!document.querySelector('#root, #app, #__next, [data-reactroot], .app, [ng-app]');
		return JSON.stringify({
			spa: hasRouter || hasPushState || routerScripts || appRoot,
			indicators: {
				hasRouter: hasRouter,
				hasCustomPushState: hasPushState,
				hasRouterScripts: routerScripts,
				hasAppRoot: appRoot
			}
		});
	})()`

	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Evaluate(js, &result),
	); err != nil {
		return false, fmt.Errorf("detect spa %s: %w", url, err)
	}

	var parsed struct {
		SPA bool `json:"spa"`
	}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		return false, fmt.Errorf("parse spa detection result: %w", err)
	}
	return parsed.SPA, nil
}

func (b *ChromeBrowser) timeoutContext() (context.Context, context.CancelFunc) {
	if b.timeout > 0 {
		return context.WithTimeout(b.ctx, b.timeout)
	}
	return context.WithTimeout(b.ctx, 30*time.Second)
}

func (b *ChromeBrowser) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
		b.cancel = nil
	}
}

func (b *ChromeBrowser) consoleInterceptJS() string {
	return `
		window.__ARES_CONSOLE__ = [];
		(function() {
			var origError = console.error;
			console.error = function() {
				window.__ARES_CONSOLE__.push({type:'error', args:Array.prototype.slice.call(arguments).join(' ')});
				return origError.apply(console, arguments);
			};
			var origLog = console.log;
			console.log = function() {
				window.__ARES_CONSOLE__.push({type:'log', args:Array.prototype.slice.call(arguments).join(' ')});
				return origLog.apply(console, arguments);
			};
			var origWarn = console.warn;
			console.warn = function() {
				window.__ARES_CONSOLE__.push({type:'warn', args:Array.prototype.slice.call(arguments).join(' ')});
				return origWarn.apply(console, arguments);
			};
		})();
	`
}

func (b *ChromeBrowser) getConsoleLogJS() string {
	return `JSON.stringify(window.__ARES_CONSOLE__ || [])`
}

func (b *ChromeBrowser) injectProbe(urlStr, param, payload string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	q := u.Query()
	if param != "" {
		q.Set(param, payload)
	} else {
		q.Set("q", payload)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (b *ChromeBrowser) ScanDOMXSS(targetURL string, param string) ([]DOMXSSResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ctx, cancel := b.timeoutContext()
	defer cancel()

	consoleJS := b.consoleInterceptJS()
	getConsoleJS := b.getConsoleLogJS()

	var results []DOMXSSResult

	for _, probe := range DefaultXSSProbes {
		injectedURL := b.injectProbe(targetURL, param, probe.Payload)

		var html string
		var consoleRaw string
		var detected string

		tasks := chromedp.Tasks{
			chromedp.Navigate(injectedURL),
			chromedp.Evaluate(consoleJS, nil),
			chromedp.Sleep(500 * time.Millisecond),
			chromedp.Evaluate(probe.DetectJS, &detected),
			chromedp.Evaluate(getConsoleJS, &consoleRaw),
			chromedp.OuterHTML("html", &html),
		}

		if err := chromedp.Run(ctx, tasks); err != nil {
			results = append(results, DOMXSSResult{
				URL:       injectedURL,
				ProbeName: probe.Name,
				Payload:   probe.Payload,
				Executed:  false,
			})
			continue
		}

		executed := detected == "true"
		confidence := 0.0
		if executed {
			confidence = 0.95
		}

		var consoleEntries []string
		if consoleRaw != "" && consoleRaw != "null" {
			var entries []struct {
				Type string `json:"type"`
				Args string `json:"args"`
			}
			if err := json.Unmarshal([]byte(consoleRaw), &entries); err == nil {
				for _, e := range entries {
					consoleEntries = append(consoleEntries, fmt.Sprintf("[%s] %s", e.Type, e.Args))
				}
			}
		}

		reflected := ""
		if strings.Contains(html, probe.Payload) {
			idx := strings.Index(html, probe.Payload)
			start := idx - 40
			if start < 0 {
				start = 0
			}
			end := idx + len(probe.Payload) + 40
			if end > len(html) {
				end = len(html)
			}
			reflected = html[start:end]
			if !executed {
				confidence = 0.6
			}
		}

		results = append(results, DOMXSSResult{
			URL:        injectedURL,
			ProbeName:  probe.Name,
			Payload:    probe.Payload,
			Executed:   executed,
			Confidence: confidence,
			Reflected:  reflected,
			ConsoleLog: consoleEntries,
		})
	}

	return results, nil
}


