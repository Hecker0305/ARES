package fuzz

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/exploit"
	"github.com/ares/engine/internal/security"
)

type FuzzConfig struct {
	Mutations    int
	Concurrency  int
	Timeout      time.Duration
	AdaptiveMode bool
	WAFDetection bool
	MaxMemoryMB  int64
}

type FuzzResult struct {
	URL         string
	Payload     string
	Mutations   []string
	StatusCode  int
	Response    string
	DetectedWAF bool
	Success     bool
}

type AdaptiveFuzzer struct {
	cfg        FuzzConfig
	mutator    *exploit.PayloadMutator
	wafSig     []string
	history    map[string]int
	mu         sync.RWMutex
	maxHistory int
}

const defaultMaxHistory = 10000

func NewAdaptiveFuzzer(cfg FuzzConfig) *AdaptiveFuzzer {
	if cfg.MaxMemoryMB <= 0 {
		cfg.MaxMemoryMB = 512
	}
	return &AdaptiveFuzzer{
		cfg:        cfg,
		mutator:    exploit.NewPayloadMutator(),
		wafSig:     []string{"ModSecurity", "Sucuri", "Cloudflare", "Akamai", "Imperva"},
		history:    make(map[string]int),
		maxHistory: defaultMaxHistory,
	}
}

func (f *AdaptiveFuzzer) Run(ctx context.Context, targetURL string, basePayloads []string) []FuzzResult {
	results := make(chan FuzzResult, 100)
	var wg sync.WaitGroup

	sem := make(chan struct{}, f.cfg.Concurrency)

	for _, payload := range basePayloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			variants := f.mutateAdaptive(p)
			for _, variant := range variants {
				result := f.sendPayload(ctx, targetURL, variant)
				results <- result
			}
		}(payload)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []FuzzResult
	for r := range results {
		allResults = append(allResults, r)
	}

	return allResults
}

func (f *AdaptiveFuzzer) mutateAdaptive(base string) []string {
	baseVariants := f.mutator.Mutate(base)

	var adaptive []string

	for i := 0; i < f.cfg.Mutations; i++ {
		variant := base
		for j := 0; j < 3; j++ {
			mutType, err := security.SecureRandIntn(6)
			if err != nil {
				mutType = j % 6
			}
			switch mutType {
			case 0:
				variant = f.obfuscate(variant)
			case 1:
				variant = f.caseSwap(variant)
			case 2:
				variant = f.nullByte(variant)
			case 3:
				variant = f.unicodeWrap(variant)
			case 4:
				variant = f.commentInject(variant)
			case 5:
				variant = f.splitToken(variant)
			}
		}
		adaptive = append(adaptive, variant)
	}

	return append(baseVariants, adaptive...)
}

func (f *AdaptiveFuzzer) obfuscate(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c == '%' {
			result.WriteString("%%25")
		} else {
			result.WriteRune(c)
		}
	}
	return result.String()
}

func (f *AdaptiveFuzzer) caseSwap(s string) string {
	runes := []rune(s)
	for i := range runes {
		upper := strings.ToUpper(string(runes[i]))
		runes[i] = []rune(upper)[0]
	}
	return string(runes)
}

func (f *AdaptiveFuzzer) nullByte(s string) string {
	var result strings.Builder
	for _, c := range s {
		result.WriteRune(c)
		result.WriteRune(0)
	}
	return result.String()
}

func (f *AdaptiveFuzzer) unicodeWrap(s string) string {
	homoglyphs := map[rune]rune{
		'a': 'а',
		'e': 'е',
		'i': 'і',
		'o': 'о',
		'u': 'ս',
		'c': 'с',
		'p': 'р',
		'x': 'х',
		'y': 'у',
	}
	return strings.Map(func(r rune) rune {
		if h, ok := homoglyphs[r]; ok {
			return h
		}
		return r
	}, s)
}

func (f *AdaptiveFuzzer) commentInject(s string) string {
	if len(s) > 10 {
		return s[:5] + "/**/" + s[5:]
	}
	return s
}

func (f *AdaptiveFuzzer) splitToken(s string) string {
	return strings.ReplaceAll(s, "=", "=[]")
}

func (f *AdaptiveFuzzer) checkMemoryLimit() bool {
	if f.cfg.MaxMemoryMB <= 0 {
		return true
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	currentMB := int64(m.Alloc / 1024 / 1024)
	return currentMB < f.cfg.MaxMemoryMB
}

var fuzzResultPool = &sync.Pool{
	New: func() any {
		return &FuzzResult{}
	},
}

func (f *AdaptiveFuzzer) sendPayload(ctx context.Context, targetURL, payload string) FuzzResult {
	resultPtr := fuzzResultPool.Get().(*FuzzResult)
	defer fuzzResultPool.Put(resultPtr)
	*resultPtr = FuzzResult{}
	resultPtr.URL = targetURL
	resultPtr.Payload = payload
	resultPtr.Success = false

	f.mu.Lock()
	f.history[payload]++
	f.mu.Unlock()

	if !f.checkMemoryLimit() {
		return *resultPtr
	}

	if err := security.ValidateURL(targetURL); err != nil {
		return *resultPtr
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return *resultPtr
	}

	q := parsed.Query()
	q.Set("q", payload)
	parsed.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return *resultPtr
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Ares/2.0)")

	client := &http.Client{
		Timeout: f.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		resultPtr.DetectedWAF = f.detectWAF(err.Error())
		return *resultPtr
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		resultPtr.StatusCode = resp.StatusCode
		resultPtr.DetectedWAF = f.detectWAF(resultPtr.Response)
		resultPtr.Success = resp.StatusCode >= 200 && resp.StatusCode < 500
		return *resultPtr
	}
	resultPtr.StatusCode = resp.StatusCode
	resultPtr.Response = string(body)
	resultPtr.DetectedWAF = f.detectWAF(resultPtr.Response)
	resultPtr.Success = resp.StatusCode >= 200 && resp.StatusCode < 500

	return *resultPtr
}

func (f *AdaptiveFuzzer) detectWAF(response string) bool {
	for _, sig := range f.wafSig {
		if strings.Contains(response, sig) {
			return true
		}
	}
	return false
}

func (f *AdaptiveFuzzer) LearnFromResponse(payload, response string, success bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if success {
		f.history[payload] += 10
	} else {
		if f.history[payload] > 0 {
			f.history[payload]--
		}
	}

	if len(f.history) > f.maxHistory {
		f.pruneHistory()
	}
}

func (f *AdaptiveFuzzer) pruneHistory() {
	type kv struct {
		key   string
		score int
	}
	items := make([]kv, 0, len(f.history))
	for k, v := range f.history {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].score < items[j].score
	})
	trim := len(items) - f.maxHistory + (f.maxHistory / 10)
	for i := 0; i < trim && i < len(items); i++ {
		delete(f.history, items[i].key)
	}
}
