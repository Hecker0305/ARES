package websecurity

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/ares/engine/internal/detection"
	"github.com/ares/engine/internal/ratelimit"
)

var (
	rl   *ratelimit.Limiter
	rlon sync.Once
)

func initLimiter() {
	rlon.Do(func() {
		rl = ratelimit.Stealth()
	})
}

func throttledExec(name string, arg ...string) *exec.Cmd {
	initLimiter()
	rl.Wait()
	return exec.Command(name, arg...)
}

type WebSecurityEngine struct {
	Native *detection.Detector
}

func NewWebSecurityEngine() *WebSecurityEngine {
	return &WebSecurityEngine{
		Native: detection.NewDetector(0),
	}
}

func SetRateLimit(rps float64, burst int) {
	initLimiter()
	rl = ratelimit.New(rps, burst)
}

func formatResults(results []detection.Result) string {
	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("[%s] %s via %s (confidence: %.1f%%)\n  Payload: %s\n  Evidence: %s\n",
			r.VulnType, r.Target, r.Parameter, r.Confidence*100, r.Payload, r.Evidence))
	}
	return sb.String()
}

func (e *WebSecurityEngine) NativeSQLi(targetURL, param string) (string, error) {
	results := e.Native.DetectSQLi(context.Background(), targetURL, param)
	if len(results) == 0 {
		return "No SQL injection detected", nil
	}
	return formatResults(results), nil
}

func (e *WebSecurityEngine) NativeXSS(targetURL, param string) (string, error) {
	results := e.Native.DetectXSS(context.Background(), targetURL, param)
	if len(results) == 0 {
		return "No XSS detected", nil
	}
	return formatResults(results), nil
}

func (e *WebSecurityEngine) NativeSSRF(targetURL, param, oobURL string) (string, error) {
	results := e.Native.DetectSSRF(context.Background(), targetURL, param, oobURL)
	if len(results) == 0 {
		return "No SSRF detected", nil
	}
	return formatResults(results), nil
}

func (e *WebSecurityEngine) NativeCmdInjection(targetURL, param string) (string, error) {
	results := e.Native.DetectCmdInjection(context.Background(), targetURL, param)
	if len(results) == 0 {
		return "No command injection detected", nil
	}
	return formatResults(results), nil
}

func (e *WebSecurityEngine) NativePathTraversal(targetURL, param string) (string, error) {
	results := e.Native.DetectPathTraversal(context.Background(), targetURL, param)
	if len(results) == 0 {
		return "No path traversal detected", nil
	}
	return formatResults(results), nil
}
