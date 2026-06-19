package runtime

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type Budget struct {
	MaxTokens     int64 `json:"max_tokens"`
	MaxMemoryMB   int64 `json:"max_memory_mb"`
	MaxGoroutines int32 `json:"max_goroutines"`
	MaxExecutions int64 `json:"max_executions"`
	MaxReplays    int64 `json:"max_replays"`
	MaxBrowserOps int64 `json:"max_browser_ops"`
	MaxScans      int32 `json:"max_scans"`
}

type Usage struct {
	TokensUsed     int64 `json:"tokens_used"`
	MemoryUsedMB   int64 `json:"memory_used_mb"`
	GoroutinesUsed int32 `json:"goroutines_used"`
	ExecutionsUsed int64 `json:"executions_used"`
	ReplaysUsed    int64 `json:"replays_used"`
	BrowserOpsUsed int64 `json:"browser_ops_used"`
	ScansActive    int32 `json:"scans_active"`
}

type Governor struct {
	mu          sync.Mutex
	budget      Budget
	usage       Usage
	goroutineCh chan struct{}
	scanSem     chan struct{}
	perTarget   map[string]*Usage
	startTime   time.Time
}

func New(budget Budget) *Governor {
	ch := make(chan struct{}, budget.MaxGoroutines)
	for i := int32(0); i < budget.MaxGoroutines; i++ {
		ch <- struct{}{}
	}

	scanLimit := budget.MaxScans
	if scanLimit <= 0 {
		scanLimit = 10
	}
	scanSem := make(chan struct{}, scanLimit)

	return &Governor{
		budget:      budget,
		goroutineCh: ch,
		scanSem:     scanSem,
		perTarget:   make(map[string]*Usage),
		startTime:   time.Now(),
	}
}

func DefaultBudget() Budget {
	return Budget{
		MaxTokens:     1000000,
		MaxMemoryMB:   1024,
		MaxGoroutines: 50,
		MaxExecutions: 1000,
		MaxReplays:    100,
		MaxBrowserOps: 50,
		MaxScans:      10,
	}
}

func (g *Governor) AcquireToken(n int64) bool {
	if n <= 0 {
		return false
	}
	for {
		cur := atomic.LoadInt64(&g.usage.TokensUsed)
		if n > math.MaxInt64-cur {
			return false
		}
		if cur+n > g.budget.MaxTokens {
			return false
		}
		if atomic.CompareAndSwapInt64(&g.usage.TokensUsed, cur, cur+n) {
			return true
		}
	}
}

func (g *Governor) ReleaseToken(n int64) {
	if n <= 0 {
		return
	}
	for {
		cur := atomic.LoadInt64(&g.usage.TokensUsed)
		release := n
		if release > cur {
			release = cur
		}
		if atomic.CompareAndSwapInt64(&g.usage.TokensUsed, cur, cur-release) {
			break
		}
	}
}

func (g *Governor) AcquireGoroutine() bool {
	select {
	case <-g.goroutineCh:
		atomic.AddInt32(&g.usage.GoroutinesUsed, 1)
		return true
	default:
		return false
	}
}

func (g *Governor) ReleaseGoroutine() {
	select {
	case g.goroutineCh <- struct{}{}:
	default:
	}
	for {
		cur := atomic.LoadInt32(&g.usage.GoroutinesUsed)
		if cur <= 0 {
			break
		}
		if atomic.CompareAndSwapInt32(&g.usage.GoroutinesUsed, cur, cur-1) {
			break
		}
	}
}

func (g *Governor) AcquireExecution() bool {
	for {
		cur := atomic.LoadInt64(&g.usage.ExecutionsUsed)
		if cur+1 > g.budget.MaxExecutions {
			return false
		}
		if atomic.CompareAndSwapInt64(&g.usage.ExecutionsUsed, cur, cur+1) {
			return true
		}
	}
}

func (g *Governor) ReleaseExecution() {
	for {
		cur := atomic.LoadInt64(&g.usage.ExecutionsUsed)
		if cur <= 0 {
			break
		}
		if atomic.CompareAndSwapInt64(&g.usage.ExecutionsUsed, cur, cur-1) {
			break
		}
	}
}

func (g *Governor) AcquireReplay() bool {
	for {
		cur := atomic.LoadInt64(&g.usage.ReplaysUsed)
		if cur+1 > g.budget.MaxReplays {
			return false
		}
		if atomic.CompareAndSwapInt64(&g.usage.ReplaysUsed, cur, cur+1) {
			return true
		}
	}
}

func (g *Governor) ReleaseReplay() {
	for {
		cur := atomic.LoadInt64(&g.usage.ReplaysUsed)
		if cur <= 0 {
			break
		}
		if atomic.CompareAndSwapInt64(&g.usage.ReplaysUsed, cur, cur-1) {
			break
		}
	}
}

func (g *Governor) AcquireBrowserOp() bool {
	for {
		cur := atomic.LoadInt64(&g.usage.BrowserOpsUsed)
		if cur+1 > g.budget.MaxBrowserOps {
			return false
		}
		if atomic.CompareAndSwapInt64(&g.usage.BrowserOpsUsed, cur, cur+1) {
			return true
		}
	}
}

func (g *Governor) ReleaseBrowserOp() {
	for {
		cur := atomic.LoadInt64(&g.usage.BrowserOpsUsed)
		if cur <= 0 {
			break
		}
		if atomic.CompareAndSwapInt64(&g.usage.BrowserOpsUsed, cur, cur-1) {
			break
		}
	}
}

func (g *Governor) AcquireScan() bool {
	select {
	case g.scanSem <- struct{}{}:
		atomic.AddInt32(&g.usage.ScansActive, 1)
		return true
	default:
		return false
	}
}

func (g *Governor) ReleaseScan() {
	select {
	case <-g.scanSem:
	default:
	}
	for {
		cur := atomic.LoadInt32(&g.usage.ScansActive)
		if cur <= 0 {
			break
		}
		if atomic.CompareAndSwapInt32(&g.usage.ScansActive, cur, cur-1) {
			break
		}
	}
}

func (g *Governor) TargetBudget(target string) *Usage {
	g.mu.Lock()
	defer g.mu.Unlock()
	u, ok := g.perTarget[target]
	if !ok {
		u = &Usage{}
		g.perTarget[target] = u
	}
	return u
}

func (g *Governor) CanAccept(target string) error {
	g.mu.Lock()
	u, ok := g.perTarget[target]
	if !ok {
		u = &Usage{}
		g.perTarget[target] = u
	}
	targetExec := u.ExecutionsUsed
	g.mu.Unlock()

	if targetExec >= g.budget.MaxExecutions/10 {
		return fmt.Errorf("target %s: execution quota exhausted", target)
	}
	if g.Usage().TokensUsed >= g.budget.MaxTokens {
		return fmt.Errorf("global token budget exhausted")
	}
	if g.Usage().ExecutionsUsed >= g.budget.MaxExecutions {
		return fmt.Errorf("global execution budget exhausted")
	}
	return nil
}

func (g *Governor) CanAcceptScan() error {
	active := atomic.LoadInt32(&g.usage.ScansActive)
	maxScans := g.budget.MaxScans
	if maxScans <= 0 {
		maxScans = 10
	}
	if active >= maxScans {
		return fmt.Errorf("max concurrent scans reached (%d/%d), reject until capacity frees", active, maxScans)
	}
	return nil
}

func (g *Governor) Usage() Usage {
	return Usage{
		TokensUsed:     atomic.LoadInt64(&g.usage.TokensUsed),
		MemoryUsedMB:   atomic.LoadInt64(&g.usage.MemoryUsedMB),
		GoroutinesUsed: atomic.LoadInt32(&g.usage.GoroutinesUsed),
		ExecutionsUsed: atomic.LoadInt64(&g.usage.ExecutionsUsed),
		ReplaysUsed:    atomic.LoadInt64(&g.usage.ReplaysUsed),
		BrowserOpsUsed: atomic.LoadInt64(&g.usage.BrowserOpsUsed),
		ScansActive:    atomic.LoadInt32(&g.usage.ScansActive),
	}
}

func (g *Governor) Budget() Budget {
	return g.budget
}

func (g *Governor) Uptime() time.Duration {
	return time.Since(g.startTime)
}

func (g *Governor) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	atomic.StoreInt64(&g.usage.TokensUsed, 0)
	atomic.StoreInt64(&g.usage.MemoryUsedMB, 0)
	atomic.StoreInt32(&g.usage.GoroutinesUsed, 0)
	atomic.StoreInt64(&g.usage.ExecutionsUsed, 0)
	atomic.StoreInt64(&g.usage.ReplaysUsed, 0)
	atomic.StoreInt64(&g.usage.BrowserOpsUsed, 0)
	atomic.StoreInt32(&g.usage.ScansActive, 0)
	g.perTarget = make(map[string]*Usage)
}
