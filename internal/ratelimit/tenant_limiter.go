package ratelimit

import (
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type TenantLimiter struct {
	mu           sync.RWMutex
	tenants      map[string]*Limiter
	defaultRPS   float64
	defaultBurst int
	planLimits   map[string]PlanLimit
}

type PlanLimit struct {
	RPS     float64
	Burst   int
	Daily   int
	Monthly int
}

func NewTenantLimiter(defaultRPS float64, defaultBurst int) *TenantLimiter {
	return &TenantLimiter{
		tenants:      make(map[string]*Limiter),
		defaultRPS:   defaultRPS,
		defaultBurst: defaultBurst,
		planLimits:   make(map[string]PlanLimit),
	}
}

func (tl *TenantLimiter) SetPlanLimit(planID string, limit PlanLimit) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.planLimits[planID] = limit
}

func (tl *TenantLimiter) GetLimiter(tenantID, planID string) *Limiter {
	tl.mu.RLock()
	limiter, ok := tl.tenants[tenantID]
	tl.mu.RUnlock()

	if ok {
		return limiter
	}

	tl.mu.Lock()
	defer tl.mu.Unlock()

	limiter, ok = tl.tenants[tenantID]
	if ok {
		return limiter
	}

	limit, hasPlan := tl.planLimits[planID]
	if hasPlan {
		limiter = New(limit.RPS, limit.Burst)
	} else {
		limiter = New(tl.defaultRPS, tl.defaultBurst)
	}

	tl.tenants[tenantID] = limiter
	return limiter
}

func (tl *TenantLimiter) Allow(tenantID, planID string) bool {
	limiter := tl.GetLimiter(tenantID, planID)
	return limiter.TryAcquire()
}

func (tl *TenantLimiter) RemoveTenant(tenantID string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	delete(tl.tenants, tenantID)
}

func (tl *TenantLimiter) Cleanup() {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	for tenantID, limiter := range tl.tenants {
		limiter.mu.Lock()
		if time.Since(limiter.lastTime) > 24*time.Hour {
			delete(tl.tenants, tenantID)
		}
		limiter.mu.Unlock()
	}
}

type SlidingWindowLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	maxReqs  int
	requests map[string][]time.Time
}

func NewSlidingWindowLimiter(window time.Duration, maxReqs int) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		window:   window,
		maxReqs:  maxReqs,
		requests: make(map[string][]time.Time),
	}
}

func (sw *SlidingWindowLimiter) Allow(key string) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-sw.window)

	timestamps := sw.requests[key]

	validTimestamps := make([]time.Time, 0, len(timestamps))
	for _, ts := range timestamps {
		if ts.After(windowStart) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	if len(validTimestamps) >= sw.maxReqs {
		sw.requests[key] = validTimestamps
		return false
	}

	validTimestamps = append(validTimestamps, now)
	sw.requests[key] = validTimestamps
	return true
}

func (sw *SlidingWindowLimiter) Cleanup() {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-sw.window)

	for key, timestamps := range sw.requests {
		validTimestamps := make([]time.Time, 0, len(timestamps))
		for _, ts := range timestamps {
			if ts.After(windowStart) {
				validTimestamps = append(validTimestamps, ts)
			}
		}
		if len(validTimestamps) == 0 {
			delete(sw.requests, key)
		} else {
			sw.requests[key] = validTimestamps
		}
	}
}

type GlobalRateLimiter struct {
	mu          sync.RWMutex
	tenantLimit *TenantLimiter
	globalLimit *SlidingWindowLimiter
	ipLimit     *SlidingWindowLimiter
	stopCh      chan struct{}
}

type GlobalConfig struct {
	DefaultRPS    float64
	DefaultBurst  int
	GlobalWindow  time.Duration
	GlobalMaxReqs int
	IPWindow      time.Duration
	IPMaxReqs     int
	PlanLimits    map[string]PlanLimit
}

func NewGlobalRateLimiter(cfg GlobalConfig) *GlobalRateLimiter {
	rl := &GlobalRateLimiter{
		tenantLimit: NewTenantLimiter(cfg.DefaultRPS, cfg.DefaultBurst),
		globalLimit: NewSlidingWindowLimiter(cfg.GlobalWindow, cfg.GlobalMaxReqs),
		ipLimit:     NewSlidingWindowLimiter(cfg.IPWindow, cfg.IPMaxReqs),
		stopCh:      make(chan struct{}),
	}

	for planID, limit := range cfg.PlanLimits {
		rl.tenantLimit.SetPlanLimit(planID, limit)
	}

	go rl.cleanupLoop()

	return rl
}

func (rl *GlobalRateLimiter) Allow(tenantID, planID, ip string) bool {
	if !rl.ipLimit.Allow(ip) {
		logger.Debug("[RateLimit] IP rate limit exceeded", logger.Fields{"ip": ip})
		return false
	}

	if tenantID != "" {
		if !rl.tenantLimit.Allow(tenantID, planID) {
			logger.Debug("[RateLimit] Tenant rate limit exceeded", logger.Fields{
				"tenant": tenantID,
				"plan":   planID,
			})
			return false
		}
	}

	if !rl.globalLimit.Allow("global") {
		logger.Debug("[RateLimit] Global rate limit exceeded")
		return false
	}

	return true
}

func (rl *GlobalRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.tenantLimit.Cleanup()
			rl.globalLimit.Cleanup()
			rl.ipLimit.Cleanup()
		}
	}
}

func (rl *GlobalRateLimiter) Stop() {
	close(rl.stopCh)
}

func DefaultPlanLimits() map[string]PlanLimit {
	return map[string]PlanLimit{
		"free": {
			RPS:     1,
			Burst:   5,
			Daily:   100,
			Monthly: 3000,
		},
		"pro": {
			RPS:     10,
			Burst:   50,
			Daily:   10000,
			Monthly: 300000,
		},
		"enterprise": {
			RPS:     100,
			Burst:   500,
			Daily:   -1,
			Monthly: -1,
		},
	}
}
