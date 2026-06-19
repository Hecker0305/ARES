package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct {
	mu              sync.Mutex
	visitors        map[string]*visitor
	rate            int
	burst           int
	cleanup         time.Duration
	trustedProxies  map[string]bool
	useForwardedFor bool
	stopCh          chan struct{}
}

type visitor struct {
	tokens   int
	lastSeen time.Time
	burst    int
}

func NewRateLimiter(rate, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		burst:    burst,
		cleanup:  10 * time.Minute,
		stopCh:   make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) isTrustedProxy(ip string) bool {
	if !rl.useForwardedFor {
		return false
	}
	return rl.trustedProxies[ip]
}

func (rl *RateLimiter) getClientIP(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	if !rl.isTrustedProxy(remoteIP) {
		return remoteIP
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		firstIP := xff
		for i, part := range splitXFF(xff) {
			if i == 0 {
				firstIP = part
				break
			}
		}
		return firstIP
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return remoteIP
}

func splitXFF(xff string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(xff); i++ {
		if xff[i] == ',' {
			parts = append(parts, xff[start:i])
			start = i + 1
		}
	}
	parts = append(parts, xff[start:])
	return parts
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	if !exists {
		rl.visitors[key] = &visitor{tokens: rl.burst, lastSeen: time.Now(), burst: rl.burst}
		return true
	}

	elapsed := time.Since(v.lastSeen)
	v.tokens += int(elapsed.Seconds() * float64(rl.rate))
	if v.tokens > v.burst {
		v.tokens = v.burst
	}
	v.lastSeen = time.Now()

	if v.tokens > 0 {
		v.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := rl.getClientIP(r)
		if !rl.Allow(key) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				if time.Since(v.lastSeen) > rl.cleanup {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}
