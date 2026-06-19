package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu       sync.Mutex
	cond     *sync.Cond
	tokens   float64
	maxToken float64
	refillHz float64
	lastTime time.Time
}

func New(rps float64, burst int) *Limiter {
	if rps <= 0 {
		rps = 1
	}
	l := &Limiter{
		tokens:   float64(burst),
		maxToken: float64(burst),
		refillHz: rps,
		lastTime: time.Now(),
	}
	l.cond = sync.NewCond(&l.mu)
	return l
}

func (l *Limiter) Wait() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for {
		now := time.Now()
		elapsed := now.Sub(l.lastTime).Seconds()
		l.tokens += elapsed * l.refillHz
		if l.tokens > l.maxToken {
			l.tokens = l.maxToken
		}
		l.lastTime = now

		if l.tokens >= 1.0 {
			l.tokens--
			return
		}

		wait := time.Duration((1.0-l.tokens)/l.refillHz*1000) * time.Millisecond

		go func() {
			time.Sleep(wait)
			l.cond.Broadcast()
		}()

		l.cond.Wait()
	}
}

func (l *Limiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastTime).Seconds()
	l.tokens += elapsed * l.refillHz
	if l.tokens > l.maxToken {
		l.tokens = l.maxToken
	}
	l.lastTime = now

	if l.tokens >= 1.0 {
		l.tokens--
		return true
	}
	return false
}

func Stealth() *Limiter { return New(1, 2) }

func Normal() *Limiter { return New(10, 20) }

func Aggressive() *Limiter { return New(50, 100) }
