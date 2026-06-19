package oob

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type CorrelatedCallback struct {
	Token    string
	ScanID   string
	Protocol string
	SourceIP string
	Payload  string
	Time     time.Time
}

type callbackResult struct {
	callbacks []Callback
	token     string
}

type Correlator struct {
	mu      sync.RWMutex
	oob     *OOBServer
	pending sync.Map // Map[string]string: token -> scanID
	results sync.Map // Map[string]chan callbackResult: token -> channel
	timeout time.Duration
	stopCh  chan struct{}
}

func NewCorrelator(oobServer *OOBServer) *Correlator {
	c := &Correlator{
		oob:     oobServer,
		timeout: 10 * time.Minute,
		stopCh:  make(chan struct{}),
	}
	go c.pollLoop()
	return c
}

func (c *Correlator) SetTimeout(d time.Duration) {
	c.mu.Lock()
	c.timeout = d
	c.mu.Unlock()
}

func (c *Correlator) RegisterScan(scanID string) string {
	token := c.oob.NewToken()
	c.pending.Store(token, scanID)
	return token
}

func (c *Correlator) RegisterScanWithSignedToken(scanID string) string {
	token := c.oob.NewSignedToken(scanID)
	c.pending.Store(token, scanID)
	return token
}

func (c *Correlator) ScanForToken(token string) string {
	if val, ok := c.pending.Load(token); ok {
		return val.(string)
	}
	return ""
}

func (c *Correlator) WaitForCallback(ctx context.Context, token string) (*CorrelatedCallback, error) {
	ch := make(chan callbackResult, 1)
	c.results.Store(token, ch)

	c.mu.RLock()
	timeout := c.timeout
	c.mu.RUnlock()

	defer func() {
		c.results.Delete(token)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-ch:
		if len(res.callbacks) == 0 {
			return nil, fmt.Errorf("no callback for token %s", res.token)
		}
		cb := res.callbacks[0]
		return &CorrelatedCallback{
			Token:    cb.Token,
			ScanID:   c.ScanForToken(res.token),
			Protocol: cb.Protocol,
			SourceIP: cb.SourceIP,
			Payload:  cb.Payload,
			Time:     cb.ReceivedAt,
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("callback timeout for token %s", token)
	}
}

func (c *Correlator) UnregisterScan(scanID string) {
	c.pending.Range(func(key, value any) bool {
		token := key.(string)
		sid := value.(string)
		if sid == scanID {
			c.pending.Delete(token)
			if ch, ok := c.results.Load(token); ok {
				close(ch.(chan callbackResult))
				c.results.Delete(token)
			}
		}
		return true
	})
}

func (c *Correlator) pollLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
		}
		c.results.Range(func(key, value any) bool {
			token := key.(string)
			ch := value.(chan callbackResult)
			callbacks := c.oob.callbacks[token]
			if len(callbacks) > 0 {
				select {
				case ch <- callbackResult{callbacks: callbacks, token: token}:
				default:
				}
			}
			return true
		})

		c.mu.RLock()
		timeout := c.timeout
		c.mu.RUnlock()
		cutoff := time.Now().Add(-timeout)

		c.pending.Range(func(key, value any) bool {
			token := key.(string)
			exists := false
			c.oob.mu.RLock()
			if cbs, ok := c.oob.callbacks[token]; ok && len(cbs) > 0 {
				if cbs[len(cbs)-1].ReceivedAt.After(cutoff) {
					exists = true
				}
			}
			c.oob.mu.RUnlock()
			if !exists && c.oob.HasCallback(token) {
				c.oob.mu.RLock()
				cbs := c.oob.callbacks[token]
				c.oob.mu.RUnlock()
				if len(cbs) == 0 || cbs[len(cbs)-1].ReceivedAt.Before(cutoff) {
					logger.Info(fmt.Sprintf("[OOB-Correlator] Cleaning stale token: %s", token))
				}
			}
			return true
		})
	}
}

func (c *Correlator) Stop() {
	close(c.stopCh)
}

func (c *Correlator) PendingCount() int {
	count := 0
	c.pending.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
