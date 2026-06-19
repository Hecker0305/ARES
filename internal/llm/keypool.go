package llm

import (
	"errors"
	"sync"
	"sync/atomic"
)

type APIKey struct {
	Key       string
	Provider  string
	InUse     bool
	FailCount int32
}

type KeyPool struct {
	mu    sync.Mutex
	keys  []*APIKey
	index int32
}

func NewKeyPool() *KeyPool {
	return &KeyPool{keys: make([]*APIKey, 0)}
}

func (p *KeyPool) Add(key, provider string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = append(p.keys, &APIKey{
		Key:      key,
		Provider: provider,
	})
}

func (p *KeyPool) Next() (*APIKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) == 0 {
		return nil, errors.New("no API keys in pool")
	}
	idx := atomic.AddInt32(&p.index, 1) % int32(len(p.keys))
	key := p.keys[idx]
	key.InUse = true
	return key, nil
}

func (p *KeyPool) RecordFailure(key *APIKey) {
	if key == nil {
		return
	}
	atomic.AddInt32(&key.FailCount, 1)
	if key.FailCount > 3 {
		p.mu.Lock()
		defer p.mu.Unlock()
		for i, k := range p.keys {
			if k == key {
				p.keys = append(p.keys[:i], p.keys[i+1:]...)
				break
			}
		}
	}
}

func (p *KeyPool) RecordSuccess(key *APIKey) {
	if key == nil {
		return
	}
	key.InUse = false
}

func (p *KeyPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.keys)
}
