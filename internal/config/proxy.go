package config

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"net/url"
	"sync"
)

type ProxyRotator struct {
	mu        sync.RWMutex
	proxies   []*url.URL
	current   int
	transport *http.Transport
}

func NewProxyRotator(proxyURLs []string) *ProxyRotator {
	pr := &ProxyRotator{
		current: 0,
	}
	for _, p := range proxyURLs {
		if parsed, err := url.Parse(p); err == nil {
			pr.proxies = append(pr.proxies, parsed)
		}
	}
	pr.transport = &http.Transport{}
	if len(pr.proxies) > 0 {
		pr.transport.Proxy = http.ProxyURL(pr.proxies[0])
	}
	return pr
}

func (pr *ProxyRotator) Next() *url.URL {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if len(pr.proxies) == 0 {
		return nil
	}
	pr.current = (pr.current + 1) % len(pr.proxies)
	proxy := pr.proxies[pr.current]
	pr.transport.Proxy = http.ProxyURL(proxy)
	return proxy
}

func (pr *ProxyRotator) Random() *url.URL {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.proxies) == 0 {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pr.proxies))))
	if err != nil {
		return pr.proxies[0]
	}
	return pr.proxies[n.Int64()]
}

func (pr *ProxyRotator) Transport() *http.Transport {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.transport
}

func (pr *ProxyRotator) Count() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return len(pr.proxies)
}
