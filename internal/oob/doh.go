package oob

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
)

var blockedDoHErrors = []string{"resolved via DoH:"}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	return false
}

type DoHFallback struct {
	providers        []string
	client           *http.Client
	useLocalResolver bool
}

func NewDoHFallback() *DoHFallback {
	return &DoHFallback{
		providers: []string{
			"https://dns.google/resolve",
			"https://cloudflare-dns.com/dns-query",
			"https://dns.quad9.net:5053/dns-query",
		},
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12},
			},
		},
	}
}

func NewDoHFallbackWithProviders(providers []string) *DoHFallback {
	d := NewDoHFallback()
	if len(providers) > 0 {
		d.providers = providers
	}
	return d
}

func (d *DoHFallback) SetProviders(providers []string) {
	d.providers = providers
}

func (d *DoHFallback) SetUseLocalResolver(use bool) {
	d.useLocalResolver = use
}

func (d *DoHFallback) Resolve(ctx context.Context, domain string) (string, error) {
	if d.useLocalResolver {
		addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err != nil {
			return "", fmt.Errorf("local resolver failed for %s: %w", domain, err)
		}
		if len(addrs) == 0 {
			return "", fmt.Errorf("local resolver returned no addresses for %s", domain)
		}
		return fmt.Sprintf("resolved via local: %s -> %s", domain, strings.Join(addrs, ", ")), nil
	}

	logger.Info(fmt.Sprintf("[DoH] PRIVACY NOTE: DNS query for %s will be sent to third-party DoH providers", domain))

	query := fmt.Sprintf("type=A&name=%s", url.QueryEscape(domain))

	for _, provider := range d.providers {
		fullURL := provider + "?" + query
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			logger.Warn("DoH: failed to create request", logger.Fields{"provider": provider, "error": err})
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := d.client.Do(req)
		if err != nil {
			logger.Warn("DoH: request failed", logger.Fields{"provider": provider, "error": err})
			continue
		}

		if resp.StatusCode != 200 {
			logger.Warn("DoH: non-200 response", logger.Fields{"provider": provider, "status": resp.StatusCode})
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			logger.Warn("DoH: failed to read response body", logger.Fields{"provider": provider, "error": err})
			continue
		}
		content := string(body)
		if strings.Contains(content, "Answer") || strings.Contains(content, "data") {
			truncated := content
			if len(truncated) > 500 {
				truncated = truncated[:500] + "..."
			}
			return fmt.Sprintf("resolved via DoH: %s", truncated), nil
		}
	}
	return "", fmt.Errorf("DoH resolution failed for %s", domain)
}

func (d *DoHFallback) Callback(token, vulnType string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	domain := fmt.Sprintf("%s.%s.oob.callback", token, vulnType)
	_, err := d.Resolve(ctx, domain)
	return err
}

func (d *DoHFallback) IsBlocked() bool {
	for _, provider := range d.providers {
		req, err := http.NewRequest("GET", provider+"?type=A&name=test.dns", nil)
		if err != nil {
			logger.Warn("DoH: failed to create blocked check request", logger.Fields{"provider": provider, "error": err})
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := d.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return false
			}
		}
	}
	return true
}
