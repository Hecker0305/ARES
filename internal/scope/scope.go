package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// isHardBlocked checks targets against a non-overridable hard-block list.
// These are always blocked regardless of scope configuration.
var hardBlockedCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"::1/128",
	"fe80::/10",
	"fc00::/7",
}

var hardBlockedIPs = []string{
	"169.254.169.254", // AWS/GCP/Azure metadata
	"100.100.100.200", // Alibaba cloud metadata
	"0.0.0.0",
}

var hardBlockedSuffixes = []string{
	".local",
	".localhost",
	".internal",
	".int",
}

type Scope struct {
	target    string
	pinnedIPs map[string][]net.IP
	pinnedAt  time.Time
	pinnedMu  sync.RWMutex
	dnsTTL    time.Duration
}

func NewScope(target string) *Scope {
	s := &Scope{
		target:    target,
		pinnedIPs: make(map[string][]net.IP),
		dnsTTL:    5 * time.Minute,
	}
	s.pinDNS(target)
	return s
}

func (s *Scope) pinDNS(target string) {
	host := extractHost(target)
	if host == "" {
		return
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return
	}

	s.pinnedMu.Lock()
	defer s.pinnedMu.Unlock()
	s.pinnedIPs[host] = ips
	s.pinnedAt = time.Now()
}

func (s *Scope) Summary() string {
	return fmt.Sprintf("target=%s", s.target)
}

type OwnershipStatus int

const (
	OwnershipUnverified OwnershipStatus = iota
	OwnershipConfirmed
	OwnershipSkipped
)

type Enforcer struct {
	targets            []string
	pinnedIPs          map[string][]net.IP
	pinnedAt           time.Time
	dnsTTL             time.Duration
	mu                 sync.RWMutex
	ownershipStatus    OwnershipStatus
	ownershipTarget    string
	ownershipConfirmed bool
}

func NewEnforcer(targets []string) *Enforcer {
	e := &Enforcer{
		targets:            targets,
		pinnedIPs:          make(map[string][]net.IP),
		dnsTTL:             5 * time.Minute,
		ownershipStatus:    OwnershipUnverified,
	}
	// Pin DNS for all targets at creation time
	for _, t := range targets {
		e.pinDNS(t)
	}
	return e
}

func (e *Enforcer) RequireOwnership(target string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ownershipTarget = target
	return e.ownershipStatus != OwnershipConfirmed
}

func (e *Enforcer) ConfirmOwnership(target string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if target == "" {
		return fmt.Errorf("target is required for ownership confirmation")
	}
	e.ownershipTarget = target
	e.ownershipStatus = OwnershipConfirmed
	e.ownershipConfirmed = true
	return nil
}

func (e *Enforcer) SkipOwnership() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ownershipStatus = OwnershipSkipped
}

func (e *Enforcer) OwnershipVerified() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ownershipConfirmed
}

func (e *Enforcer) OwnershipStatusString() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	switch e.ownershipStatus {
	case OwnershipConfirmed:
		return "confirmed:" + e.ownershipTarget
	case OwnershipSkipped:
		return "skipped"
	default:
		return "unverified"
	}
}

func (e *Enforcer) pinDNS(target string) {
	// Don't re-pin if within TTL
	if time.Since(e.pinnedAt) < e.dnsTTL && len(e.pinnedIPs) > 0 {
		return
	}
	host := extractHost(target)
	if host == "" {
		return
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return
	}
	// Track host by its target string for lookup
	e.pinnedIPs[host] = ips
	e.pinnedAt = time.Now()
}

func (e *Enforcer) IsAllowed(target string) bool {
	// 0. Ownership must be confirmed or skipped before any scanning
	e.mu.RLock()
	ownershipOK := e.ownershipConfirmed || e.ownershipStatus == OwnershipSkipped
	e.mu.RUnlock()
	if !ownershipOK {
		return false
	}

	// 1. Always block hard-blocked resources (metadata, loopback, private)
	if isHardBlocked(target) {
		return false
	}

	host := extractHost(target)
	if host == "" {
		return false
	}

	// 2. If we have pinned targets, verify against them
	e.mu.RLock()
	targets := e.targets
	e.mu.RUnlock()

	if len(targets) == 0 {
		return true
	}

	// 3. Check if host matches any scope target (exact or subdomain match)
	hostLower := strings.ToLower(host)
	for _, t := range targets {
		targetHost := extractHost(t)
		if targetHost == "" {
			continue
		}
		targetLower := strings.ToLower(targetHost)
		if hostLower == targetLower || strings.HasSuffix(hostLower, "."+targetLower) {
			return true
		}
	}

	// 4. DNS pinning: check if host resolves to an IP within scope
	e.mu.Lock()
	e.pinDNS(target)
	e.mu.Unlock()

	e.mu.RLock()
	pinned := e.pinnedIPs[host]
	e.mu.RUnlock()

	for _, ip := range pinned {
		for _, t := range targets {
			targetHost := extractHost(t)
			if targetHost == "" {
				continue
			}
			e.mu.RLock()
			targetIPs := e.pinnedIPs[targetHost]
			e.mu.RUnlock()
			for _, tip := range targetIPs {
				if ip.Equal(tip) {
					return true
				}
			}
		}
	}

	return false
}

func isHardBlocked(target string) bool {
	host := extractHost(target)
	if host == "" {
		host = target
	}

	// Check hard-blocked IPs
	for _, hb := range hardBlockedIPs {
		if strings.EqualFold(host, hb) {
			return true
		}
	}

	// Check hard-blocked suffixes
	for _, suffix := range hardBlockedSuffixes {
		if strings.HasSuffix(strings.ToLower(host), suffix) {
			return true
		}
	}

	// Parse as IP for CIDR checks
	ip := net.ParseIP(host)
	if ip == nil {
		if addrs, err := net.LookupIP(host); err == nil {
			for _, addr := range addrs {
				if ipInCIDRs(addr, hardBlockedCIDRs) {
					return true
				}
			}
		}
		return false
	}
	return ipInCIDRs(ip, hardBlockedCIDRs)
}

func ipInCIDRs(ip net.IP, cidrs []string) bool {
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func extractHost(target string) string {
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	if u.Host != "" {
		return u.Hostname()
	}
	return target
}
