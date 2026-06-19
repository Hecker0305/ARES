package capability

import (
	"fmt"
	"sort"
	"sync"
)

var dangerousCapCombinations = map[string][]string{
	"shell.exec":    {"file.write", "network.raw", "exploit.run"},
	"file.write":    {"shell.exec", "system.modify", "file.delete"},
	"exploit.run":   {"shell.exec", "payload.send", "network.raw"},
	"network.raw":   {"shell.exec", "exploit.run", "file.write"},
	"system.modify": {"file.write", "shell.exec", "file.delete"},
}

const maxCapabilityChainDepth = 20

type Set struct {
	mu           sync.RWMutex
	allow        map[string]bool
	deny         map[string]bool
	maxAllowed   map[string]bool
	ceiling      int
	chainHistory []string
}

func New() *Set {
	return &Set{
		allow:      make(map[string]bool),
		deny:       make(map[string]bool),
		maxAllowed: make(map[string]bool),
		ceiling:    0,
	}
}

func (s *Set) Allow(caps ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range caps {
		if s.deny[c] {
			continue
		}
		s.allow[c] = true
		s.maxAllowed[c] = true
	}
	if s.ceiling == 0 {
		s.ceiling = len(s.allow)
	}
}

func (s *Set) Deny(caps ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range caps {
		s.deny[c] = true
		delete(s.allow, c)
		delete(s.maxAllowed, c)
	}
}

func (s *Set) Can(cap string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.deny[cap] {
		return false
	}
	if !s.allow[cap] {
		return false
	}
	return true
}

func (s *Set) Allowed() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for c := range s.allow {
		if !s.deny[c] {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Set) Denied() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for c := range s.deny {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func (s *Set) MaxAllowed() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for c := range s.maxAllowed {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func (s *Set) SetCeiling(max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ceiling = max
}

func (s *Set) recordChainStep(step string) {
	s.chainHistory = append(s.chainHistory, step)
	if len(s.chainHistory) > maxCapabilityChainDepth {
		s.chainHistory = s.chainHistory[len(s.chainHistory)-maxCapabilityChainDepth:]
	}
}

func (s *Set) CheckChainEscalation(chain []string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.checkChainEscalationLocked(chain)
}

func (s *Set) checkChainEscalationLocked(chain []string) error {

	if len(chain) > maxCapabilityChainDepth {
		return fmt.Errorf("capability chain exceeds maximum depth of %d", maxCapabilityChainDepth)
	}

	combined := make(map[string]bool)
	for _, cap := range chain {
		combined[cap] = true
	}

	for cap, dangerous := range dangerousCapCombinations {
		if !combined[cap] {
			continue
		}
		for _, d := range dangerous {
			if combined[d] {
				return fmt.Errorf("dangerous capability combination detected: %s + %s", cap, d)
			}
		}
	}

	if s.ceiling > 0 && len(combined) > s.ceiling {
		return fmt.Errorf("combined capabilities (%d) exceed ceiling (%d)", len(combined), s.ceiling)
	}

	for cap := range combined {
		if s.deny[cap] {
			return fmt.Errorf("chain includes denied capability: %s", cap)
		}
		if !s.maxAllowed[cap] && !s.allow[cap] {
			return fmt.Errorf("chain includes capability outside max allowed set: %s", cap)
		}
	}

	return nil
}

func Merge(sets ...*Set) (*Set, error) {
	result := New()

	allDenied := make(map[string]bool)
	allMaxAllowed := make(map[string]bool)
	minCeiling := 0

	for _, s := range sets {
		s.mu.RLock()
		for c := range s.deny {
			allDenied[c] = true
		}
		for c := range s.maxAllowed {
			allMaxAllowed[c] = true
		}
		if s.ceiling > 0 {
			if minCeiling == 0 || s.ceiling < minCeiling {
				minCeiling = s.ceiling
			}
		}
		s.mu.RUnlock()
	}

	for _, s := range sets {
		for _, c := range s.Allowed() {
			if allDenied[c] {
				continue
			}
			result.allow[c] = true
		}
	}

	for c := range allDenied {
		result.deny[c] = true
		delete(result.allow, c)
	}

	result.maxAllowed = allMaxAllowed
	result.ceiling = minCeiling

	if result.ceiling > 0 && len(result.allow) > result.ceiling {
		return nil, fmt.Errorf("merged capabilities (%d) exceed minimum ceiling (%d)", len(result.allow), result.ceiling)
	}

	for cap, dangerous := range dangerousCapCombinations {
		if !result.allow[cap] {
			continue
		}
		for _, d := range dangerous {
			if result.allow[d] {
				return nil, fmt.Errorf("merge creates dangerous capability combination: %s + %s", cap, d)
			}
		}
	}

	return result, nil
}

var BrowserAgent = func() *Set {
	s := New()
	s.Allow("dom.read", "form.submit", "cookie.read", "navigation")
	s.Deny("shell.exec", "file.write", "network.raw")
	s.SetCeiling(4)
	return s
}()

var ReconAgent = func() *Set {
	s := New()
	s.Allow("dns.resolve", "port.scan", "http.request", "tech.detect")
	s.Deny("shell.exec", "file.write", "exploit.run")
	s.SetCeiling(4)
	return s
}()

var ExploitAgent = func() *Set {
	s := New()
	s.Allow("exploit.run", "payload.send", "http.request", "network.connect")
	s.Deny("file.delete", "system.modify")
	s.SetCeiling(4)
	return s
}()

var VerifierAgent = func() *Set {
	s := New()
	s.Allow("replay", "http.request", "evidence.collect")
	s.Deny("shell.exec", "file.write", "exploit.run", "network.raw")
	s.SetCeiling(3)
	return s
}()
