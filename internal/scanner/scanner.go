// Package scanner provides scan configuration, profiles, and engine execution
// for the ARES Engine autonomous penetration testing system.
package scanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

// Severity levels for scan findings
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ScanPhase represents a named phase in a scan execution.
type ScanPhase string

const (
	PhaseRecon        ScanPhase = "recon"
	PhaseDiscovery    ScanPhase = "discovery"
	PhaseVulnScan     ScanPhase = "vuln_scan"
	PhaseExploit      ScanPhase = "exploit"
	PhaseVerification ScanPhase = "verification"
	PhaseReporting    ScanPhase = "reporting"
)

// ScannerConfig defines runtime configuration for a scanner instance.
type ScannerConfig struct {
	Timeout        time.Duration `json:"timeout"`
	MaxParallelism int           `json:"max_parallelism"`
	RateLimit      float64       `json:"rate_limit"`
	OOBEndpoint    string        `json:"oob_endpoint,omitempty"`
	SeclistsDir    string        `json:"seclists_dir,omitempty"`
	OutputDir      string        `json:"output_dir,omitempty"`
}

// DefaultScannerConfig returns a scanner config with sensible defaults.
func DefaultScannerConfig() ScannerConfig {
	seclists := os.Getenv("ARES_SECLISTS_DIR")
	if seclists == "" {
		seclists = "/usr/share/seclists/"
	}
	return ScannerConfig{
		Timeout:        30 * time.Minute,
		MaxParallelism: 3,
		RateLimit:      2.0,
		SeclistsDir:    seclists,
		OutputDir:      "./evidence",
	}
}

// ScanProfile defines a named scan profile with specific tool categories and phases.
type ScanProfile struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	Phases       []ScanPhase `json:"phases"`
	ToolCategories []string  `json:"tool_categories"`
	MaxIterations int        `json:"max_iterations"`
}

// Predefined scan profiles
var (
	ProfileQuick = ScanProfile{
		Name:         "quick",
		Description:  "Quick reconnaissance and common vulnerability scan",
		Phases:       []ScanPhase{PhaseRecon, PhaseVulnScan},
		ToolCategories: []string{"recon", "vuln"},
		MaxIterations: 30,
	}
	ProfileFull = ScanProfile{
		Name:         "full",
		Description:  "Full penetration test covering all phases",
		Phases:       []ScanPhase{PhaseRecon, PhaseDiscovery, PhaseVulnScan, PhaseExploit, PhaseVerification, PhaseReporting},
		ToolCategories: []string{"recon", "discovery", "vuln", "exploit"},
		MaxIterations: 200,
	}
	ProfileStealth = ScanProfile{
		Name:         "stealth",
		Description:  "Low-and-slow scan with minimal detection footprint",
		Phases:       []ScanPhase{PhaseRecon, PhaseDiscovery},
		ToolCategories: []string{"recon", "discovery"},
		MaxIterations: 60,
	}
	ProfileWebApp = ScanProfile{
		Name:         "webapp",
		Description:  "Web application-focused scan (SQLi, XSS, SSRF, etc.)",
		Phases:       []ScanPhase{PhaseRecon, PhaseVulnScan, PhaseExploit},
		ToolCategories: []string{"recon", "vuln", "exploit"},
		MaxIterations: 100,
	}
	ProfileAD = ScanProfile{
		Name:         "active_directory",
		Description:  "Active Directory security assessment",
		Phases:       []ScanPhase{PhaseRecon, PhaseDiscovery, PhaseExploit},
		ToolCategories: []string{"recon", "discovery", "exploit"},
		MaxIterations: 150,
	}
)

// ScanFinding represents a single finding discovered during a scan.
type ScanFinding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    Severity  `json:"severity"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence,omitempty"`
	Phase       ScanPhase `json:"phase"`
	Tool        string    `json:"tool"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScanResult holds the complete result of a scan execution.
type ScanResult struct {
	Target     string        `json:"target"`
	Profile    string        `json:"profile"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Findings   []ScanFinding `json:"findings"`
	PhaseCount int           `json:"phase_count"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
}

// ScanProgressCallback is called periodically during scan execution with
// the current phase, progress (0.0–1.0), and any new findings.
type ScanProgressCallback func(phase ScanPhase, progress float64, findings []ScanFinding)

// Engine is the core scanner engine that executes scans based on profiles.
type Engine struct {
	mu           sync.RWMutex
	config       ScannerConfig
	activeScan   *activeScan
}

type activeScan struct {
	target    string
	profile   ScanProfile
	startTime time.Time
	phase     ScanPhase
	findings  []ScanFinding
	cancel    chan struct{}
}

// NewEngine creates a new scanner engine with the given configuration.
func NewEngine(cfg ScannerConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

// NewDefaultEngine creates a scanner engine with default configuration.
func NewDefaultEngine() *Engine {
	return NewEngine(DefaultScannerConfig())
}

// Config returns a copy of the current scanner configuration.
func (e *Engine) Config() ScannerConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// SetConfig updates the scanner configuration.
func (e *Engine) SetConfig(cfg ScannerConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
}

// Profiles returns the list of available scan profiles.
func (e *Engine) Profiles() []ScanProfile {
	return []ScanProfile{
		ProfileQuick,
		ProfileFull,
		ProfileStealth,
		ProfileWebApp,
		ProfileAD,
	}
}

// ProfileByName returns the scan profile with the given name, or nil if not found.
func (e *Engine) ProfileByName(name string) *ScanProfile {
	profiles := e.Profiles()
	for _, p := range profiles {
		if strings.EqualFold(p.Name, name) {
			return &p
		}
	}
	return nil
}

// Start begins a scan on the given target using the specified profile.
// Returns an error if a scan is already in progress or the profile is invalid.
func (e *Engine) Start(target string, profile ScanProfile) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeScan != nil {
		return fmt.Errorf("scan already in progress for target %s", e.activeScan.target)
	}

	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if len(profile.Phases) == 0 {
		return fmt.Errorf("profile %q has no phases", profile.Name)
	}

	e.activeScan = &activeScan{
		target:    target,
		profile:   profile,
		startTime: time.Now(),
		phase:     profile.Phases[0],
		findings:  make([]ScanFinding, 0),
		cancel:    make(chan struct{}),
	}

	logger.Info("Scan started",
		logger.Fields{
			"component": "Scanner",
			"target":    target,
			"profile":   profile.Name,
			"phases":    len(profile.Phases),
		})

	return nil
}

// Stop cancels an in-progress scan.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeScan == nil {
		return fmt.Errorf("no active scan to stop")
	}

	close(e.activeScan.cancel)
	e.activeScan = nil
	logger.Info("Scan stopped", logger.Fields{"component": "Scanner"})
	return nil
}

// IsActive returns whether a scan is currently running.
func (e *Engine) IsActive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeScan != nil
}

// Status returns the current scan status, or nil if no scan is running.
func (e *Engine) Status() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.activeScan == nil {
		return map[string]interface{}{
			"active": false,
		}
	}

	return map[string]interface{}{
		"active":          true,
		"target":          e.activeScan.target,
		"profile":         e.activeScan.profile.Name,
		"phase":           string(e.activeScan.phase),
		"elapsed":         time.Since(e.activeScan.startTime).String(),
		"findings_count":  len(e.activeScan.findings),
		"total_phases":    len(e.activeScan.profile.Phases),
	}
}


