package engine

import (
	"time"

	"github.com/ares/engine/internal/scanctx"
)

type Phase = scanctx.Phase

const (
	PhaseRecon       Phase = scanctx.PhaseRecon
	PhaseDiscovery   Phase = scanctx.PhaseDiscovery
	PhaseVulnScan    Phase = scanctx.PhaseVulnScan
	PhaseExploit     Phase = scanctx.PhaseExploit
	PhasePostExploit Phase = scanctx.PhasePostExploit
	PhaseReport      Phase = scanctx.PhaseReport
)

type ScanConfig struct {
	MaxIterations  int
	StuckThreshold int
	TargetReinject int
	ConfidenceGate float64
	MaxWorkers     int
}

type Engine struct {
	config  ScanConfig
	phase   Phase
	started time.Time
}

func NewEngine(cfg ScanConfig) *Engine {
	return &Engine{
		config:  cfg,
		phase:   PhaseRecon,
		started: time.Now(),
	}
}

func (e *Engine) Phase() Phase {
	return e.phase
}

func (e *Engine) SetPhase(p Phase) {
	e.phase = p
}

func (e *Engine) Config() ScanConfig {
	return e.config
}

func (e *Engine) Uptime() time.Duration {
	return time.Since(e.started)
}
