package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/worker"
)

type AutonomousExecutor struct {
	mu          sync.RWMutex
	coordinator *worker.Coordinator
	scanCfg     AutonomousConfig
	active      bool
	cancel      context.CancelFunc
}

type AutonomousConfig struct {
	MaxTargets   int           `json:"max_targets"`
	ScanInterval time.Duration `json:"scan_interval"`
	StopOnFirst  bool          `json:"stop_on_first"`
}

func (a *AutonomousExecutor) Start(ctx context.Context, targets []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active {
		return
	}
	if len(targets) == 0 {
		return
	}
	if len(targets) > a.scanCfg.MaxTargets {
		targets = targets[:a.scanCfg.MaxTargets]
	}
	ctx, a.cancel = context.WithCancel(ctx)
	a.active = true
	go a.run(ctx, targets)
}

func (a *AutonomousExecutor) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
	a.active = false
}

func (a *AutonomousExecutor) IsActive() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.active
}

func (a *AutonomousExecutor) Config() AutonomousConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.scanCfg
}

func (a *AutonomousExecutor) SetConfig(cfg AutonomousConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scanCfg = cfg
}

func (a *AutonomousExecutor) run(ctx context.Context, targets []string) {
	defer func() {
		a.mu.Lock()
		a.active = false
		a.mu.Unlock()
	}()

	for i, tgt := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		logger.Info("[Autonomous] Starting scan", logger.Fields{"target": tgt, "index": i, "total": len(targets)})
		if err := a.coordinator.Run(tgt); err != nil {
			logger.Error("[Autonomous] Scan failed", logger.Fields{"target": tgt, "error": err})
			if a.scanCfg.StopOnFirst {
				return
			}
			continue
		}

		if i < len(targets)-1 {
			timer := time.NewTimer(a.scanCfg.ScanInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

type AutonomousHandler struct {
	executor *AutonomousExecutor
}

func (h *AutonomousHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.startAutonomous(w, r)
	case http.MethodGet:
		h.getAutonomousStatus(w, r)
	case http.MethodDelete:
		h.stopAutonomous(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *AutonomousHandler) startAutonomous(w http.ResponseWriter, r *http.Request) {
	if h.executor.IsActive() {
		http.Error(w, "autonomous scan already running", http.StatusConflict)
		return
	}
	var req struct {
		Targets []string          `json:"targets"`
		Config  *AutonomousConfig `json:"config,omitempty"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Targets) == 0 {
		http.Error(w, "no targets provided", http.StatusBadRequest)
		return
	}
	if req.Config != nil {
		h.executor.SetConfig(*req.Config)
	}
	go h.executor.Start(r.Context(), req.Targets)
	writeJSON(w, map[string]string{"status": "started", "targets": fmt.Sprintf("%d", len(req.Targets))})
}

func (h *AutonomousHandler) getAutonomousStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"active": h.executor.IsActive(),
		"config": h.executor.Config(),
	})
}

func (h *AutonomousHandler) stopAutonomous(w http.ResponseWriter, r *http.Request) {
	h.executor.Stop()
	writeJSON(w, map[string]string{"status": "stopped"})
}
