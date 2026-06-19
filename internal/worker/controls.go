package worker

import (
	"sync"

	"github.com/ares/engine/internal/agent"
)

type ScanControls struct {
	mu     sync.RWMutex
	agents map[string]*agent.Agent
}

func (sc *ScanControls) Register(scanID string, a *agent.Agent) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.agents[scanID] = a
}

func (sc *ScanControls) Unregister(scanID string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	delete(sc.agents, scanID)
}

func (sc *ScanControls) PauseScan(scanID string) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if a, ok := sc.agents[scanID]; ok {
		a.Pause()
	}
}

func (sc *ScanControls) ResumeScan(scanID string) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if a, ok := sc.agents[scanID]; ok {
		a.Resume()
	}
}
