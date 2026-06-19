package engineerrors

import (
	"fmt"
	"sync"
	"time"
)

type Governor struct {
	mu          sync.Mutex
	maxPackets  int
	maxBytes    int64
	maxDuration time.Duration
	usedPackets int
	usedBytes   int64
	start       time.Time
}

var (
	defaultGovernor = &Governor{
		maxPackets:  10000,
		maxBytes:    500 * 1024 * 1024,
		maxDuration: 5 * time.Minute,
	}
	simulationGovernor = &Governor{
		maxPackets:  50000,
		maxBytes:    2 * 1024 * 1024 * 1024,
		maxDuration: 30 * time.Minute,
	}
)

func GetDefaultGovernor() *Governor {
	return defaultGovernor
}

func GetSimulationGovernor() *Governor {
	return simulationGovernor
}

func (g *Governor) Configure(maxPackets int, maxBytes int64, maxDuration time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if maxPackets > 0 {
		g.maxPackets = maxPackets
	}
	if maxBytes > 0 {
		g.maxBytes = maxBytes
	}
	if maxDuration > 0 {
		g.maxDuration = maxDuration
	}
}

func (g *Governor) Check(packets int, bytes int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.start.IsZero() {
		g.start = time.Now()
		g.usedPackets = 0
		g.usedBytes = 0
	}

	if g.maxDuration > 0 && time.Since(g.start) > g.maxDuration {
		g.start = time.Now()
		g.usedPackets = 0
		g.usedBytes = 0
	}

	newPackets := g.usedPackets + packets
	newBytes := g.usedBytes + bytes

	if newPackets > g.maxPackets {
		return ResourceExceeded("packets", g.maxPackets)
	}
	if newBytes > g.maxBytes {
		return ResourceExceeded("bytes", int(g.maxBytes))
	}

	g.usedPackets = newPackets
	g.usedBytes = newBytes
	return nil
}

func (g *Governor) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.usedPackets = 0
	g.usedBytes = 0
	g.start = time.Now()
}

func (g *Governor) Usage() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return fmt.Sprintf("%d packets / %s bytes in %s",
		g.usedPackets, formatBytes(g.usedBytes), time.Since(g.start).Round(time.Second))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
