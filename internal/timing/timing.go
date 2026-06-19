package timing

import (
	"fmt"
	"sync"
	"time"
)

type TimingProfile struct {
	mu             sync.Mutex
	startTime      time.Time
	monotonicStart int64
	samples        []time.Duration
	maxSkew        time.Duration
}

func NewTimingProfile() *TimingProfile {
	now := time.Now()
	return &TimingProfile{
		startTime:      now,
		monotonicStart: now.UnixNano(),
		samples:        make([]time.Duration, 0, 10),
		maxSkew:        100 * time.Millisecond,
	}
}

func (tp *TimingProfile) Elapsed() time.Duration {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tp.startTime)

	tp.samples = append(tp.samples, elapsed)
	if len(tp.samples) > 10 {
		tp.samples = tp.samples[1:]
	}

	return elapsed
}

func (tp *TimingProfile) ElapsedMonotonic() time.Duration {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	now := time.Now()
	return time.Duration(now.UnixNano() - tp.monotonicStart)
}

func (tp *TimingProfile) Reset() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	now := time.Now()
	tp.startTime = now
	tp.monotonicStart = now.UnixNano()
	tp.samples = tp.samples[:0]
}

func (tp *TimingProfile) DetectClockSkew() (bool, time.Duration, string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if len(tp.samples) < 2 {
		return false, 0, "insufficient samples"
	}

	wallElapsed := time.Since(tp.startTime)
	monoElapsed := time.Duration(time.Now().UnixNano() - tp.monotonicStart)

	skew := wallElapsed - monoElapsed
	if skew < 0 {
		skew = -skew
	}

	if skew > tp.maxSkew {
		return true, skew, fmt.Sprintf("clock skew detected: wall=%v monotonic=%v skew=%v",
			wallElapsed, monoElapsed, skew)
	}

	return false, skew, "clock within acceptable range"
}

func (tp *TimingProfile) SetMaxSkew(d time.Duration) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.maxSkew = d
}

func (tp *TimingProfile) AverageElapsed() time.Duration {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if len(tp.samples) == 0 {
		return 0
	}

	var total time.Duration
	for _, s := range tp.samples {
		total += s
	}
	return total / time.Duration(len(tp.samples))
}

func (tp *TimingProfile) SampleCount() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return len(tp.samples)
}
