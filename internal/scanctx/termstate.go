package scanctx

import (
	"sync"
	"time"
)

type TermEntry struct {
	Seq       int
	Command   string
	Output    string
	Timestamp time.Time
	Duration  time.Duration
}

type TermState struct {
	mu      sync.RWMutex
	history []TermEntry
	cmdSeq  int
	prevCmd string
}

func NewTermState() *TermState {
	return &TermState{}
}

func (ts *TermState) Record(cmd, output string, duration time.Duration) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.cmdSeq++
	ts.history = append(ts.history, TermEntry{
		Seq:       ts.cmdSeq,
		Command:   cmd,
		Output:    output,
		Timestamp: time.Now(),
		Duration:  duration,
	})
	ts.prevCmd = cmd
}

func (ts *TermState) RepeatCount(cmd string) int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	count := 0
	for _, e := range ts.history {
		if e.Command == cmd {
			count++
		}
	}
	return count
}

func (ts *TermState) IsRepeat(cmd string, threshold int) bool {
	return ts.RepeatCount(cmd) >= threshold
}

func (ts *TermState) History() []TermEntry {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	result := make([]TermEntry, len(ts.history))
	copy(result, ts.history)
	return result
}
