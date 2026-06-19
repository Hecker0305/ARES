package persistence

import (
	"time"

	"github.com/ares/engine/internal/agent"
)

type Checkpoint struct {
	ID        string          `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Phase     string          `json:"phase"`
	Iteration int             `json:"iteration"`
	Targets   []string        `json:"targets"`
	Findings  []agent.Finding `json:"findings"`
}

type DiskStore struct{}

func NewDiskStore(dir string, maxCheckpoints int) *DiskStore {
	return &DiskStore{}
}

func (ds *DiskStore) Save(cp Checkpoint) error {
	return nil
}
