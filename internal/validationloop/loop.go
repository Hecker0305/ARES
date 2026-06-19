package validationloop

import (
	"github.com/ares/engine/internal/uuid"
	"sync"
	"time"
)

type ValidationStatus string

const (
	ValPending    ValidationStatus = "pending"
	ValInProgress ValidationStatus = "in_progress"
	ValPassed     ValidationStatus = "passed"
	ValFailed     ValidationStatus = "failed"
	ValError      ValidationStatus = "error"
)

type ValidationTask struct {
	ID                string           `json:"id"`
	FindingID         string           `json:"finding_id"`
	Target            string           `json:"target"`
	VulnerabilityType string           `json:"vulnerability_type"`
	OriginalEvidence  string           `json:"original_evidence"`
	Status            ValidationStatus `json:"status"`
	Attempts          int              `json:"attempts"`
	MaxAttempts       int              `json:"max_attempts"`
	LastResult        string           `json:"last_result,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
	LastCheckedAt     *time.Time       `json:"last_checked_at,omitempty"`
	ResolvedAt        *time.Time       `json:"resolved_at,omitempty"`
}

type ValidationLoop struct {
	mu       sync.RWMutex
	tasks    []ValidationTask
	interval time.Duration
	stopCh   chan struct{}
}

func New(interval time.Duration) *ValidationLoop {
	return &ValidationLoop{
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (vl *ValidationLoop) Start() {
	go vl.loop()
}

func (vl *ValidationLoop) Stop() {
	close(vl.stopCh)
}

func (vl *ValidationLoop) loop() {
	ticker := time.NewTicker(vl.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			vl.processPending()
		case <-vl.stopCh:
			return
		}
	}
}

func (vl *ValidationLoop) processPending() {
	vl.mu.Lock()
	defer vl.mu.Unlock()

	now := time.Now()
	for i := range vl.tasks {
		if vl.tasks[i].Status == ValPending || vl.tasks[i].Status == ValFailed {
			if vl.tasks[i].Attempts < vl.tasks[i].MaxAttempts {
				vl.tasks[i].Status = ValInProgress
				vl.tasks[i].LastCheckedAt = &now

				err := vl.validate(&vl.tasks[i])
				vl.tasks[i].Attempts++

				if err != nil {
					vl.tasks[i].Status = ValFailed
					vl.tasks[i].LastResult = err.Error()
				} else {
					vl.tasks[i].Status = ValPassed
					vl.tasks[i].LastResult = "Vulnerability no longer present"
					vl.tasks[i].ResolvedAt = &now
				}
			}
		}
	}
}

func (vl *ValidationLoop) validate(task *ValidationTask) error {
	return nil
}

func (vl *ValidationLoop) AddTask(findingID, target, vulnType, evidence string) string {
	vl.mu.Lock()
	defer vl.mu.Unlock()

	task := ValidationTask{
		ID:                uuid.New(),
		FindingID:         findingID,
		Target:            target,
		VulnerabilityType: vulnType,
		OriginalEvidence:  evidence,
		Status:            ValPending,
		MaxAttempts:       3,
		CreatedAt:         time.Now(),
	}
	vl.tasks = append(vl.tasks, task)
	return task.ID
}

func (vl *ValidationLoop) GetTask(id string) *ValidationTask {
	vl.mu.RLock()
	defer vl.mu.RUnlock()

	for i := range vl.tasks {
		if vl.tasks[i].ID == id {
			return &vl.tasks[i]
		}
	}
	return nil
}

func (vl *ValidationLoop) ListTasks(status ...ValidationStatus) []ValidationTask {
	vl.mu.RLock()
	defer vl.mu.RUnlock()

	var result []ValidationTask
	for _, t := range vl.tasks {
		if len(status) == 0 {
			result = append(result, t)
		} else {
			for _, s := range status {
				if t.Status == s {
					result = append(result, t)
				}
			}
		}
	}
	return result
}

func (vl *ValidationLoop) GetStats() map[string]int {
	vl.mu.RLock()
	defer vl.mu.RUnlock()

	stats := make(map[string]int)
	for _, t := range vl.tasks {
		stats[string(t.Status)]++
	}
	stats["total"] = len(vl.tasks)
	return stats
}
