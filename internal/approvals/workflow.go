package approvals

import (
	"github.com/ares/engine/internal/uuid"
	"fmt"
	"sync"
	"time"
)

type ApprovalType string

const (
	ApprovalExploit     ApprovalType = "exploit"
	ApprovalRemediation ApprovalType = "remediation"
	ApprovalIntegration ApprovalType = "integration"
)

type ApprovalStatus string

const (
	StatusPending  ApprovalStatus = "pending"
	StatusApproved ApprovalStatus = "approved"
	StatusDenied   ApprovalStatus = "denied"
	StatusExpired  ApprovalStatus = "expired"
)

type ApprovalRequest struct {
	ID         string            `json:"id"`
	Type       ApprovalType      `json:"type"`
	Status     ApprovalStatus    `json:"status"`
	Requester  string            `json:"requester"`
	Target     string            `json:"target"`
	Reason     string            `json:"reason"`
	Details    map[string]string `json:"details,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	ApprovedBy string            `json:"approved_by,omitempty"`
	ApprovedAt *time.Time        `json:"approved_at,omitempty"`
	DeniedBy   string            `json:"denied_by,omitempty"`
	DeniedAt   *time.Time        `json:"denied_at,omitempty"`
	DenyReason string            `json:"deny_reason,omitempty"`
}

type WorkflowEngine struct {
	mu              sync.RWMutex
	requests        []ApprovalRequest
	requireApproval map[ApprovalType]bool
	stopCh          chan struct{}
}

func New() *WorkflowEngine {
	w := &WorkflowEngine{
		requireApproval: map[ApprovalType]bool{
			ApprovalExploit:     true,
			ApprovalRemediation: true,
			ApprovalIntegration: true,
		},
		stopCh: make(chan struct{}),
	}
	go w.expiryLoop()
	return w
}

func (w *WorkflowEngine) Stop() {
	close(w.stopCh)
}

func (w *WorkflowEngine) expiryLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			now := time.Now()
			for i := range w.requests {
				if w.requests[i].Status == StatusPending && now.After(w.requests[i].ExpiresAt) {
					w.requests[i].Status = StatusExpired
				}
			}
			w.mu.Unlock()
		case <-w.stopCh:
			return
		}
	}
}

func (w *WorkflowEngine) RequiresApproval(t ApprovalType) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.requireApproval[t]
}

func (w *WorkflowEngine) SetRequiresApproval(t ApprovalType, required bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.requireApproval[t] = required
}

func (w *WorkflowEngine) CreateRequest(req ApprovalRequest) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if req.ID == "" {
		req.ID = uuid.New()
	}
	req.Status = StatusPending
	req.CreatedAt = time.Now()
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().Add(24 * time.Hour)
	}

	w.requests = append(w.requests, req)
	return req.ID, nil
}

func (w *WorkflowEngine) Approve(id, approver string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for i := range w.requests {
		if w.requests[i].ID == id {
			if w.requests[i].Status != StatusPending {
				return fmt.Errorf("request %s is not pending (current: %s)", id, w.requests[i].Status)
			}
			now := time.Now()
			w.requests[i].Status = StatusApproved
			w.requests[i].ApprovedBy = approver
			w.requests[i].ApprovedAt = &now
			return nil
		}
	}
	return fmt.Errorf("approval request %s not found", id)
}

func (w *WorkflowEngine) Deny(id, denier, reason string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for i := range w.requests {
		if w.requests[i].ID == id {
			if w.requests[i].Status != StatusPending {
				return fmt.Errorf("request %s is not pending (current: %s)", id, w.requests[i].Status)
			}
			now := time.Now()
			w.requests[i].Status = StatusDenied
			w.requests[i].DeniedBy = denier
			w.requests[i].DeniedAt = &now
			w.requests[i].DenyReason = reason
			return nil
		}
	}
	return fmt.Errorf("approval request %s not found", id)
}

func (w *WorkflowEngine) GetRequest(id string) *ApprovalRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for i := range w.requests {
		if w.requests[i].ID == id {
			req := w.requests[i]
			return &req
		}
	}
	return nil
}

func (w *WorkflowEngine) ListRequests(status ...ApprovalStatus) []ApprovalRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var result []ApprovalRequest
	for _, req := range w.requests {
		if len(status) == 0 {
			result = append(result, req)
		} else {
			for _, s := range status {
				if req.Status == s {
					result = append(result, req)
				}
			}
		}
	}
	return result
}

func (w *WorkflowEngine) ListRequestsByType(t ApprovalType, status ...ApprovalStatus) []ApprovalRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var result []ApprovalRequest
	for _, req := range w.requests {
		if req.Type != t {
			continue
		}
		if len(status) == 0 {
			result = append(result, req)
		} else {
			for _, s := range status {
				if req.Status == s {
					result = append(result, req)
				}
			}
		}
	}
	return result
}
