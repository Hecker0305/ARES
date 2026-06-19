package collaboration

import (
	"github.com/ares/engine/internal/uuid"
	"sync"
	"time"
)

type Comment struct {
	ID         string    `json:"id"`
	TargetID   string    `json:"target_id"`
	TargetType string    `json:"target_type"`
	Author     string    `json:"author"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Assignment struct {
	ID          string     `json:"id"`
	TargetID    string     `json:"target_id"`
	TargetType  string     `json:"target_type"`
	Assignee    string     `json:"assignee"`
	AssignedBy  string     `json:"assigned_by"`
	Status      string     `json:"status"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type EvidenceReview struct {
	ID         string     `json:"id"`
	FindingID  string     `json:"finding_id"`
	Reviewer   string     `json:"reviewer"`
	Status     string     `json:"status"`
	Notes      string     `json:"notes,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
}

type TeamWorkflow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Assignee string `json:"assignee"`
}

type CollaborationEngine struct {
	mu          sync.RWMutex
	comments    []Comment
	assignments []Assignment
	reviews     []EvidenceReview
}

func New() *CollaborationEngine {
	return &CollaborationEngine{}
}

func (ce *CollaborationEngine) AddComment(targetID, targetType, author, content string) string {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	comment := Comment{
		ID:         uuid.New(),
		TargetID:   targetID,
		TargetType: targetType,
		Author:     author,
		Content:    content,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	ce.comments = append(ce.comments, comment)
	return comment.ID
}

func (ce *CollaborationEngine) GetComments(targetID string) []Comment {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var result []Comment
	for _, c := range ce.comments {
		if c.TargetID == targetID {
			result = append(result, c)
		}
	}
	return result
}

func (ce *CollaborationEngine) Assign(targetID, targetType, assignee, assignedBy string) string {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	assignment := Assignment{
		ID:         uuid.New(),
		TargetID:   targetID,
		TargetType: targetType,
		Assignee:   assignee,
		AssignedBy: assignedBy,
		Status:     "open",
		CreatedAt:  time.Now(),
	}
	ce.assignments = append(ce.assignments, assignment)
	return assignment.ID
}

func (ce *CollaborationEngine) CompleteAssignment(id string) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	for i := range ce.assignments {
		if ce.assignments[i].ID == id {
			now := time.Now()
			ce.assignments[i].Status = "completed"
			ce.assignments[i].CompletedAt = &now
			return true
		}
	}
	return false
}

func (ce *CollaborationEngine) GetAssignments(assignee string) []Assignment {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var result []Assignment
	for _, a := range ce.assignments {
		if assignee == "" || a.Assignee == assignee {
			result = append(result, a)
		}
	}
	return result
}

func (ce *CollaborationEngine) CreateReview(findingID, reviewer string) string {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	review := EvidenceReview{
		ID:        uuid.New(),
		FindingID: findingID,
		Reviewer:  reviewer,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	ce.reviews = append(ce.reviews, review)
	return review.ID
}

func (ce *CollaborationEngine) ApproveReview(id, notes string) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	for i := range ce.reviews {
		if ce.reviews[i].ID == id {
			now := time.Now()
			ce.reviews[i].Status = "approved"
			ce.reviews[i].Notes = notes
			ce.reviews[i].ReviewedAt = &now
			return true
		}
	}
	return false
}

func (ce *CollaborationEngine) RejectReview(id, notes string) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	for i := range ce.reviews {
		if ce.reviews[i].ID == id {
			now := time.Now()
			ce.reviews[i].Status = "rejected"
			ce.reviews[i].Notes = notes
			ce.reviews[i].ReviewedAt = &now
			return true
		}
	}
	return false
}

func (ce *CollaborationEngine) GetReviews(status string) []EvidenceReview {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var result []EvidenceReview
	for _, r := range ce.reviews {
		if status == "" || r.Status == status {
			result = append(result, r)
		}
	}
	return result
}
