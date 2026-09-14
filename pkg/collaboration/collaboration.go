package collaboration

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type AssignmentStatus string

const (
	StatusAssigned      AssignmentStatus = "assigned"
	StatusInProgress   AssignmentStatus = "in_progress"
	StatusResolved     AssignmentStatus = "resolved"
	StatusAccepted     AssignmentStatus = "accepted"
	StatusRiskAccepted AssignmentStatus = "risk_accepted"
)

type AuditAction string

const (
	ActionAssigned       AuditAction = "assigned"
	ActionUnassigned     AuditAction = "unassigned"
	ActionCommented      AuditAction = "commented"
	ActionStatusChanged  AuditAction = "status_changed"
	ActionSeverityChanged AuditAction = "severity_changed"
	ActionAssignedTo     AuditAction = "assigned_to"
)

type VulnerabilityAssignment struct {
	ID            string
	VulnerabilityID string
	AssigneeID    string
	AssigneeName  string
	AssigneeEmail string
	AssignedBy    string
	AssignedAt    time.Time
	Status        AssignmentStatus
	Notes         string
	Resolution    string
	ResolvedAt    *time.Time
}

type Comment struct {
	ID              string
	VulnerabilityID string
	AuthorID        string
	AuthorName      string
	Content         string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ParentID        string
}

type AuditLogEntry struct {
	ID              string
	Action          AuditAction
	PerformedBy     string
	VulnerabilityID string
	OldValue        string
	NewValue        string
	Timestamp       time.Time
}

type TeamMember struct {
	ID        string
	Name      string
	Email     string
	Role      string
	AvatarURL string
	CreatedAt time.Time
}

type CollaborationManager struct {
	mu          sync.RWMutex
	assignments map[string][]*VulnerabilityAssignment
	comments    map[string][]*Comment
	auditLog    map[string][]*AuditLogEntry
	members     map[string]*TeamMember
}

func NewCollaborationManager() *CollaborationManager {
	return &CollaborationManager{
		assignments: make(map[string][]*VulnerabilityAssignment),
		comments:    make(map[string][]*Comment),
		auditLog:    make(map[string][]*AuditLogEntry),
		members:     make(map[string]*TeamMember),
	}
}

func (cm *CollaborationManager) AssignVulnerability(vulnID, assigneeID, assigneeName, assigneeEmail, assignedBy string) (*VulnerabilityAssignment, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	assignment := &VulnerabilityAssignment{
		ID:              uuid.New().String(),
		VulnerabilityID: vulnID,
		AssigneeID:      assigneeID,
		AssigneeName:    assigneeName,
		AssigneeEmail:   assigneeEmail,
		AssignedBy:      assignedBy,
		AssignedAt:      time.Now().UTC(),
		Status:          StatusAssigned,
	}

	cm.assignments[vulnID] = append(cm.assignments[vulnID], assignment)

	cm.auditLog[vulnID] = append(cm.auditLog[vulnID], &AuditLogEntry{
		ID:              uuid.New().String(),
		Action:          ActionAssigned,
		PerformedBy:     assignedBy,
		VulnerabilityID: vulnID,
		OldValue:        "",
		NewValue:        assigneeID,
		Timestamp:       time.Now().UTC(),
	})

	return assignment, nil
}

func (cm *CollaborationManager) UnassignVulnerability(vulnID, assigneeID, unassignedBy string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	assignments, ok := cm.assignments[vulnID]
	if !ok {
		return fmt.Errorf("no assignments found for vulnerability %s", vulnID)
	}

	found := false
	for i, a := range assignments {
		if a.AssigneeID == assigneeID && a.Status != StatusResolved {
			cm.assignments[vulnID] = append(assignments[:i], assignments[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("assignee %s not found or already resolved for vulnerability %s", assigneeID, vulnID)
	}

	cm.auditLog[vulnID] = append(cm.auditLog[vulnID], &AuditLogEntry{
		ID:              uuid.New().String(),
		Action:          ActionUnassigned,
		PerformedBy:     unassignedBy,
		VulnerabilityID: vulnID,
		OldValue:        assigneeID,
		NewValue:        "",
		Timestamp:       time.Now().UTC(),
	})

	return nil
}

func (cm *CollaborationManager) UpdateAssignmentStatus(vulnID, assigneeID string, status AssignmentStatus, updatedBy string) (*VulnerabilityAssignment, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	assignments, ok := cm.assignments[vulnID]
	if !ok {
		return nil, fmt.Errorf("no assignments found for vulnerability %s", vulnID)
	}

	for _, a := range assignments {
		if a.AssigneeID == assigneeID {
			oldStatus := string(a.Status)
			a.Status = status
			if status == StatusResolved || status == StatusAccepted || status == StatusRiskAccepted {
				now := time.Now().UTC()
				a.ResolvedAt = &now
			}

			cm.auditLog[vulnID] = append(cm.auditLog[vulnID], &AuditLogEntry{
				ID:              uuid.New().String(),
				Action:          ActionStatusChanged,
				PerformedBy:     updatedBy,
				VulnerabilityID: vulnID,
				OldValue:        oldStatus,
				NewValue:        string(status),
				Timestamp:       time.Now().UTC(),
			})

			return a, nil
		}
	}

	return nil, fmt.Errorf("assignee %s not found for vulnerability %s", assigneeID, vulnID)
}

func (cm *CollaborationManager) GetAssignments(vulnID string) []*VulnerabilityAssignment {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.assignments[vulnID]
}

func (cm *CollaborationManager) AddComment(vulnID, authorID, authorName, content, parentID string) (*Comment, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now().UTC()
	comment := &Comment{
		ID:              uuid.New().String(),
		VulnerabilityID: vulnID,
		AuthorID:        authorID,
		AuthorName:      authorName,
		Content:         content,
		CreatedAt:       now,
		UpdatedAt:       now,
		ParentID:        parentID,
	}

	cm.comments[vulnID] = append(cm.comments[vulnID], comment)

	cm.auditLog[vulnID] = append(cm.auditLog[vulnID], &AuditLogEntry{
		ID:              uuid.New().String(),
		Action:          ActionCommented,
		PerformedBy:     authorID,
		VulnerabilityID: vulnID,
		OldValue:        "",
		NewValue:        content,
		Timestamp:       now,
	})

	return comment, nil
}

func (cm *CollaborationManager) GetComments(vulnID string) []*Comment {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.comments[vulnID]
}

func (cm *CollaborationManager) GetAuditLog(vulnID string) []*AuditLogEntry {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.auditLog[vulnID]
}

func (cm *CollaborationManager) AddTeamMember(name, email, role, avatarURL string) *TeamMember {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	member := &TeamMember{
		ID:        uuid.New().String(),
		Name:      name,
		Email:     email,
		Role:      role,
		AvatarURL: avatarURL,
		CreatedAt: time.Now().UTC(),
	}

	cm.members[member.ID] = member
	return member
}

func (cm *CollaborationManager) RemoveTeamMember(id string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.members[id]; !ok {
		return fmt.Errorf("team member %s not found", id)
	}

	delete(cm.members, id)
	return nil
}

func (cm *CollaborationManager) ListTeamMembers() []*TeamMember {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	members := make([]*TeamMember, 0, len(cm.members))
	for _, m := range cm.members {
		members = append(members, m)
	}
	return members
}