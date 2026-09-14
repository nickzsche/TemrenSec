package collaboration

import (
	"testing"
)

func TestNewCollaborationManager(t *testing.T) {
	cm := NewCollaborationManager()
	if cm == nil {
		t.Error("NewCollaborationManager() should not return nil")
	}
	if len(cm.ListTeamMembers()) != 0 {
		t.Error("New manager should have no team members")
	}
}

func TestAssignVulnerability(t *testing.T) {
	cm := NewCollaborationManager()

	assignment, err := cm.AssignVulnerability("vuln-1", "user-1", "Alice", "alice@example.com", "admin")
	if err != nil {
		t.Fatalf("AssignVulnerability() error: %v", err)
	}

	if assignment.VulnerabilityID != "vuln-1" {
		t.Errorf("VulnerabilityID = %q, want %q", assignment.VulnerabilityID, "vuln-1")
	}
	if assignment.AssigneeID != "user-1" {
		t.Errorf("AssigneeID = %q, want %q", assignment.AssigneeID, "user-1")
	}
	if assignment.AssigneeName != "Alice" {
		t.Errorf("AssigneeName = %q, want %q", assignment.AssigneeName, "Alice")
	}
	if assignment.AssigneeEmail != "alice@example.com" {
		t.Errorf("AssigneeEmail = %q, want %q", assignment.AssigneeEmail, "alice@example.com")
	}
	if assignment.AssignedBy != "admin" {
		t.Errorf("AssignedBy = %q, want %q", assignment.AssignedBy, "admin")
	}
	if assignment.Status != StatusAssigned {
		t.Errorf("Status = %q, want %q", assignment.Status, StatusAssigned)
	}
	if assignment.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestGetAssignments(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AssignVulnerability("vuln-1", "user-1", "Alice", "alice@example.com", "admin")
	cm.AssignVulnerability("vuln-1", "user-2", "Bob", "bob@example.com", "admin")

	assignments := cm.GetAssignments("vuln-1")
	if len(assignments) != 2 {
		t.Errorf("GetAssignments() returned %d assignments, want 2", len(assignments))
	}

	empty := cm.GetAssignments("vuln-999")
	if len(empty) != 0 {
		t.Errorf("GetAssignments() for nonexistent vuln returned %d, want 0", len(empty))
	}
}

func TestUnassignVulnerability(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AssignVulnerability("vuln-1", "user-1", "Alice", "alice@example.com", "admin")
	err := cm.UnassignVulnerability("vuln-1", "user-1", "admin")
	if err != nil {
		t.Fatalf("UnassignVulnerability() error: %v", err)
	}

	assignments := cm.GetAssignments("vuln-1")
	if len(assignments) != 0 {
		t.Errorf("After unassign, got %d assignments, want 0", len(assignments))
	}

	err = cm.UnassignVulnerability("vuln-999", "user-1", "admin")
	if err == nil {
		t.Error("UnassignVulnerability() should return error for nonexistent assignment")
	}
}

func TestUpdateAssignmentStatus(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AssignVulnerability("vuln-1", "user-1", "Alice", "alice@example.com", "admin")
	updated, err := cm.UpdateAssignmentStatus("vuln-1", "user-1", StatusInProgress, "admin")
	if err != nil {
		t.Fatalf("UpdateAssignmentStatus() error: %v", err)
	}

	if updated.Status != StatusInProgress {
		t.Errorf("Status = %q, want %q", updated.Status, StatusInProgress)
	}

	_, err = cm.UpdateAssignmentStatus("vuln-999", "user-1", StatusResolved, "admin")
	if err == nil {
		t.Error("UpdateAssignmentStatus() should return error for nonexistent assignment")
	}
}

func TestAddComment(t *testing.T) {
	cm := NewCollaborationManager()

	comment, err := cm.AddComment("vuln-1", "user-1", "Alice", "This looks critical", "")
	if err != nil {
		t.Fatalf("AddComment() error: %v", err)
	}

	if comment.VulnerabilityID != "vuln-1" {
		t.Errorf("VulnerabilityID = %q, want %q", comment.VulnerabilityID, "vuln-1")
	}
	if comment.AuthorID != "user-1" {
		t.Errorf("AuthorID = %q, want %q", comment.AuthorID, "user-1")
	}
	if comment.Content != "This looks critical" {
		t.Errorf("Content = %q, want %q", comment.Content, "This looks critical")
	}

	reply, err := cm.AddComment("vuln-1", "user-2", "Bob", "Agreed", comment.ID)
	if err != nil {
		t.Fatalf("AddComment() reply error: %v", err)
	}
	if reply.ParentID != comment.ID {
		t.Errorf("Reply ParentID = %q, want %q", reply.ParentID, comment.ID)
	}
}

func TestGetComments(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AddComment("vuln-1", "user-1", "Alice", "Comment 1", "")
	cm.AddComment("vuln-1", "user-2", "Bob", "Comment 2", "")

	comments := cm.GetComments("vuln-1")
	if len(comments) != 2 {
		t.Errorf("GetComments() returned %d comments, want 2", len(comments))
	}

	empty := cm.GetComments("vuln-999")
	if len(empty) != 0 {
		t.Errorf("GetComments() for nonexistent vuln returned %d, want 0", len(empty))
	}
}

func TestGetAuditLog(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AssignVulnerability("vuln-1", "user-1", "Alice", "alice@example.com", "admin")

	auditLog := cm.GetAuditLog("vuln-1")
	if len(auditLog) == 0 {
		t.Error("AssignVulnerability should create audit log entry")
	}

	if auditLog[0].Action != ActionAssigned {
		t.Errorf("Audit action = %q, want %q", auditLog[0].Action, ActionAssigned)
	}
	if auditLog[0].VulnerabilityID != "vuln-1" {
		t.Errorf("Audit VulnerabilityID = %q, want %q", auditLog[0].VulnerabilityID, "vuln-1")
	}
}

func TestAddTeamMember(t *testing.T) {
	cm := NewCollaborationManager()

	member := cm.AddTeamMember("Alice", "alice@example.com", "admin", "https://example.com/avatar1.png")

	if member.Name != "Alice" {
		t.Errorf("Name = %q, want %q", member.Name, "Alice")
	}
	if member.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", member.Email, "alice@example.com")
	}
	if member.Role != "admin" {
		t.Errorf("Role = %q, want %q", member.Role, "admin")
	}
	if member.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestRemoveTeamMember(t *testing.T) {
	cm := NewCollaborationManager()

	member := cm.AddTeamMember("Alice", "alice@example.com", "admin", "")
	err := cm.RemoveTeamMember(member.ID)
	if err != nil {
		t.Fatalf("RemoveTeamMember() error: %v", err)
	}

	members := cm.ListTeamMembers()
	if len(members) != 0 {
		t.Errorf("After removal, ListTeamMembers() returned %d, want 0", len(members))
	}

	err = cm.RemoveTeamMember("nonexistent")
	if err == nil {
		t.Error("RemoveTeamMember() should return error for nonexistent ID")
	}
}

func TestListTeamMembers(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AddTeamMember("Alice", "alice@example.com", "admin", "")
	cm.AddTeamMember("Bob", "bob@example.com", "analyst", "")

	members := cm.ListTeamMembers()
	if len(members) != 2 {
		t.Errorf("ListTeamMembers() returned %d, want 2", len(members))
	}
}

func TestAuditLogOnUnassign(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AssignVulnerability("vuln-1", "user-1", "Alice", "alice@example.com", "admin")
	cm.UnassignVulnerability("vuln-1", "user-1", "admin")

	auditLog := cm.GetAuditLog("vuln-1")
	hasUnassign := false
	for _, entry := range auditLog {
		if entry.Action == ActionUnassigned {
			hasUnassign = true
		}
	}
	if !hasUnassign {
		t.Error("Expected ActionUnassigned in audit log after unassigning vulnerability")
	}
}

func TestAuditLogOnStatusChange(t *testing.T) {
	cm := NewCollaborationManager()

	cm.AssignVulnerability("vuln-1", "user-1", "Alice", "alice@example.com", "admin")
	cm.UpdateAssignmentStatus("vuln-1", "user-1", StatusResolved, "admin")

	auditLog := cm.GetAuditLog("vuln-1")
	hasStatusChange := false
	for _, entry := range auditLog {
		if entry.Action == ActionStatusChanged {
			hasStatusChange = true
		}
	}
	if !hasStatusChange {
		t.Error("Expected ActionStatusChanged in audit log after status update")
	}
}