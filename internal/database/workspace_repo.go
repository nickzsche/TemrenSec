package database

import (
	"context"

	"github.com/temren/internal/model"
)

// WorkspaceRepo persists workspaces (ASPM grouping) in the workspaces table.
// Replaces the previous in-memory store so workspaces survive restarts.
type WorkspaceRepo struct{}

func NewWorkspaceRepo() *WorkspaceRepo { return &WorkspaceRepo{} }

// Create inserts a workspace. createdBy may be "" (stored as NULL).
func (r *WorkspaceRepo) Create(ctx context.Context, name, description, createdBy string) (*model.Workspace, error) {
	w := &model.Workspace{Name: name, Description: description, CreatedBy: createdBy}
	var by interface{}
	if createdBy != "" {
		by = createdBy
	}
	err := Pool.QueryRow(ctx,
		`INSERT INTO workspaces (name, description, created_by)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at`,
		name, description, by,
	).Scan(&w.ID, &w.CreatedAt)
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (r *WorkspaceRepo) List(ctx context.Context) ([]*model.Workspace, error) {
	rows, err := Pool.Query(ctx,
		`SELECT id, name, description, created_at FROM workspaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*model.Workspace, 0)
	for rows.Next() {
		w := &model.Workspace{}
		if err := rows.Scan(&w.ID, &w.Name, &w.Description, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
