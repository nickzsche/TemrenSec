package database

import (
	"context"

	"github.com/temren/internal/model"
)

// TriageRepo persists triage suppression rules (triage_suppressions table).
// Suppressions hide matching findings on every scan, so triaged noise stays
// gone instead of resurfacing each run.
type TriageRepo struct{}

func NewTriageRepo() *TriageRepo { return &TriageRepo{} }

func (r *TriageRepo) Create(ctx context.Context, s *model.TriageSuppression) error {
	var ws interface{}
	if s.WorkspaceID != "" {
		ws = s.WorkspaceID
	}
	return Pool.QueryRow(ctx,
		`INSERT INTO triage_suppressions (workspace_id, scanner, url_glob, param, reason)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		ws, s.Scanner, s.URLGlob, s.Param, s.Reason,
	).Scan(&s.ID, &s.CreatedAt)
}

func (r *TriageRepo) List(ctx context.Context) ([]*model.TriageSuppression, error) {
	rows, err := Pool.Query(ctx,
		`SELECT id, COALESCE(workspace_id::text,''), COALESCE(scanner,''), COALESCE(url_glob,''),
		        COALESCE(param,''), COALESCE(reason,''), created_at
		 FROM triage_suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*model.TriageSuppression, 0)
	for rows.Next() {
		s := &model.TriageSuppression{}
		if err := rows.Scan(&s.ID, &s.WorkspaceID, &s.Scanner, &s.URLGlob, &s.Param, &s.Reason, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListGlobal returns suppressions with no workspace (applied to every scan).
func (r *TriageRepo) ListGlobal(ctx context.Context) ([]*model.TriageSuppression, error) {
	rows, err := Pool.Query(ctx,
		`SELECT id, '', COALESCE(scanner,''), COALESCE(url_glob,''), COALESCE(param,''),
		        COALESCE(reason,''), created_at
		 FROM triage_suppressions WHERE workspace_id IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*model.TriageSuppression, 0)
	for rows.Next() {
		s := &model.TriageSuppression{}
		if err := rows.Scan(&s.ID, &s.WorkspaceID, &s.Scanner, &s.URLGlob, &s.Param, &s.Reason, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
