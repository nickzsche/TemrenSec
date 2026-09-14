package database

import (
	"context"
	"time"

	"github.com/temren/internal/model"
	"github.com/google/uuid"
)

type TargetRepo struct{}

func NewTargetRepo() *TargetRepo { return &TargetRepo{} }

func (r *TargetRepo) Create(ctx context.Context, t *model.Target) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	now := time.Now()
	t.CreatedAt = now
	t.UpdatedAt = now
	_, err := Pool.Exec(ctx,
		`INSERT INTO targets (id, project_id, url, name, scan_settings, status, schedule, security_score, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		t.ID, t.ProjectID, t.URL, t.Name, t.ScanSettings, t.Status, t.Schedule, t.SecurityScore, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

func (r *TargetRepo) GetByID(ctx context.Context, id string) (*model.Target, error) {
	t := &model.Target{}
	err := Pool.QueryRow(ctx,
		`SELECT id, project_id, url, name, scan_settings, status, last_scan_at, schedule, security_score, created_at, updated_at
		 FROM targets WHERE id=$1`, id,
	).Scan(&t.ID, &t.ProjectID, &t.URL, &t.Name, &t.ScanSettings, &t.Status, &t.LastScanAt, &t.Schedule, &t.SecurityScore, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TargetRepo) ListByProject(ctx context.Context, projectID string) ([]*model.Target, error) {
	rows, err := Pool.Query(ctx,
		`SELECT id, project_id, url, name, scan_settings, status, last_scan_at, schedule, security_score, created_at, updated_at
		 FROM targets WHERE project_id=$1 ORDER BY created_at DESC`, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*model.Target
	for rows.Next() {
		t := &model.Target{}
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.URL, &t.Name, &t.ScanSettings, &t.Status, &t.LastScanAt, &t.Schedule, &t.SecurityScore, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func (r *TargetRepo) CountByUser(ctx context.Context, userID string) (int, error) {
	var count int
	err := Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM targets t JOIN projects p ON t.project_id = p.id WHERE p.user_id = $1`, userID,
	).Scan(&count)
	return count, err
}

func (r *TargetRepo) Update(ctx context.Context, t *model.Target) error {
	t.UpdatedAt = time.Now()
	_, err := Pool.Exec(ctx,
		`UPDATE targets SET url=$2, name=$3, scan_settings=$4, status=$5, schedule=$6, security_score=$7, last_scan_at=$8, updated_at=$9 WHERE id=$1`,
		t.ID, t.URL, t.Name, t.ScanSettings, t.Status, t.Schedule, t.SecurityScore, t.LastScanAt, t.UpdatedAt,
	)
	return err
}

func (r *TargetRepo) Delete(ctx context.Context, id string) error {
	_, err := Pool.Exec(ctx, `DELETE FROM targets WHERE id=$1`, id)
	return err
}

func (r *TargetRepo) UpdateSecurityScore(ctx context.Context, id string, score int) error {
	_, err := Pool.Exec(ctx, `UPDATE targets SET security_score=$2, updated_at=NOW() WHERE id=$1`, id, score)
	return err
}

func (r *TargetRepo) ListScheduled(ctx context.Context) ([]*model.Target, error) {
	rows, err := Pool.Query(ctx,
		`SELECT id, project_id, url, name, scan_settings, status, last_scan_at, schedule, security_score, created_at, updated_at
		 FROM targets WHERE schedule != '' AND status = 'active'`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*model.Target
	for rows.Next() {
		t := &model.Target{}
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.URL, &t.Name, &t.ScanSettings, &t.Status, &t.LastScanAt, &t.Schedule, &t.SecurityScore, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}
