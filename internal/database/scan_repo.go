package database

import (
	"context"
	"encoding/json"
	"time"

	"github.com/temren/internal/model"
	"github.com/google/uuid"
)

type ScanRepo struct{}

func NewScanRepo() *ScanRepo { return &ScanRepo{} }

func (r *ScanRepo) Create(ctx context.Context, s *model.Scan) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	s.CreatedAt = time.Now()
	if s.Status == "" {
		s.Status = "pending"
	}
	_, err := Pool.Exec(ctx,
		`INSERT INTO scans (id, target_id, status, config, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		s.ID, s.TargetID, s.Status, s.Config, s.CreatedAt,
	)
	return err
}

func (r *ScanRepo) GetByID(ctx context.Context, id string) (*model.Scan, error) {
	s := &model.Scan{}
	err := Pool.QueryRow(ctx,
		`SELECT id, target_id, status, started_at, completed_at, duration_seconds, pages_crawled,
		        total_findings, critical_count, high_count, medium_count, low_count, info_count,
		        summary, config, error, created_at
		 FROM scans WHERE id=$1`, id,
	).Scan(&s.ID, &s.TargetID, &s.Status, &s.StartedAt, &s.CompletedAt, &s.DurationSeconds, &s.PagesCrawled,
		&s.TotalFindings, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
		&s.Summary, &s.Config, &s.Error, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r *ScanRepo) ListByTarget(ctx context.Context, targetID string, limit, offset int) ([]*model.Scan, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := Pool.Query(ctx,
		`SELECT id, target_id, status, started_at, completed_at, duration_seconds, pages_crawled,
		        total_findings, critical_count, high_count, medium_count, low_count, info_count,
		        summary, config, error, created_at
		 FROM scans WHERE target_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, targetID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*model.Scan
	for rows.Next() {
		s := &model.Scan{}
		if err := rows.Scan(&s.ID, &s.TargetID, &s.Status, &s.StartedAt, &s.CompletedAt, &s.DurationSeconds, &s.PagesCrawled,
			&s.TotalFindings, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
			&s.Summary, &s.Config, &s.Error, &s.CreatedAt); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, nil
}

func (r *ScanRepo) ListByUser(ctx context.Context, userID string, limit, offset int) ([]*model.Scan, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := Pool.Query(ctx,
		`SELECT s.id, s.target_id, s.status, s.started_at, s.completed_at, s.duration_seconds, s.pages_crawled,
		        s.total_findings, s.critical_count, s.high_count, s.medium_count, s.low_count, s.info_count,
		        s.summary, s.config, s.error, s.created_at
		 FROM scans s
		 JOIN targets t ON s.target_id = t.id
		 JOIN projects p ON t.project_id = p.id
		 WHERE p.user_id = $1
		 ORDER BY s.created_at DESC LIMIT $2 OFFSET $3`, userID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*model.Scan
	for rows.Next() {
		s := &model.Scan{}
		if err := rows.Scan(&s.ID, &s.TargetID, &s.Status, &s.StartedAt, &s.CompletedAt, &s.DurationSeconds, &s.PagesCrawled,
			&s.TotalFindings, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
			&s.Summary, &s.Config, &s.Error, &s.CreatedAt); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, nil
}

func (r *ScanRepo) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := Pool.Exec(ctx, `UPDATE scans SET status=$2 WHERE id=$1`, id, status)
	return err
}

func (r *ScanRepo) StartScan(ctx context.Context, id string) error {
	now := time.Now()
	_, err := Pool.Exec(ctx,
		`UPDATE scans SET status='running', started_at=$2 WHERE id=$1`, id, now,
	)
	return err
}

func (r *ScanRepo) CompleteScan(ctx context.Context, s *model.Scan) error {
	now := time.Now()
	s.CompletedAt = &now
	if s.StartedAt != nil {
		s.DurationSeconds = int(now.Sub(*s.StartedAt).Seconds())
	}
	summaryJSON, _ := json.Marshal(map[string]int{
		"critical": s.CriticalCount,
		"high":     s.HighCount,
		"medium":   s.MediumCount,
		"low":      s.LowCount,
		"info":     s.InfoCount,
	})

	_, err := Pool.Exec(ctx,
		`UPDATE scans SET status='completed', completed_at=$2, duration_seconds=$3, pages_crawled=$4,
		        total_findings=$5, critical_count=$6, high_count=$7, medium_count=$8, low_count=$9, info_count=$10,
		        summary=$11 WHERE id=$1`,
		s.ID, s.CompletedAt, s.DurationSeconds, s.PagesCrawled,
		s.TotalFindings, s.CriticalCount, s.HighCount, s.MediumCount, s.LowCount, s.InfoCount,
		string(summaryJSON),
	)
	return err
}

func (r *ScanRepo) FailScan(ctx context.Context, id, scanErr string) error {
	_, err := Pool.Exec(ctx,
		`UPDATE scans SET status='failed', completed_at=NOW(), error=$2 WHERE id=$1`, id, scanErr,
	)
	return err
}

func (r *ScanRepo) CountByUser(ctx context.Context, userID string) (int, error) {
	var count int
	err := Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM scans s
		 JOIN targets t ON s.target_id = t.id
		 JOIN projects p ON t.project_id = p.id
		 WHERE p.user_id = $1 AND DATE(s.created_at) = CURRENT_DATE`, userID,
	).Scan(&count)
	return count, err
}
