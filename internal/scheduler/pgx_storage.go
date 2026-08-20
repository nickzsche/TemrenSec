package scheduler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/temren/internal/database"
	"github.com/jackc/pgx/v5"
)

// PgxStorage implements Storage on the application's pgx pool.
//
// PostgresStorage already existed but takes a *sql.DB, while the rest of the
// app runs on pgxpool — which is part of why the scheduler was never wired up
// and the HTTP handlers returned invented schedules instead. This adapter lets
// the real scheduler run on the pool the app already has.
//
// The schedules table is created by migration 002.
type PgxStorage struct{}

func NewPgxStorage() *PgxStorage { return &PgxStorage{} }

const scheduleColumns = `id, target_id, user_id, cron_expr, frequency, enabled,
	COALESCE(last_run, 'epoch'::timestamptz), COALESCE(next_run, 'epoch'::timestamptz),
	created_at, updated_at`

func scanSchedule(row pgx.Row) (*Schedule, error) {
	var s Schedule
	err := row.Scan(&s.ID, &s.TargetID, &s.UserID, &s.CronExpr, &s.Frequency,
		&s.Enabled, &s.LastRun, &s.NextRun, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (p *PgxStorage) Save(s *Schedule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	_, err := database.Pool.Exec(ctx, `
		INSERT INTO schedules (id, target_id, user_id, cron_expr, frequency, enabled,
		                       last_run, next_run, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, 'epoch'::timestamptz),
		        NULLIF($8, 'epoch'::timestamptz), $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			cron_expr  = EXCLUDED.cron_expr,
			frequency  = EXCLUDED.frequency,
			enabled    = EXCLUDED.enabled,
			next_run   = EXCLUDED.next_run,
			updated_at = EXCLUDED.updated_at`,
		s.ID, s.TargetID, s.UserID, s.CronExpr, s.Frequency, s.Enabled,
		s.LastRun, s.NextRun, s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save schedule: %w", err)
	}
	return nil
}

func (p *PgxStorage) Get(id string) (*Schedule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := scanSchedule(database.Pool.QueryRow(ctx,
		`SELECT `+scheduleColumns+` FROM schedules WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("schedule not found")
	}
	return s, err
}

func (p *PgxStorage) GetByTarget(targetID string) (*Schedule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := scanSchedule(database.Pool.QueryRow(ctx,
		`SELECT `+scheduleColumns+` FROM schedules WHERE target_id = $1
		 ORDER BY created_at DESC LIMIT 1`, targetID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("schedule not found")
	}
	return s, err
}

func (p *PgxStorage) List(userID string) ([]*Schedule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := database.Pool.Query(ctx,
		`SELECT `+scheduleColumns+` FROM schedules WHERE user_id = $1
		 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	defer rows.Close()

	var out []*Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan schedule: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListEnabled returns every active schedule, for rehydrating the in-memory cron
// on startup. Without this a restart silently stops all recurring scans.
func (p *PgxStorage) ListEnabled() ([]*Schedule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := database.Pool.Query(ctx,
		`SELECT `+scheduleColumns+` FROM schedules WHERE enabled = true`)
	if err != nil {
		return nil, fmt.Errorf("list enabled schedules: %w", err)
	}
	defer rows.Close()

	var out []*Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan schedule: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PgxStorage) Delete(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := database.Pool.Exec(ctx, `DELETE FROM schedules WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete schedule: %w", err)
	}
	return nil
}

func (p *PgxStorage) Update(s *Schedule) error { return p.Save(s) }
