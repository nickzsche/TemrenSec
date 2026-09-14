package scheduler

import (
	"database/sql"
	"fmt"
	"time"
)

type PostgresStorage struct {
	db *sql.DB
}

func NewPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

func (s *PostgresStorage) InitSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS schedules (
		id VARCHAR(255) PRIMARY KEY,
		target_id VARCHAR(255) NOT NULL,
		user_id VARCHAR(255) NOT NULL,
		cron_expr VARCHAR(255),
		frequency VARCHAR(50),
		enabled BOOLEAN DEFAULT true,
		last_run TIMESTAMP,
		next_run TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_schedules_target ON schedules(target_id);
	CREATE INDEX IF NOT EXISTS idx_schedules_user ON schedules(user_id);
	`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStorage) Save(schedule *Schedule) error {
	query := `
		INSERT INTO schedules (id, target_id, user_id, cron_expr, frequency, enabled, next_run, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			target_id = EXCLUDED.target_id,
			cron_expr = EXCLUDED.cron_expr,
			frequency = EXCLUDED.frequency,
			enabled = EXCLUDED.enabled,
			next_run = EXCLUDED.next_run,
			updated_at = EXCLUDED.updated_at
	`
	
	if schedule.CreatedAt.IsZero() {
		schedule.CreatedAt = time.Now()
	}
	schedule.UpdatedAt = time.Now()

	_, err := s.db.Exec(query,
		schedule.ID,
		schedule.TargetID,
		schedule.UserID,
		schedule.CronExpr,
		schedule.Frequency,
		schedule.Enabled,
		schedule.NextRun,
		schedule.CreatedAt,
		schedule.UpdatedAt,
	)
	
	return err
}

func (s *PostgresStorage) Get(id string) (*Schedule, error) {
	query := `SELECT id, target_id, user_id, cron_expr, frequency, enabled, last_run, next_run, created_at, updated_at FROM schedules WHERE id = $1`
	
	row := s.db.QueryRow(query, id)
	schedule := &Schedule{}
	
	var lastRun, nextRun sql.NullTime
	
	err := row.Scan(
		&schedule.ID,
		&schedule.TargetID,
		&schedule.UserID,
		&schedule.CronExpr,
		&schedule.Frequency,
		&schedule.Enabled,
		&lastRun,
		&nextRun,
		&schedule.CreatedAt,
		&schedule.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("schedule not found")
		}
		return nil, err
	}
	
	if lastRun.Valid {
		schedule.LastRun = lastRun.Time
	}
	if nextRun.Valid {
		schedule.NextRun = nextRun.Time
	}
	
	return schedule, nil
}

func (s *PostgresStorage) GetByTarget(targetID string) (*Schedule, error) {
	query := `SELECT id, target_id, user_id, cron_expr, frequency, enabled, last_run, next_run, created_at, updated_at FROM schedules WHERE target_id = $1 LIMIT 1`
	
	row := s.db.QueryRow(query, targetID)
	schedule := &Schedule{}
	
	var lastRun, nextRun sql.NullTime
	
	err := row.Scan(
		&schedule.ID,
		&schedule.TargetID,
		&schedule.UserID,
		&schedule.CronExpr,
		&schedule.Frequency,
		&schedule.Enabled,
		&lastRun,
		&nextRun,
		&schedule.CreatedAt,
		&schedule.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("schedule not found")
		}
		return nil, err
	}
	
	if lastRun.Valid {
		schedule.LastRun = lastRun.Time
	}
	if nextRun.Valid {
		schedule.NextRun = nextRun.Time
	}
	
	return schedule, nil
}

func (s *PostgresStorage) List(userID string) ([]*Schedule, error) {
	query := `SELECT id, target_id, user_id, cron_expr, frequency, enabled, last_run, next_run, created_at, updated_at FROM schedules WHERE user_id = $1 ORDER BY created_at DESC`
	
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var schedules []*Schedule
	
	for rows.Next() {
		schedule := &Schedule{}
		var lastRun, nextRun sql.NullTime
		
		err := rows.Scan(
			&schedule.ID,
			&schedule.TargetID,
			&schedule.UserID,
			&schedule.CronExpr,
			&schedule.Frequency,
			&schedule.Enabled,
			&lastRun,
			&nextRun,
			&schedule.CreatedAt,
			&schedule.UpdatedAt,
		)
		
		if err != nil {
			return nil, err
		}
		
		if lastRun.Valid {
			schedule.LastRun = lastRun.Time
		}
		if nextRun.Valid {
			schedule.NextRun = nextRun.Time
		}
		
		schedules = append(schedules, schedule)
	}
	
	return schedules, rows.Err()
}

func (s *PostgresStorage) Delete(id string) error {
	query := `DELETE FROM schedules WHERE id = $1`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgresStorage) Update(schedule *Schedule) error {
	return s.Save(schedule)
}
