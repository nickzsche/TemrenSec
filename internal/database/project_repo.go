package database

import (
	"context"
	"time"

	"github.com/temren/internal/model"
	"github.com/google/uuid"
)

type ProjectRepo struct{}

func NewProjectRepo() *ProjectRepo { return &ProjectRepo{} }

func (r *ProjectRepo) Create(ctx context.Context, p *model.Project) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	_, err := Pool.Exec(ctx,
		`INSERT INTO projects (id, user_id, name, description, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		p.ID, p.UserID, p.Name, p.Description, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

func (r *ProjectRepo) GetByID(ctx context.Context, id string) (*model.Project, error) {
	p := &model.Project{}
	err := Pool.QueryRow(ctx,
		`SELECT id, user_id, name, description, created_at, updated_at FROM projects WHERE id=$1`, id,
	).Scan(&p.ID, &p.UserID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *ProjectRepo) ListByUser(ctx context.Context, userID string) ([]*model.Project, error) {
	rows, err := Pool.Query(ctx,
		`SELECT id, user_id, name, description, created_at, updated_at FROM projects WHERE user_id=$1 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []*model.Project
	for rows.Next() {
		p := &model.Project{}
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

func (r *ProjectRepo) Update(ctx context.Context, p *model.Project) error {
	p.UpdatedAt = time.Now()
	_, err := Pool.Exec(ctx,
		`UPDATE projects SET name=$2, description=$3, updated_at=$4 WHERE id=$1`,
		p.ID, p.Name, p.Description, p.UpdatedAt,
	)
	return err
}

func (r *ProjectRepo) Delete(ctx context.Context, id string) error {
	_, err := Pool.Exec(ctx, `DELETE FROM projects WHERE id=$1`, id)
	return err
}
