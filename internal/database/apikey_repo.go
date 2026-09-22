package database

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/temren/internal/model"
)

type APIKeyRepo struct{}

func NewAPIKeyRepo() *APIKeyRepo { return &APIKeyRepo{} }

func (r *APIKeyRepo) Create(ctx context.Context, k *model.APIKey, keyHash string) error {
	if k.ID == "" {
		k.ID = uuid.New().String()
	}
	k.CreatedAt = time.Now()
	_, err := Pool.Exec(ctx,
		`INSERT INTO api_keys (id, user_id, name, prefix, key_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		k.ID, k.UserID, k.Name, k.Prefix, keyHash, k.CreatedAt,
	)
	return err
}

// ListByUser returns the user's active (non-revoked) keys, newest first.
func (r *APIKeyRepo) ListByUser(ctx context.Context, userID string) ([]*model.APIKey, error) {
	rows, err := Pool.Query(ctx,
		`SELECT id, user_id, name, prefix, last_used_at, created_at FROM api_keys
		 WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []*model.APIKey{}
	for rows.Next() {
		k := &model.APIKey{}
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// Revoke marks the key revoked. Scoped by user so one user can't revoke
// another's key; returns pgx.ErrNoRows when nothing matched.
func (r *APIKeyRepo) Revoke(ctx context.Context, id, userID string) error {
	tag, err := Pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, userID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// Authenticate resolves an active key hash to its owner and stamps last_used_at.
func (r *APIKeyRepo) Authenticate(ctx context.Context, keyHash string) (*model.User, error) {
	u := &model.User{}
	err := Pool.QueryRow(ctx,
		`UPDATE api_keys k SET last_used_at=NOW() FROM users u
		 WHERE k.key_hash=$1 AND k.revoked_at IS NULL AND u.id=k.user_id
		 RETURNING u.id, u.email, u.plan`, keyHash,
	).Scan(&u.ID, &u.Email, &u.Plan)
	if err != nil {
		return nil, err
	}
	return u, nil
}
