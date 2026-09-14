package database

import (
	"context"
	"time"

	"github.com/temren/internal/model"
	"github.com/google/uuid"
)

type UserRepo struct{}

func NewUserRepo() *UserRepo { return &UserRepo{} }

func (r *UserRepo) Create(ctx context.Context, user *model.User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := Pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, full_name, plan, totp_secret, totp_enabled, email_verified, verification_token, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		user.ID, user.Email, user.PasswordHash, user.FullName, user.Plan, user.TOTPSecret, user.TOTPEnabled, user.EmailVerified, user.VerificationToken, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

func (r *UserRepo) GetByID(ctx context.Context, id string) (*model.User, error) {
	user := &model.User{}
	err := Pool.QueryRow(ctx,
		`SELECT id, email, password_hash, full_name, plan, totp_secret, totp_enabled, email_verified, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.FullName, &user.Plan, &user.TOTPSecret, &user.TOTPEnabled, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	user := &model.User{}
	err := Pool.QueryRow(ctx,
		`SELECT id, email, password_hash, full_name, plan, totp_secret, totp_enabled, email_verified, created_at, updated_at
		 FROM users WHERE email = $1`, email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.FullName, &user.Plan, &user.TOTPSecret, &user.TOTPEnabled, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepo) Update(ctx context.Context, user *model.User) error {
	user.UpdatedAt = time.Now()
	_, err := Pool.Exec(ctx,
		`UPDATE users SET email=$2, full_name=$3, plan=$4, totp_secret=$5, totp_enabled=$6, updated_at=$7 WHERE id=$1`,
		user.ID, user.Email, user.FullName, user.Plan, user.TOTPSecret, user.TOTPEnabled, user.UpdatedAt,
	)
	return err
}

func (r *UserRepo) Delete(ctx context.Context, id string) error {
	_, err := Pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

func (r *UserRepo) StoreRefreshToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	id := uuid.New().String()
	_, err := Pool.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)`,
		id, userID, token, expiresAt,
	)
	return err
}

func (r *UserRepo) GetRefreshToken(ctx context.Context, token string) (*model.RefreshToken, error) {
	rt := &model.RefreshToken{}
	err := Pool.QueryRow(ctx,
		`SELECT id, user_id, token, expires_at, created_at FROM refresh_tokens WHERE token=$1 AND expires_at > NOW()`,
		token,
	).Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt, &rt.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *UserRepo) DeleteRefreshToken(ctx context.Context, token string) error {
	_, err := Pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE token=$1`, token)
	return err
}

func (r *UserRepo) DeleteUserRefreshTokens(ctx context.Context, userID string) error {
	_, err := Pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id=$1`, userID)
	return err
}
