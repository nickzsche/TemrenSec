package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/temren/internal/database"
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
)

// APIKeyPrefix marks a bearer token as an API key rather than a JWT.
const APIKeyPrefix = middleware.APIKeyPrefix

var ErrInvalidAPIKey = errors.New("invalid api key")

type APIKeyService struct {
	db *database.APIKeyRepo
}

func NewAPIKeyService() *APIKeyService {
	return &APIKeyService{db: database.NewAPIKeyRepo()}
}

// HashAPIKey is the stored form of a key. Keys carry 256 bits of entropy, so a
// plain SHA-256 is enough (and lets us look them up by hash).
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return APIKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Create returns the stored key and its plaintext; the plaintext is never
// retrievable again.
func (s *APIKeyService) Create(ctx context.Context, userID, name string) (*model.APIKey, string, error) {
	raw, err := generateAPIKey()
	if err != nil {
		return nil, "", err
	}
	k := &model.APIKey{UserID: userID, Name: name, Prefix: raw[:len(APIKeyPrefix)+8]}
	if err := s.db.Create(ctx, k, HashAPIKey(raw)); err != nil {
		return nil, "", err
	}
	return k, raw, nil
}

func (s *APIKeyService) List(ctx context.Context, userID string) ([]*model.APIKey, error) {
	return s.db.ListByUser(ctx, userID)
}

func (s *APIKeyService) Revoke(ctx context.Context, id, userID string) error {
	return s.db.Revoke(ctx, id, userID)
}

func (s *APIKeyService) Authenticate(ctx context.Context, raw string) (*model.User, error) {
	if !strings.HasPrefix(raw, APIKeyPrefix) {
		return nil, ErrInvalidAPIKey
	}
	u, err := s.db.Authenticate(ctx, HashAPIKey(raw))
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	return u, nil
}
