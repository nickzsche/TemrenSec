package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/temren/internal/config"
	"github.com/temren/internal/database"
	"github.com/temren/internal/model"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userDB *database.UserRepo
}

func NewAuthService() *AuthService {
	return &AuthService{
		userDB: database.NewUserRepo(),
	}
}

func (s *AuthService) Register(ctx context.Context, email, password, fullName string) (*model.AuthResponse, error) {
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Email:        email,
		PasswordHash: string(hash),
		FullName:     fullName,
		Plan:         "free",
	}

	if err := s.userDB.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("email already exists")
	}

	return s.generateTokens(user)
}

func (s *AuthService) Login(ctx context.Context, email, password, totpCode string) (*model.AuthResponse, error) {
	user, err := s.userDB.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.TOTPEnabled {
		if totpCode == "" {
			return nil, fmt.Errorf("2FA code required")
		}
		if !ValidateTOTP(user.TOTPSecret, totpCode) {
			return nil, fmt.Errorf("invalid 2FA code")
		}
	}

	return s.generateTokens(user)
}

func (s *AuthService) RefreshToken(ctx context.Context, token string) (*model.AuthResponse, error) {
	rt, err := s.userDB.GetRefreshToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	user, err := s.userDB.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	_ = s.userDB.DeleteRefreshToken(ctx, token)

	return s.generateTokens(user)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) {
	if refreshToken != "" {
		_ = s.userDB.DeleteRefreshToken(ctx, refreshToken)
	}
}

func (s *AuthService) Enable2FA(ctx context.Context, userID string) (string, error) {
	user, err := s.userDB.GetByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("user not found")
	}

	if user.TOTPSecret == "" {
		secret := GenerateTOTPSecret()
		user.TOTPSecret = secret
		_ = s.userDB.Update(ctx, user)
	}

	return TOTPURI(user.Email, user.TOTPSecret), nil
}

func (s *AuthService) Verify2FA(ctx context.Context, userID, code string) error {
	user, err := s.userDB.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if !ValidateTOTP(user.TOTPSecret, code) {
		return fmt.Errorf("invalid code")
	}

	user.TOTPEnabled = true
	return s.userDB.Update(ctx, user)
}

func (s *AuthService) GetUser(ctx context.Context, userID string) (*model.User, error) {
	user, err := s.userDB.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	user.PasswordHash = ""
	user.TOTPSecret = ""
	return user, nil
}

func (s *AuthService) generateTokens(user *model.User) (*model.AuthResponse, error) {
	now := time.Now()
	accessExpiry := now.Add(24 * time.Hour)
	refreshExpiry := now.Add(7 * 24 * time.Hour)

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"plan":    user.Plan,
		"iat":     now.Unix(),
		"exp":     accessExpiry.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(config.AppConfig.JWTSecret))
	if err != nil {
		return nil, err
	}

	refreshToken := GenerateRefreshToken()
	ctx := context.Background()
	if err := s.userDB.StoreRefreshToken(ctx, user.ID, refreshToken, refreshExpiry); err != nil {
		return nil, err
	}

	user.PasswordHash = ""
	user.TOTPSecret = ""

	return &model.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func GenerateRefreshToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func GenerateTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func TOTPURI(email, secret string) string {
	return fmt.Sprintf("otpauth://totp/Temren:%s?secret=%s&issuer=Temren", email, secret)
}

func ValidateTOTP(secret, code string) bool {
	now := time.Now().Unix() / 30
	for i := -1; i <= 1; i++ {
		if generateTOTPCode(secret, now+int64(i)) == code {
			return true
		}
	}
	return false
}

func generateTOTPCode(secret string, timestamp int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	code := truncated % uint32(math.Pow10(6))
	return fmt.Sprintf("%06d", code)
}
