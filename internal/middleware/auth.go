package middleware

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/temren/internal/config"
	"github.com/temren/internal/model"
)

// APIKeyPrefix marks a bearer token as an API key rather than a JWT.
const APIKeyPrefix = "tsk_"

// APIKeyAuth resolves a raw API key to its owner. Wired to
// service.APIKeyService.Authenticate in handler.SetupRoutes; nil disables keys.
var APIKeyAuth func(ctx context.Context, rawKey string) (*model.User, error)

// SessionOnly rejects requests authenticated with an API key, so a leaked key
// can't be used to mint or revoke keys.
func SessionOnly() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Locals("auth_method") == "api_key" {
			return c.Status(403).JSON(fiber.Map{"error": "this endpoint requires a login session, not an api key"})
		}
		return c.Next()
	}
}

func AuthRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{"error": "missing authorization header"})
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.Status(401).JSON(fiber.Map{"error": "invalid authorization format"})
		}

		if strings.HasPrefix(parts[1], APIKeyPrefix) {
			if APIKeyAuth == nil {
				return c.Status(401).JSON(fiber.Map{"error": "invalid or revoked api key"})
			}
			user, err := APIKeyAuth(c.Context(), parts[1])
			if err != nil {
				return c.Status(401).JSON(fiber.Map{"error": "invalid or revoked api key"})
			}
			c.Locals("user_id", user.ID)
			c.Locals("email", user.Email)
			c.Locals("plan", user.Plan)
			c.Locals("auth_method", "api_key")
			return c.Next()
		}

		token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(config.AppConfig.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "invalid or expired token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(401).JSON(fiber.Map{"error": "invalid token claims"})
		}

		c.Locals("user_id", claims["user_id"])
		c.Locals("email", claims["email"])
		c.Locals("plan", claims["plan"])

		return c.Next()
	}
}

func GetUserID(c *fiber.Ctx) string {
	if v := c.Locals("user_id"); v != nil {
		return v.(string)
	}
	return ""
}

func GetPlan(c *fiber.Ctx) string {
	if v := c.Locals("plan"); v != nil {
		return v.(string)
	}
	return "free"
}
