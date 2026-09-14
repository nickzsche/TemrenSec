package middleware

import (
	"strings"

	"github.com/temren/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

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
