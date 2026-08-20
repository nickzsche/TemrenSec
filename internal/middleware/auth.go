package middleware

import (
	"strings"

	"github.com/temren/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// AuthRequired authenticates from the Authorization header.
func AuthRequired() fiber.Handler { return authenticate(false) }

// AuthRequiredWS authenticates a WebSocket upgrade. The browser WebSocket API
// cannot set request headers, so the token may also arrive as ?token=. Query
// strings land in access logs, so this is deliberately limited to /ws rather
// than accepted everywhere.
func AuthRequiredWS() fiber.Handler { return authenticate(true) }

func authenticate(allowQueryToken bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw := ""
		if authHeader := c.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				return c.Status(401).JSON(fiber.Map{"error": "invalid authorization format"})
			}
			raw = parts[1]
		} else if allowQueryToken {
			raw = c.Query("token")
		}

		if raw == "" {
			return c.Status(401).JSON(fiber.Map{"error": "missing authorization header"})
		}

		token, err := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(config.AppConfig.JWTSecret), nil
		}, jwt.WithValidMethods([]string{"HS256"}))

		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "invalid or expired token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(401).JSON(fiber.Map{"error": "invalid token claims"})
		}

		// user_id is the identity every ownership check downstream depends on;
		// a token without a usable one must not be treated as authenticated.
		userID, _ := claims["user_id"].(string)
		if userID == "" {
			return c.Status(401).JSON(fiber.Map{"error": "invalid token claims"})
		}

		c.Locals("user_id", userID)
		c.Locals("email", claims["email"])
		c.Locals("plan", claims["plan"])

		return c.Next()
	}
}

// GetUserID returns the authenticated user's ID, or "" when the request did not
// pass through AuthRequired. The type assertion is checked: /ws is reachable
// without the middleware, and an unchecked assertion panicked there.
func GetUserID(c *fiber.Ctx) string {
	if v, ok := c.Locals("user_id").(string); ok {
		return v
	}
	return ""
}

func GetPlan(c *fiber.Ctx) string {
	if v, ok := c.Locals("plan").(string); ok && v != "" {
		return v
	}
	return "free"
}
