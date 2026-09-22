package middleware

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/temren/internal/config"
	"github.com/temren/internal/model"
)

func authApp(t *testing.T) *fiber.App {
	t.Helper()
	config.AppConfig = &config.Config{JWTSecret: "test-secret"}
	APIKeyAuth = func(_ context.Context, raw string) (*model.User, error) {
		if raw == "tsk_good" {
			return &model.User{ID: "u1", Email: "a@b.c", Plan: "pro"}, nil
		}
		return nil, errors.New("revoked")
	}
	t.Cleanup(func() { APIKeyAuth = nil })

	app := fiber.New()
	app.Get("/me", AuthRequired(), func(c *fiber.Ctx) error {
		return c.SendString(GetUserID(c) + "|" + GetPlan(c))
	})
	app.Get("/keys", AuthRequired(), SessionOnly(), func(c *fiber.Ctx) error { return c.SendString("ok") })
	return app
}

func get(t *testing.T, app *fiber.App, path, bearer string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

func TestAuthRequired_APIKeyAndJWT(t *testing.T) {
	app := authApp(t)

	if code, body := get(t, app, "/me", "tsk_good"); code != 200 || body != "u1|pro" {
		t.Fatalf("valid api key: got %d %q", code, body)
	}
	if code, _ := get(t, app, "/me", "tsk_revoked"); code != 401 {
		t.Fatalf("revoked api key: want 401, got %d", code)
	}

	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "u2", "plan": "free"}).SignedString([]byte("test-secret"))
	if code, body := get(t, app, "/me", tok); code != 200 || body != "u2|free" {
		t.Fatalf("jwt: got %d %q", code, body)
	}

	// A leaked key must not be able to manage keys; a session can.
	if code, _ := get(t, app, "/keys", "tsk_good"); code != 403 {
		t.Fatalf("api key on session-only route: want 403, got %d", code)
	}
	if code, _ := get(t, app, "/keys", tok); code != 200 {
		t.Fatalf("jwt on session-only route: want 200, got %d", code)
	}
}
