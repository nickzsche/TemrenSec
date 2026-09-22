package handler

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/temren/internal/middleware"
)

func (h *Handler) CreateAPIKey(c *fiber.Ctx) error {
	var body struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 255 {
		return c.Status(400).JSON(fiber.Map{"error": "name required (max 255 chars)"})
	}

	k, raw, err := h.apiKeySvc.Create(c.Context(), middleware.GetUserID(c), body.Name)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to create api key"})
	}
	return c.Status(201).JSON(fiber.Map{
		"id":         k.ID,
		"name":       k.Name,
		"prefix":     k.Prefix,
		"created_at": k.CreatedAt,
		"key":        raw, // shown once
	})
}

func (h *Handler) ListAPIKeys(c *fiber.Ctx) error {
	keys, err := h.apiKeySvc.List(c.Context(), middleware.GetUserID(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to list api keys"})
	}
	return c.JSON(keys)
}

func (h *Handler) RevokeAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if _, err := uuid.Parse(id); err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "api key not found"})
	}
	err := h.apiKeySvc.Revoke(c.Context(), id, middleware.GetUserID(c))
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "api key not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to revoke api key"})
	}
	return c.SendStatus(204)
}
