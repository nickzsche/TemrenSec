package handler

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
)

func (h *Handler) CreateTarget(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	var req model.CreateTargetRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.URL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "url is required"})
	}

	target, err := h.targetSvc.Create(c.Context(), userID, &req)
	if err != nil {
		// An invalid or refused target URL is the caller's mistake, not a
		// server fault; everything else goes through the sentinel mapping.
		if strings.Contains(err.Error(), "invalid target URL") {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		return respondError(c, err)
	}

	return c.Status(201).JSON(target)
}

func (h *Handler) GetTarget(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	target, err := h.targetSvc.Get(c.Context(), id, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "target not found"})
	}

	return c.JSON(target)
}

func (h *Handler) ListTargets(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	projectID := c.Params("projectId")

	targets, err := h.targetSvc.List(c.Context(), projectID, userID)
	if err != nil {
		return respondError(c, err)
	}

	return c.JSON(fiber.Map{"targets": targets})
}

func (h *Handler) UpdateTarget(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	var req model.CreateTargetRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	target, err := h.targetSvc.Update(c.Context(), id, userID, &req)
	if err != nil {
		return respondError(c, err)
	}

	return c.JSON(target)
}

func (h *Handler) DeleteTarget(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	if err := h.targetSvc.Delete(c.Context(), id, userID); err != nil {
		return respondError(c, err)
	}

	return c.JSON(fiber.Map{"message": "target deleted"})
}
