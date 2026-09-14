package handler

import (
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
	"github.com/gofiber/fiber/v2"
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
		status := 500
		if err.Error() == "plan limit reached" {
			status = 403
		}
		return c.Status(status).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(target)
}

func (h *Handler) DeleteTarget(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	if err := h.targetSvc.Delete(c.Context(), id, userID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "target deleted"})
}
