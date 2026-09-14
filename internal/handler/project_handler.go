package handler

import (
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
	"github.com/gofiber/fiber/v2"
)

func (h *Handler) CreateProject(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	var req model.CreateProjectRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "name is required"})
	}

	project, err := h.projectSvc.Create(c.Context(), userID, req.Name, req.Description)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(project)
}

func (h *Handler) GetProject(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	project, err := h.projectSvc.Get(c.Context(), id, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "project not found"})
	}

	return c.JSON(project)
}

func (h *Handler) ListProjects(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	projects, err := h.projectSvc.List(c.Context(), userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"projects": projects})
}

func (h *Handler) UpdateProject(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	var req model.CreateProjectRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	project, err := h.projectSvc.Update(c.Context(), id, userID, req.Name, req.Description)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(project)
}

func (h *Handler) DeleteProject(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	if err := h.projectSvc.Delete(c.Context(), id, userID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "project deleted"})
}
