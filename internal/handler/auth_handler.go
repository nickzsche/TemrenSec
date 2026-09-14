package handler

import (
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
	"github.com/temren/internal/service"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	authSvc    *service.AuthService
	projectSvc *service.ProjectService
	targetSvc  *service.TargetService
	scanSvc    *service.ScanService
}

func NewHandler() *Handler {
	return &Handler{
		authSvc:    service.NewAuthService(),
		projectSvc: service.NewProjectService(),
		targetSvc:  service.NewTargetService(),
		scanSvc:    service.NewScanService(),
	}
}

func (h *Handler) Register(c *fiber.Ctx) error {
	var req model.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email and password required"})
	}

	resp, err := h.authSvc.Register(c.Context(), req.Email, req.Password, req.FullName)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(resp)
}

func (h *Handler) Login(c *fiber.Ctx) error {
	var req model.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email and password required"})
	}

	resp, err := h.authSvc.Login(c.Context(), req.Email, req.Password, req.TOTPCode)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (h *Handler) RefreshToken(c *fiber.Ctx) error {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	resp, err := h.authSvc.RefreshToken(c.Context(), body.RefreshToken)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (h *Handler) Logout(c *fiber.Ctx) error {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = c.BodyParser(&body)
	h.authSvc.Logout(c.Context(), body.RefreshToken)
	return c.JSON(fiber.Map{"message": "logged out"})
}

func (h *Handler) GetMe(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	user, err := h.authSvc.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(user)
}

func (h *Handler) Enable2FA(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	uri, err := h.authSvc.Enable2FA(c.Context(), userID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"totp_uri": uri})
}

func (h *Handler) Verify2FA(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	var body struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	if err := h.authSvc.Verify2FA(c.Context(), userID, body.Code); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "2FA enabled"})
}
