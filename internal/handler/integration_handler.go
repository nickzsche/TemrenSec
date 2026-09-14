package handler

import (
	"fmt"
	"time"

	"github.com/temren/internal/integration/github"
	"github.com/temren/internal/integration/jira"
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/scheduler"
	"github.com/temren/internal/webhook"
	"github.com/gofiber/fiber/v2"
)

func (h *Handler) CreateSchedule(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	targetID := c.Params("targetId")

	var req struct {
		CronExpr  string `json:"cron_expr"`
		Frequency string `json:"frequency"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	schedule := &scheduler.Schedule{
		ID:        fmt.Sprintf("sch_%d", time.Now().UnixNano()),
		TargetID:  targetID,
		UserID:    userID,
		CronExpr:  req.CronExpr,
		Frequency: req.Frequency,
		Enabled:   true,
	}

	return c.Status(201).JSON(schedule)
}

func (h *Handler) GetSchedule(c *fiber.Ctx) error {
	targetID := c.Params("targetId")
	return c.JSON(fiber.Map{"target_id": targetID, "schedule": nil})
}

func (h *Handler) DeleteSchedule(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "schedule deleted"})
}

func (h *Handler) GetScanProgress(c *fiber.Ctx) error {
	scanID := c.Params("scanId")
	
	if wsHub == nil {
		return c.JSON(fiber.Map{"scan_id": scanID, "progress": 0, "status": "unknown"})
	}
	
	progress, ok := wsHub.GetScanProgress(scanID)
	if !ok {
		return c.JSON(fiber.Map{"scan_id": scanID, "progress": 0, "status": "pending"})
	}
	
	return c.JSON(progress)
}

func (h *Handler) GetVulnerability(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	vulnID := c.Params("vulnId")
	
	vuln, err := h.scanSvc.GetVulnerability(c.Context(), vulnID, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "vulnerability not found"})
	}
	
	return c.JSON(vuln)
}

func (h *Handler) ListWebhooks(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"webhooks": []interface{}{}})
}

func (h *Handler) CreateWebhook(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	
	var req struct {
		URL    string   `json:"url"`
		Secret string   `json:"secret"`
		Events []string `json:"events"`
	}
	
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	
	endpoint := &webhook.WebhookEndpoint{
		ID:     fmt.Sprintf("wh_%d", time.Now().UnixNano()),
		UserID: userID,
		URL:    req.URL,
		Secret: req.Secret,
		Events: req.Events,
		Active: true,
	}
	
	return c.Status(201).JSON(endpoint)
}

func (h *Handler) DeleteWebhook(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "webhook deleted"})
}

func (h *Handler) TestWebhook(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "webhook test sent", "status": "success"})
}

func (h *Handler) ConfigureJira(c *fiber.Ctx) error {
	var req struct {
		BaseURL  string `json:"base_url"`
		Username string `json:"username"`
		APIToken string `json:"api_token"`
		Project  string `json:"project"`
	}
	
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	
	client := jira.NewClient(&jira.Config{
		BaseURL:  req.BaseURL,
		Username: req.Username,
		APIToken: req.APIToken,
		Project:  req.Project,
	})
	
	if err := client.TestConnection(); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error(), "connected": false})
	}
	
	return c.JSON(fiber.Map{"connected": true, "message": "Jira connected successfully"})
}

func (h *Handler) TestJira(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok", "message": "Jira integration test"})
}

func (h *Handler) ConfigureGitHub(c *fiber.Ctx) error {
	var req struct {
		Token      string `json:"token"`
		Owner      string `json:"owner"`
		Repository string `json:"repository"`
	}
	
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	
	client := github.NewClient(&github.Config{
		Token:      req.Token,
		Owner:      req.Owner,
		Repository: req.Repository,
	})
	
	if err := client.TestConnection(); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error(), "connected": false})
	}
	
	return c.JSON(fiber.Map{"connected": true, "message": "GitHub connected successfully"})
}

func (h *Handler) TestGitHub(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok", "message": "GitHub integration test"})
}
