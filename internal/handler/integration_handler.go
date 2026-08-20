package handler

import (
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/temren/internal/integration/github"
	"github.com/temren/internal/integration/jira"
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/safeurl"
	"github.com/temren/internal/scheduler"
	"github.com/temren/internal/webhook"
)

// Schedule and webhook handlers persist through the scheduler and webhook
// managers. They previously built a struct in memory and returned 201 without
// storing anything, while the real implementations sat unused next door — so
// "Scheduled Scans" and "Webhooks" appeared to work and silently did nothing.

func (h *Handler) CreateSchedule(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	targetID := c.Params("targetId")

	// Only the target's owner may schedule scans against it.
	if _, err := h.targetSvc.Get(c.Context(), targetID, userID); err != nil {
		return respondError(c, err)
	}

	var req struct {
		CronExpr  string `json:"cron_expr"`
		Frequency string `json:"frequency"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.CronExpr == "" && req.Frequency == "" {
		return c.Status(400).JSON(fiber.Map{"error": "cron_expr or frequency is required"})
	}

	sched := GetScheduler()
	if sched == nil {
		return c.Status(503).JSON(fiber.Map{"error": "scheduler unavailable"})
	}

	schedule := &scheduler.Schedule{
		ID:        fmt.Sprintf("sch_%d", time.Now().UnixNano()),
		TargetID:  targetID,
		UserID:    userID,
		CronExpr:  req.CronExpr,
		Frequency: req.Frequency,
		Enabled:   true,
	}

	if err := sched.Schedule(schedule); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(schedule)
}

func (h *Handler) GetSchedule(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	targetID := c.Params("targetId")

	if _, err := h.targetSvc.Get(c.Context(), targetID, userID); err != nil {
		return respondError(c, err)
	}

	store := scheduler.NewPgxStorage()
	schedule, err := store.GetByTarget(targetID)
	if err != nil {
		return c.JSON(fiber.Map{"target_id": targetID, "schedule": nil})
	}
	if schedule.UserID != userID {
		return c.JSON(fiber.Map{"target_id": targetID, "schedule": nil})
	}

	return c.JSON(fiber.Map{"target_id": targetID, "schedule": schedule})
}

func (h *Handler) DeleteSchedule(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	targetID := c.Params("targetId")

	if _, err := h.targetSvc.Get(c.Context(), targetID, userID); err != nil {
		return respondError(c, err)
	}

	store := scheduler.NewPgxStorage()
	schedule, err := store.GetByTarget(targetID)
	if err != nil {
		return respondNotFound(c, "schedule")
	}
	if schedule.UserID != userID {
		return respondNotFound(c, "schedule")
	}

	if sched := GetScheduler(); sched != nil {
		if err := sched.Unschedule(schedule.ID); err != nil {
			log.Printf("[api] unschedule %s: %v", schedule.ID, err)
		}
	}
	if err := store.Delete(schedule.ID); err != nil {
		return respondError(c, err)
	}

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
	userID := middleware.GetUserID(c)

	endpoints, err := webhook.NewCustomWebhookManager().ListEndpoints(userID)
	if err != nil {
		return respondError(c, err)
	}
	if endpoints == nil {
		endpoints = []*webhook.WebhookEndpoint{}
	}
	return c.JSON(fiber.Map{"webhooks": endpoints})
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
	// Deliveries are sent server-side to this URL, so it is a request-forging
	// vector unless it is checked before being stored.
	if err := safeurl.Validate(req.URL); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	if len(req.Events) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "at least one event is required"})
	}

	endpoint := &webhook.WebhookEndpoint{
		UserID: userID,
		URL:    req.URL,
		Secret: req.Secret,
		Events: req.Events,
		Active: true,
	}

	if err := webhook.NewCustomWebhookManager().CreateEndpoint(endpoint); err != nil {
		return respondError(c, err)
	}

	return c.Status(201).JSON(endpoint)
}

func (h *Handler) DeleteWebhook(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	mgr := webhook.NewCustomWebhookManager()
	endpoint, err := mgr.GetEndpoint(id)
	if err != nil || endpoint.UserID != userID {
		return respondNotFound(c, "webhook")
	}

	if err := mgr.DeleteEndpoint(id); err != nil {
		return respondError(c, err)
	}
	return c.JSON(fiber.Map{"message": "webhook deleted"})
}

func (h *Handler) TestWebhook(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	id := c.Params("id")

	mgr := webhook.NewCustomWebhookManager()
	endpoint, err := mgr.GetEndpoint(id)
	if err != nil || endpoint.UserID != userID {
		return respondNotFound(c, "webhook")
	}

	delivery, err := mgr.TestEndpoint(endpoint)
	if err != nil {
		return c.Status(502).JSON(fiber.Map{"error": err.Error(), "status": "failed"})
	}

	return c.JSON(fiber.Map{
		"message":  "webhook test sent",
		"status":   map[bool]string{true: "success", false: "failed"}[delivery.Success],
		"delivery": delivery,
	})
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
