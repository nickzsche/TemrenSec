package handler

import (
	"strconv"

	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
	"github.com/temren/internal/queue"
	"github.com/gofiber/fiber/v2"
)

func (h *Handler) StartScan(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	targetID := c.Params("targetId")

	var req model.StartScanRequest
	_ = c.BodyParser(&req)

	scan, err := h.scanSvc.StartScan(c.Context(), userID, targetID, &req)
	if err != nil {
		status := 500
		if err.Error() == "plan limit reached" {
			status = 403
		} else if err.Error() == "target not found" {
			status = 404
		}
		return c.Status(status).JSON(fiber.Map{"error": err.Error()})
	}

	target, _ := h.scanSvc.GetScan(c.Context(), scan.ID, userID)
	_ = target

	q := GetQueue()
	if q != nil {
		targetInfo, terr := h.targetSvc.Get(c.Context(), targetID, userID)
		targetURL := ""
		if terr == nil {
			targetURL = targetInfo.URL
		}
		_ = q.EnqueueScan(c.Context(), &queue.ScanPayload{
			ScanID:   scan.ID,
			TargetID: targetID,
			URL:      targetURL,
			Config:   scan.Config,
		})
	}

	return c.Status(201).JSON(scan)
}

func (h *Handler) GetScan(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	scanID := c.Params("scanId")

	scan, err := h.scanSvc.GetScan(c.Context(), scanID, userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(scan)
}

func (h *Handler) ListScans(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	targetID := c.Params("targetId")

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	scans, err := h.scanSvc.ListScans(c.Context(), targetID, userID, limit, offset)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"scans": scans})
}

func (h *Handler) GetScanVulnerabilities(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	scanID := c.Params("scanId")

	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	severity := c.Query("severity")

	vulns, err := h.scanSvc.GetVulnerabilities(c.Context(), scanID, userID, severity, limit, offset)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"vulnerabilities": vulns})
}

func (h *Handler) GetTargetVulnerabilities(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	targetID := c.Params("targetId")

	limit, _ := strconv.Atoi(c.Query("limit", "50"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	severity := c.Query("severity")

	vulns, err := h.scanSvc.GetTargetVulnerabilities(c.Context(), targetID, userID, severity, limit, offset)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"vulnerabilities": vulns})
}

func (h *Handler) UpdateVulnStatus(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	vulnID := c.Params("vulnId")

	var body struct {
		Status string `json:"status"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	if err := h.scanSvc.UpdateVulnerabilityStatus(c.Context(), vulnID, userID, body.Status); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "vulnerability updated"})
}

func (h *Handler) GetDashboard(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	stats, err := h.scanSvc.GetDashboard(c.Context(), userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(stats)
}
