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
		if err.Error() == "target not found" {
			return respondNotFound(c, "target")
		}
		return respondError(c, err)
	}

	// A scan row with nothing behind it is worse than a failed request: the UI
	// shows it queued forever. Resolve the target and enqueue before reporting
	// success, and surface any failure instead of discarding it.
	targetInfo, err := h.targetSvc.Get(c.Context(), targetID, userID)
	if err != nil {
		h.failScan(c, scan.ID, "could not resolve target URL")
		return respondError(c, err)
	}

	q := GetQueue()
	if q == nil {
		h.failScan(c, scan.ID, "scan queue unavailable")
		return c.Status(503).JSON(fiber.Map{"error": "scan queue unavailable, try again shortly"})
	}

	if err := q.EnqueueScan(c.Context(), &queue.ScanPayload{
		ScanID:   scan.ID,
		TargetID: targetID,
		URL:      targetInfo.URL,
		Config:   scan.Config,
	}); err != nil {
		h.failScan(c, scan.ID, "could not queue scan: "+err.Error())
		return c.Status(503).JSON(fiber.Map{"error": "could not queue scan, try again shortly"})
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
		return respondError(c, err)
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
		return respondError(c, err)
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
		return respondError(c, err)
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
		return respondError(c, err)
	}

	return c.JSON(fiber.Map{"message": "vulnerability updated"})
}

func (h *Handler) GetDashboard(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	stats, err := h.scanSvc.GetDashboard(c.Context(), userID)
	if err != nil {
		return respondError(c, err)
	}

	return c.JSON(stats)
}
