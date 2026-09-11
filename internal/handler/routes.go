package handler

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/temren/internal/config"
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
	"github.com/temren/internal/queue"
	"github.com/temren/internal/service"
	"github.com/temren/internal/websocket"
	wsfiber "github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

var scanQueue *queue.Queue
var rateLimiter *middleware.RateLimiter
var wsHub *websocket.Hub

func SetupRoutes(app *fiber.App) {
	h := NewHandler()
	scanQueue = queue.NewQueue()
	var err error
	rateLimiter, err = middleware.NewRateLimiter()
	if err != nil {
		log.Fatalf("[api] rate limiter (redis) unavailable: %v", err)
	}
	wsHub = websocket.GetHub()
	// Optional cross-instance bridge: when TEMREN_WS_REDIS is set, every
	// broadcast also fans out to peer API replicas via Redis pub/sub.
	// Without this, replicaCount > 1 silently breaks real-time progress
	// (clients see only the events from the pod they're connected to).
	if addr := os.Getenv("TEMREN_WS_REDIS"); addr != "" {
		channel := os.Getenv("TEMREN_WS_REDIS_CHANNEL")
		if channel == "" {
			channel = "temren:ws:broadcast"
		}
		if bridge, err := websocket.NewRedisBridge(context.Background(), addr, channel, wsHub); err != nil {
			log.Printf("[ws] redis bridge disabled: %v (single-pod mode)", err)
		} else {
			wsHub.AttachBridge(bridge)
			log.Printf("[ws] redis bridge attached: %s channel=%s", addr, channel)
		}
	}

	app.Use(recover.New(recover.Config{EnableStackTrace: true}))
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     config.AppConfig.FrontendURL,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}))

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "timestamp": time.Now().Format(time.RFC3339)})
	})

	app.Get("/ws", wsfiber.New(websocket.HandleWebSocket(wsHub)))

	api := app.Group("/api/v1")

	api.Post("/auth/register", rateLimiter.LimitByIP(), h.Register)
	api.Post("/auth/login", rateLimiter.LimitByIP(), h.Login)
	api.Post("/auth/refresh", h.RefreshToken)

	authed := api.Group("", middleware.AuthRequired())

	authed.Post("/auth/logout", h.Logout)
	authed.Get("/auth/me", h.GetMe)
	authed.Post("/auth/2fa/enable", h.Enable2FA)
	authed.Post("/auth/2fa/verify", h.Verify2FA)

	authed.Get("/dashboard", h.GetDashboard)

	authed.Post("/projects", h.CreateProject)
	authed.Get("/projects", h.ListProjects)
	authed.Get("/projects/:id", h.GetProject)
	authed.Put("/projects/:id", h.UpdateProject)
	authed.Delete("/projects/:id", h.DeleteProject)

	authed.Post("/targets", h.CreateTarget)
	authed.Get("/projects/:projectId/targets", h.ListTargets)
	authed.Get("/targets/:id", h.GetTarget)
	authed.Put("/targets/:id", h.UpdateTarget)
	authed.Delete("/targets/:id", h.DeleteTarget)

	authed.Post("/targets/:targetId/schedule", h.CreateSchedule)
	authed.Get("/targets/:targetId/schedule", h.GetSchedule)
	authed.Delete("/targets/:targetId/schedule", h.DeleteSchedule)

	authed.Post("/targets/:targetId/scans", h.StartScan)
	authed.Get("/targets/:targetId/scans", h.ListScans)
	authed.Get("/scans/:scanId", h.GetScan)
	authed.Get("/scans/:scanId/progress", h.GetScanProgress)
	authed.Get("/scans/:scanId/vulnerabilities", h.GetScanVulnerabilities)
	authed.Get("/targets/:targetId/vulnerabilities", h.GetTargetVulnerabilities)
	authed.Patch("/vulnerabilities/:vulnId", h.UpdateVulnStatus)

	authed.Get("/vulnerabilities/:vulnId", h.GetVulnerability)

	authed.Get("/webhooks", h.ListWebhooks)
	authed.Post("/webhooks", h.CreateWebhook)
	authed.Delete("/webhooks/:id", h.DeleteWebhook)
	authed.Post("/webhooks/:id/test", h.TestWebhook)

	authed.Post("/integrations/jira/configure", h.ConfigureJira)
	authed.Post("/integrations/jira/test", h.TestJira)
	authed.Post("/integrations/github/configure", h.ConfigureGitHub)
	authed.Post("/integrations/github/test", h.TestGitHub)

	authed.Post("/cli/scan-results", h.ReceiveCLIScan)

	_ = service.ErrForbidden
	_ = service.ErrPlanLimit
	_ = model.PlanConfig
}

func GetQueue() *queue.Queue {
	return scanQueue
}
