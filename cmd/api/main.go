package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/temren/internal/config"
	"github.com/temren/internal/database"
	"github.com/temren/internal/handler"
	"github.com/temren/pkg/ai"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg := config.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := database.Connect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}
	defer database.Close()
	log.Println("[api] database connected")

	if err := database.RunMigrations(ctx); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	app := fiber.New(fiber.Config{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		BodyLimit:   10 * 1024 * 1024,
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":    "ok",
			"service":   "temren-api",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	handler.SetupRoutes(app)
	handler.RegisterV2(app)

	// Optionally wire an AI provider from env. First match wins.
	switch {
	case os.Getenv("ANTHROPIC_API_KEY") != "":
		handler.ConfigureAI(ai.NewAnthropicProvider(os.Getenv("ANTHROPIC_API_KEY")))
		log.Println("[api] AI: anthropic configured")
	case os.Getenv("OPENAI_API_KEY") != "":
		handler.ConfigureAI(ai.NewOpenAIProvider(os.Getenv("OPENAI_API_KEY")))
		log.Println("[api] AI: openai configured")
	case os.Getenv("OLLAMA_MODEL") != "":
		handler.ConfigureAI(ai.NewOllamaProvider(os.Getenv("OLLAMA_MODEL")))
		log.Println("[api] AI: ollama configured")
	}

	go func() {
		addr := fmt.Sprintf(":%s", cfg.Port)
		log.Printf("[api] starting server on %s", addr)
		if err := app.Listen(addr); err != nil {
			log.Printf("[api] server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[api] shutting down...")
	return app.ShutdownWithTimeout(30 * time.Second)
}
