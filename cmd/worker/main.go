package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/temren/internal/config"
	"github.com/temren/internal/database"
	"github.com/temren/internal/queue"
	"github.com/temren/internal/websocket"
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
	log.Println("[worker] database connected")

	// Live progress: the worker has no WebSocket clients of its own, so it
	// publishes scan events onto the Redis channel the API replicas subscribe
	// to. Without TEMREN_WS_REDIS the worker's events can't reach the browser
	// (separate process) — the live dashboard stays empty. Mirror api wiring.
	hub := websocket.GetHub()
	if addr := os.Getenv("TEMREN_WS_REDIS"); addr != "" {
		channel := os.Getenv("TEMREN_WS_REDIS_CHANNEL")
		if channel == "" {
			channel = "temren:ws:broadcast"
		}
		if bridge, err := websocket.NewRedisBridge(ctx, addr, channel, hub); err != nil {
			log.Printf("[worker][ws] redis bridge disabled: %v — live progress won't reach the UI", err)
		} else {
			hub.AttachBridge(bridge)
			log.Printf("[worker][ws] redis bridge attached: %s channel=%s", addr, channel)
		}
	} else {
		log.Println("[worker][ws] TEMREN_WS_REDIS unset — live progress won't reach the UI")
	}

	worker := queue.NewWorker()

	go func() {
		log.Println("[worker] starting scan worker...")
		if err := worker.Run(); err != nil {
			log.Printf("[worker] worker error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[worker] shutting down...")
	cancel()
	return nil
}
