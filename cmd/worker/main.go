package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/temren/internal/config"
	"github.com/temren/internal/database"
	"github.com/temren/internal/queue"
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

	// Scan counters, durations and finding totals are recorded here, not in the
	// API — they were being computed and then had nowhere to go, because this
	// process exposed no metrics endpoint. Prometheus scrapes both.
	metricsSrv := startMetricsServer()

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

	if metricsSrv != nil {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("[worker] metrics server shutdown: %v", err)
		}
	}
	return nil
}

// startMetricsServer exposes /metrics and /health on METRICS_PORT (default
// 9090). Returns nil if the listener could not be started — a scrape endpoint
// is not worth taking the worker down for.
func startMetricsServer() *http.Server {
	port := os.Getenv("METRICS_PORT")
	if port == "" {
		port = "9090"
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"temren-worker"}`))
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("[worker] metrics on :%s/metrics", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[worker] metrics server: %v", err)
		}
	}()
	return srv
}
