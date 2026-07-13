package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/observability"
	"github.com/aegis/aegis/internal/storage"
)

func main() {
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("worker stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	cfg.ServiceName = "aegis-worker"
	logger := observability.NewLogger(cfg.ServiceName, cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := storage.Open(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer store.Close()

	logger.Info("worker ready; durable background jobs will be enabled in later milestones")
	<-ctx.Done()
	logger.Info("worker stopped")
	return nil
}
