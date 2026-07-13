package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/observability"
	"github.com/aegis/aegis/internal/storage"
)

func main() {
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("audit verifier failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	cfg.ServiceName = "aegis-audit-verifier"
	logger := observability.NewLogger(cfg.ServiceName, cfg.LogLevel)

	store, err := storage.Open(context.Background(), cfg, logger)
	if err != nil {
		return err
	}
	defer store.Close()

	fmt.Println("audit verifier connected to PostgreSQL; hash-chain verification is scheduled for Milestone 7")
	return nil
}
