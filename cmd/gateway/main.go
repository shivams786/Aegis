package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegis/aegis/internal/api"
	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/core"
	"github.com/aegis/aegis/internal/observability"
	"github.com/aegis/aegis/internal/storage"
)

func main() {
	if err := run(); err != nil {
		logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("service", "aegis-gateway")
		logger.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}

	logger := observability.NewLogger(cfg.ServiceName, cfg.LogLevel)
	logger.Info("starting gateway", "config", cfg.String())

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracer, err := observability.InitTracer(rootCtx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracer(ctx); err != nil {
			logger.Warn("otel tracer shutdown failed", "error", err)
		}
	}()

	store, err := storage.Open(rootCtx, cfg, logger)
	if err != nil {
		return err
	}
	defer store.Close()

	var validator *authn.Validator
	if cfg.Auth.Enabled {
		validator, err = authn.NewValidatorFromConfig(rootCtx, cfg.Auth, &http.Client{Timeout: 5 * time.Second})
		if err != nil {
			return err
		}
		logger.Info("jwt authentication enabled", "issuer", cfg.Auth.Issuer, "audiences", cfg.Auth.Audiences)
	} else {
		logger.Warn("jwt authentication disabled; protected routes are open for local development")
	}

	engine, err := core.NewDemoEngine()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.NewRouter(cfg, store, logger, validator, engine),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("gateway listening", "addr", cfg.HTTPAddr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-rootCtx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return err
	}
	logger.Info("gateway stopped")
	return nil
}
