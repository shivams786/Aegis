package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/events"
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

	if cfg.Sidecars.NATS.Addr == "" {
		logger.Warn("nats is not configured; outbox publishing is disabled")
	} else {
		publisher := events.NATSPublisher{Addr: cfg.Sidecars.NATS.Addr, Subject: cfg.Sidecars.NATS.Subject, Timeout: 2 * time.Second}
		logger.Info("outbox publisher ready", "nats_addr", cfg.Sidecars.NATS.Addr, "nats_subject", cfg.Sidecars.NATS.Subject, "outbox_interval", cfg.Worker.OutboxInterval.String(), "outbox_batch_size", cfg.Worker.OutboxBatchSize)
		go runOutboxPublisher(ctx, logger, store, publisher, cfg.Worker.OutboxInterval, storage.OutboxDrainOptions{BatchSize: cfg.Worker.OutboxBatchSize, MaxAttempts: cfg.Worker.OutboxMaxAttempts})
	}
	logger.Info("approval expiry worker ready", "approval_expiry_interval", cfg.Worker.ApprovalExpiryInterval.String())
	go runApprovalExpirer(ctx, logger, store, cfg.Worker.ApprovalExpiryInterval)
	logger.Info("budget reservation sweeper ready", "budget_sweep_interval", cfg.Worker.BudgetSweepInterval.String(), "budget_reservation_ttl", cfg.Worker.BudgetReservationTTL.String(), "budget_sweep_batch_size", cfg.Worker.BudgetSweepBatchSize)
	go runBudgetReservationSweeper(ctx, logger, store, cfg.Worker.BudgetSweepInterval, storage.BudgetReservationSweepOptions{StaleAfter: cfg.Worker.BudgetReservationTTL, BatchSize: cfg.Worker.BudgetSweepBatchSize})
	logger.Info("reconciliation lease worker ready", "reconciliation_interval", cfg.Worker.ReconciliationInterval.String(), "reconciliation_batch_size", cfg.Worker.ReconciliationBatchSize, "reconciliation_lease_duration", cfg.Worker.ReconciliationLeaseDuration.String(), "reconciliation_retry_after", cfg.Worker.ReconciliationRetryAfter.String(), "reconciliation_lease_owner", cfg.Worker.ReconciliationLeaseOwner)
	go runReconciliationLeaser(ctx, logger, store, cfg.Worker.ReconciliationInterval, storage.ReconciliationLeaseOptions{LeaseOwner: cfg.Worker.ReconciliationLeaseOwner, LeaseDuration: cfg.Worker.ReconciliationLeaseDuration, RetryAfter: cfg.Worker.ReconciliationRetryAfter, BatchSize: cfg.Worker.ReconciliationBatchSize})
	logger.Info("policy simulation worker ready", "policy_simulation_interval", cfg.Worker.PolicySimulationInterval.String(), "policy_simulation_batch_size", cfg.Worker.PolicySimulationBatchSize, "policy_simulation_lease_duration", cfg.Worker.PolicySimulationLeaseDuration.String(), "policy_simulation_retry_after", cfg.Worker.PolicySimulationRetryAfter.String(), "policy_simulation_lease_owner", cfg.Worker.PolicySimulationLeaseOwner)
	go runPolicySimulationWorker(ctx, logger, store, cfg.Worker.PolicySimulationInterval, storage.PolicySimulationLeaseOptions{LeaseOwner: cfg.Worker.PolicySimulationLeaseOwner, LeaseDuration: cfg.Worker.PolicySimulationLeaseDuration, RetryAfter: cfg.Worker.PolicySimulationRetryAfter, BatchSize: cfg.Worker.PolicySimulationBatchSize})
	logger.Info("audit root worker ready", "audit_root_interval", cfg.Worker.AuditRootInterval.String(), "audit_root_signer", cfg.Worker.AuditRootSigner)
	runAuditRootGenerator(ctx, logger, store, cfg.Worker.AuditRootInterval, cfg.Worker.AuditRootSigner)
	logger.Info("worker stopped")
	return nil
}

func runOutboxPublisher(ctx context.Context, logger *slog.Logger, store *storage.Store, publisher events.NATSPublisher, interval time.Duration, opts storage.OutboxDrainOptions) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	drain := func() {
		result, err := store.PublishPendingOutbox(ctx, publisher, opts)
		if err != nil {
			logger.Error("outbox drain failed", "error", err)
			return
		}
		if result.Published > 0 || result.Failed > 0 || result.DeadLettered > 0 {
			logger.Info("outbox drain completed", "published", result.Published, "failed", result.Failed, "dead_lettered", result.DeadLettered)
		}
	}
	drain()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drain()
		}
	}
}

func runAuditRootGenerator(ctx context.Context, logger *slog.Logger, store *storage.Store, interval time.Duration, signer string) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	generate := func() {
		result, err := store.GenerateAuditRoots(ctx, signer)
		if err != nil {
			logger.Error("audit root generation failed", "error", err)
			return
		}
		if result.Generated > 0 {
			logger.Info("audit root generation completed", "generated", result.Generated)
		}
	}
	generate()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			generate()
		}
	}
}

func runApprovalExpirer(ctx context.Context, logger *slog.Logger, store *storage.Store, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	expire := func() {
		count, err := store.ExpirePendingApprovals(ctx)
		if err != nil {
			logger.Error("approval expiry failed", "error", err)
			return
		}
		if count > 0 {
			logger.Info("approval expiry completed", "expired", count)
		}
	}
	expire()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expire()
		}
	}
}

func runBudgetReservationSweeper(ctx context.Context, logger *slog.Logger, store *storage.Store, interval time.Duration, opts storage.BudgetReservationSweepOptions) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	sweep := func() {
		result, err := store.ReleaseStaleBudgetReservations(ctx, opts)
		if err != nil {
			logger.Error("budget reservation sweep failed", "error", err)
			return
		}
		if result.Released > 0 {
			logger.Info("budget reservation sweep completed", "released", result.Released)
		}
	}
	sweep()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

func runReconciliationLeaser(ctx context.Context, logger *slog.Logger, store *storage.Store, interval time.Duration, opts storage.ReconciliationLeaseOptions) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lease := func() {
		result, err := store.LeaseReconciliationInvocations(ctx, opts)
		if err != nil {
			logger.Error("reconciliation leasing failed", "error", err)
			return
		}
		if result.Leased > 0 {
			logger.Info("reconciliation leasing completed", "leased", result.Leased)
		}
	}
	lease()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lease()
		}
	}
}

func runPolicySimulationWorker(ctx context.Context, logger *slog.Logger, store *storage.Store, interval time.Duration, opts storage.PolicySimulationLeaseOptions) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	work := func() {
		leaseResult, err := store.LeasePolicySimulationRuns(ctx, opts)
		if err != nil {
			logger.Error("policy simulation leasing failed", "error", err)
			return
		}
		completeResult, err := store.CompleteLeasedPolicySimulationRuns(ctx, storage.PolicySimulationCompleteOptions{LeaseOwner: opts.LeaseOwner, BatchSize: opts.BatchSize})
		if err != nil {
			logger.Error("policy simulation completion failed", "error", err)
			return
		}
		if leaseResult.Leased > 0 || completeResult.Completed > 0 || completeResult.Failed > 0 {
			logger.Info("policy simulation worker completed", "leased", leaseResult.Leased, "completed", completeResult.Completed, "failed", completeResult.Failed)
		}
	}
	work()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			work()
		}
	}
}
