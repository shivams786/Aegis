package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aegis/aegis/internal/audit"
	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/observability"
	"github.com/aegis/aegis/internal/storage"
)

type verifierOptions struct {
	filePath     string
	tenantID     string
	expectedRoot string
	rootOutPath  string
	signer       string
}

type auditExport struct {
	TenantID string        `json:"tenant_id"`
	Events   []audit.Event `json:"events"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("audit verifier failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	if opts.filePath != "" {
		return verifyExport(opts, stdout)
	}
	return verifyDatabaseConnectivity(stdout)
}

func parseOptions(args []string) (verifierOptions, error) {
	flags := flag.NewFlagSet("audit-verifier", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := verifierOptions{}
	flags.StringVar(&opts.filePath, "file", "", "path to exported audit events JSON")
	flags.StringVar(&opts.tenantID, "tenant", "", "tenant_id to verify when the export contains more than one tenant")
	flags.StringVar(&opts.expectedRoot, "expect-root", "", "expected root hash to compare after verification")
	flags.StringVar(&opts.rootOutPath, "root-out", "", "optional path for the generated root manifest JSON")
	flags.StringVar(&opts.signer, "signer", "aegis-dev-signer", "signer identifier for generated root manifests")
	if err := flags.Parse(args); err != nil {
		return verifierOptions{}, err
	}
	if flags.NArg() > 0 {
		return verifierOptions{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return opts, nil
}

func verifyExport(opts verifierOptions, stdout io.Writer) error {
	tenantID, events, err := loadExport(opts.filePath)
	if err != nil {
		return err
	}
	if opts.tenantID != "" {
		tenantID = opts.tenantID
		events = filterTenant(events, opts.tenantID)
	}
	if tenantID == "" {
		tenantID, err = singleTenant(events)
		if err != nil {
			return err
		}
	}
	if len(events) == 0 {
		return errors.New("audit export contains no events for the requested tenant")
	}
	if err := ensureSingleTenant(events, tenantID); err != nil {
		return err
	}
	if err := audit.Verify(events); err != nil {
		return err
	}
	root, err := audit.RootManifest(tenantID, events, opts.signer, time.Now().UTC())
	if err != nil {
		return err
	}
	if opts.expectedRoot != "" && opts.expectedRoot != root.RootHash {
		return fmt.Errorf("audit root mismatch: expected %s got %s", opts.expectedRoot, root.RootHash)
	}
	if opts.rootOutPath != "" {
		if err := writeRoot(opts.rootOutPath, root); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "verified %d audit events for tenant %s\n", len(events), tenantID)
	fmt.Fprintf(stdout, "root %s %s\n", root.RootID, root.RootHash)
	return nil
}

func verifyDatabaseConnectivity(stdout io.Writer) error {
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

	fmt.Fprintln(stdout, "audit verifier connected to PostgreSQL; use -file to verify exported audit events offline")
	return nil
}

func loadExport(path string) (string, []audit.Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read audit export: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", nil, errors.New("audit export is empty")
	}
	switch trimmed[0] {
	case '[':
		var events []audit.Event
		if err := decodeJSON(trimmed, &events); err != nil {
			return "", nil, fmt.Errorf("decode audit event array: %w", err)
		}
		return "", events, nil
	case '{':
		var export auditExport
		if err := decodeJSON(trimmed, &export); err != nil {
			return "", nil, fmt.Errorf("decode audit export object: %w", err)
		}
		return export.TenantID, export.Events, nil
	default:
		return "", nil, errors.New("audit export must be a JSON array or object")
	}
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("json contains more than one value")
	}
	return nil
}

func filterTenant(events []audit.Event, tenantID string) []audit.Event {
	filtered := make([]audit.Event, 0, len(events))
	for _, event := range events {
		if event.TenantID == tenantID {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func singleTenant(events []audit.Event) (string, error) {
	if len(events) == 0 {
		return "", errors.New("audit export contains no events")
	}
	tenantID := events[0].TenantID
	if tenantID == "" {
		return "", errors.New("audit event is missing tenant_id")
	}
	for _, event := range events[1:] {
		if event.TenantID != tenantID {
			return "", errors.New("audit export contains multiple tenants; pass -tenant")
		}
	}
	return tenantID, nil
}

func ensureSingleTenant(events []audit.Event, tenantID string) error {
	for _, event := range events {
		if event.TenantID != tenantID {
			return fmt.Errorf("audit export contains event for tenant %s while verifying %s", event.TenantID, tenantID)
		}
	}
	return nil
}

func writeRoot(path string, root audit.Root) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create root manifest: %w", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(root); err != nil {
		return fmt.Errorf("write root manifest: %w", err)
	}
	return nil
}
