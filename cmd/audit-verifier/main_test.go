package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/audit"
)

func TestRunVerifiesAuditExportArray(t *testing.T) {
	events := testAuditEvents(t)
	root, err := audit.RootManifest("tenant_acme", events, "test-signer", time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("root manifest: %v", err)
	}
	exportPath := writeJSON(t, "events.json", events)
	rootPath := filepath.Join(t.TempDir(), "root.json")

	var out bytes.Buffer
	err = run([]string{
		"-file", exportPath,
		"-tenant", "tenant_acme",
		"-expect-root", root.RootHash,
		"-root-out", rootPath,
		"-signer", "test-signer",
	}, &out)
	if err != nil {
		t.Fatalf("verify export: %v", err)
	}
	if !strings.Contains(out.String(), "verified 2 audit events for tenant tenant_acme") {
		t.Fatalf("unexpected output: %s", out.String())
	}
	if _, err := os.Stat(rootPath); err != nil {
		t.Fatalf("expected root manifest file: %v", err)
	}
}

func TestRunRejectsTamperedAuditExport(t *testing.T) {
	events := testAuditEvents(t)
	events[0].RedactedPayload["status"] = "tampered"
	exportPath := writeJSON(t, "tampered.json", auditExport{TenantID: "tenant_acme", Events: events})

	var out bytes.Buffer
	err := run([]string{"-file", exportPath}, &out)
	if err == nil {
		t.Fatal("expected tampered export to fail")
	}
	if !strings.Contains(err.Error(), "audit event hash mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testAuditEvents(t *testing.T) []audit.Event {
	t.Helper()
	chain := audit.NewChain()
	if _, err := chain.Append("tenant_acme", "inv_1", "INVOCATION_RECEIVED", "agent", "agent_1", "OK", map[string]any{"status": "received"}); err != nil {
		t.Fatalf("append first event: %v", err)
	}
	if _, err := chain.Append("tenant_acme", "inv_1", "INVOCATION_SUCCEEDED", "agent", "agent_1", "OK", map[string]any{"amount_minor": 50000}); err != nil {
		t.Fatalf("append second event: %v", err)
	}
	return chain.Events("tenant_acme")
}

func writeJSON(t *testing.T, name string, value any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create export: %v", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		t.Fatalf("write export: %v", err)
	}
	return path
}
