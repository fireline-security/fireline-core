package main

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// setUpTurso points FIRELINE_STORAGE_BACKEND/FIRELINE_TURSO_DSN at a fresh,
// file-backed Turso database under t.TempDir() and applies migrations to it,
// so command tests can exercise the real storage round trip without Docker
// or any external service (matching how internal/storage/turso's own
// contract test runs ungated). File-backed, not ":memory:", so separate
// command executions within one test (migrate, then import, then evaluate)
// see the same data.
func setUpTurso(t *testing.T) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "fireline.db")
	t.Setenv("FIRELINE_STORAGE_BACKEND", "turso")
	t.Setenv("FIRELINE_TURSO_DSN", dsn)

	if _, err := runCmd(t, newMigrateCmd()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// runCmd executes cmd with args, capturing its combined stdout/stderr.
func runCmd(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

var _ = io.Discard // kept available for callers that want to ignore output explicitly
