package main

import (
	"path/filepath"
	"testing"
)

func TestMigrateCmd_Success(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "fireline.db")
	t.Setenv("FIRELINE_STORAGE_BACKEND", "turso")
	t.Setenv("FIRELINE_TURSO_DSN", dsn)

	if _, err := runCmd(t, newMigrateCmd()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func TestMigrateCmd_Idempotent(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "fireline.db")
	t.Setenv("FIRELINE_STORAGE_BACKEND", "turso")
	t.Setenv("FIRELINE_TURSO_DSN", dsn)

	if _, err := runCmd(t, newMigrateCmd()); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if _, err := runCmd(t, newMigrateCmd()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestMigrateCmd_MissingDSN(t *testing.T) {
	t.Setenv("FIRELINE_STORAGE_BACKEND", "turso")
	t.Setenv("FIRELINE_TURSO_DSN", "")

	if _, err := runCmd(t, newMigrateCmd()); err == nil {
		t.Fatal("expected an error for missing FIRELINE_TURSO_DSN, got nil")
	}
}

func TestMigrateCmd_BadStorageBackend(t *testing.T) {
	t.Setenv("FIRELINE_STORAGE_BACKEND", "mysql")

	if _, err := runCmd(t, newMigrateCmd()); err == nil {
		t.Fatal("expected an error for an unknown FIRELINE_STORAGE_BACKEND, got nil")
	}
}
