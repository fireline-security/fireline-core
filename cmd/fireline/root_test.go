package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/fireline-security/fireline-core/internal/config"
)

func TestOpenRepository_PostgresMissingDSN(t *testing.T) {
	_, err := openRepository(context.Background(), config.Config{StorageBackend: config.StorageBackendPostgres})
	if err == nil {
		t.Fatal("expected an error for missing FIRELINE_POSTGRES_DSN, got nil")
	}
}

func TestOpenRepository_TursoMissingDSN(t *testing.T) {
	_, err := openRepository(context.Background(), config.Config{StorageBackend: config.StorageBackendTurso})
	if err == nil {
		t.Fatal("expected an error for missing FIRELINE_TURSO_DSN, got nil")
	}
}

func TestOpenRepository_TursoFileBacked(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "fireline.db")
	opened, err := openRepository(context.Background(), config.Config{
		StorageBackend: config.StorageBackendTurso,
		TursoDSN:       dsn,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer opened.close()

	if err := opened.migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func TestOpenRepository_UnsupportedBackend(t *testing.T) {
	_, err := openRepository(context.Background(), config.Config{StorageBackend: "mysql"})
	if err == nil {
		t.Fatal("expected an error for an unsupported backend, got nil")
	}
}

func TestNewRootCmd_RegistersEverySubcommand(t *testing.T) {
	cmd := newRootCmd()

	want := []string{"migrate", "import", "serve", "evaluate"}
	for _, name := range want {
		if found, _, err := cmd.Find([]string{name}); err != nil || found.Name() != name {
			t.Errorf("subcommand %q not registered on root: %v", name, err)
		}
	}
}
