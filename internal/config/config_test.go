package config

import (
	"errors"
	"os"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{envStorageBackend, envPostgresDSN, envTursoDSN} {
		prev, had := os.LookupEnv(key)
		_ = os.Unsetenv(key)
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(key, prev)
			}
		})
	}
}

func TestLoad_DefaultsToPostgres(t *testing.T) {
	clearEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.StorageBackend != StorageBackendPostgres {
		t.Errorf("StorageBackend = %q, want %q", cfg.StorageBackend, StorageBackendPostgres)
	}
}

func TestLoad_ExplicitTursoBackend(t *testing.T) {
	clearEnv(t)
	t.Setenv(envStorageBackend, "turso")
	t.Setenv(envTursoDSN, "file:local.db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.StorageBackend != StorageBackendTurso {
		t.Errorf("StorageBackend = %q, want %q", cfg.StorageBackend, StorageBackendTurso)
	}
	if cfg.TursoDSN != "file:local.db" {
		t.Errorf("TursoDSN = %q, want %q", cfg.TursoDSN, "file:local.db")
	}
}

func TestLoad_UnknownBackend(t *testing.T) {
	clearEnv(t)
	t.Setenv(envStorageBackend, "mysql")

	if _, err := Load(); !errors.Is(err, ErrUnknownStorageBackend) {
		t.Errorf("got error %v, want %v", err, ErrUnknownStorageBackend)
	}
}
