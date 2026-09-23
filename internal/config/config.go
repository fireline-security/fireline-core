// Package config loads fireline-core's runtime configuration from the
// process environment.
package config

import (
	"errors"
	"fmt"
	"os"
)

// StorageBackend selects which ObservationRepository implementation the
// running process uses (D-12: storage is selected at startup).
type StorageBackend string

// The storage backends Load accepts for FIRELINE_STORAGE_BACKEND.
const (
	StorageBackendPostgres StorageBackend = "postgres"
	StorageBackendTurso    StorageBackend = "turso"
)

const (
	envStorageBackend = "FIRELINE_STORAGE_BACKEND"
	envPostgresDSN    = "FIRELINE_POSTGRES_DSN"
	envTursoDSN       = "FIRELINE_TURSO_DSN"
)

// ErrUnknownStorageBackend is returned by Load when FIRELINE_STORAGE_BACKEND
// names a backend fireline-core doesn't implement.
var ErrUnknownStorageBackend = errors.New("config: unknown storage backend")

// Config holds fireline-core's runtime configuration, as loaded by Load.
type Config struct {
	StorageBackend StorageBackend
	PostgresDSN    string
	TursoDSN       string
}

// Load reads configuration from the environment, defaulting
// FIRELINE_STORAGE_BACKEND to "postgres" when unset. It does not require the
// selected backend's DSN to be non-empty: not every command needs a live
// connection (e.g. `fireline migrate --help`), so callers that do need one
// check it explicitly and fail with a command-specific message.
func Load() (Config, error) {
	backend := StorageBackend(getenvDefault(envStorageBackend, string(StorageBackendPostgres)))
	switch backend {
	case StorageBackendPostgres, StorageBackendTurso:
	default:
		return Config{}, fmt.Errorf("%w: %q (want %q or %q)",
			ErrUnknownStorageBackend, backend, StorageBackendPostgres, StorageBackendTurso)
	}

	return Config{
		StorageBackend: backend,
		PostgresDSN:    os.Getenv(envPostgresDSN),
		TursoDSN:       os.Getenv(envTursoDSN),
	}, nil
}

func getenvDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
