package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/fireline-security/fireline-core/internal/config"
	"github.com/fireline-security/fireline-core/internal/storage"
	"github.com/fireline-security/fireline-core/internal/storage/postgres"
	"github.com/fireline-security/fireline-core/internal/storage/turso"
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "fireline",
		Short:         "Fireline: define the line, stop the spread.",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	cmd.AddCommand(newMigrateCmd())
	cmd.AddCommand(newImportCmd())
	cmd.AddCommand(newServeCmd())
	cmd.AddCommand(newEvaluateCmd())
	return cmd
}

// openRepositoryResult pairs an opened storage.ObservationRepository with the
// operations that are backend-specific rather than part of the interface
// itself: closing the underlying connection, and applying migrations. Close
// isn't on storage.ObservationRepository because not every conceivable
// implementation needs one (the in-memory fake used in tests doesn't); the
// same goes for migrations, which are an operational concern, not a
// storage-agnostic one.
type openRepositoryResult struct {
	repo    storage.ObservationRepository
	close   func()
	migrate func(ctx context.Context) error
}

func openRepository(ctx context.Context, cfg config.Config) (openRepositoryResult, error) {
	switch cfg.StorageBackend {
	case config.StorageBackendPostgres:
		if cfg.PostgresDSN == "" {
			return openRepositoryResult{}, fmt.Errorf("FIRELINE_POSTGRES_DSN is required for the postgres backend")
		}
		repo, err := postgres.Open(ctx, cfg.PostgresDSN)
		if err != nil {
			return openRepositoryResult{}, err
		}
		return openRepositoryResult{repo: repo, close: repo.Close, migrate: repo.Migrate}, nil

	case config.StorageBackendTurso:
		if cfg.TursoDSN == "" {
			return openRepositoryResult{}, fmt.Errorf("FIRELINE_TURSO_DSN is required for the turso backend")
		}
		repo, err := turso.Open(ctx, cfg.TursoDSN)
		if err != nil {
			return openRepositoryResult{}, err
		}
		return openRepositoryResult{repo: repo, close: func() { _ = repo.Close() }, migrate: repo.Migrate}, nil

	default:
		return openRepositoryResult{}, fmt.Errorf("unsupported storage backend %q", cfg.StorageBackend)
	}
}
