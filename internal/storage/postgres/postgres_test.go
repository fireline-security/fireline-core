//go:build integration

// This file needs a real PostgreSQL, so it's excluded from the default `go
// test ./...` (no build tag means it's never compiled without
// -tags=integration) and needs Docker or an equivalent running somewhere
// testcontainers-go can reach it.
package postgres_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/fireline-security/fireline-core/internal/storage"
	"github.com/fireline-security/fireline-core/internal/storage/postgres"
	"github.com/fireline-security/fireline-core/internal/storage/storagetest"
)

func TestRepository_Contract(t *testing.T) {
	ctx := context.Background()
	dsn := postgresTestDSN(t)

	repo, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(repo.Close)
	if err := repo.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// A second, test-only pool just to truncate between subtests, kept out
	// of Repository's own API, which has no reason to expose it.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open pool for test truncation: %v", err)
	}
	t.Cleanup(pool.Close)

	storagetest.RunObservationRepositoryContract(t, func(t *testing.T) storage.ObservationRepository {
		t.Helper()
		if _, err := pool.Exec(ctx, "DELETE FROM observations"); err != nil {
			t.Fatalf("truncate observations: %v", err)
		}
		return repo
	})
}

// postgresTestDSN returns POSTGRES_TEST_DSN if set (point it at `docker
// compose up -d`'s instance to reuse one running Postgres across runs);
// otherwise it starts a throwaway container via testcontainers-go.
func postgresTestDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("POSTGRES_TEST_DSN"); dsn != "" {
		return dsn
	}

	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("fireline"),
		tcpostgres.WithUsername("fireline"),
		tcpostgres.WithPassword("fireline"),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	return dsn
}
