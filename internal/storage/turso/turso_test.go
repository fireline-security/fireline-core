package turso_test

import (
	"context"
	"testing"

	"github.com/fireline-security/fireline-core/internal/storage"
	"github.com/fireline-security/fireline-core/internal/storage/storagetest"
	"github.com/fireline-security/fireline-core/internal/storage/turso"
)

// Unlike Postgres's, this contract test carries no build tag and needs no
// external service: Turso's embedded engine opens ":memory:" directly, and
// every subtest gets a genuinely fresh database for free.
func TestRepository_Contract(t *testing.T) {
	storagetest.RunObservationRepositoryContract(t, func(t *testing.T) storage.ObservationRepository {
		t.Helper()
		ctx := context.Background()

		repo, err := turso.Open(ctx, ":memory:")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() {
			if err := repo.Close(); err != nil {
				t.Logf("close repository: %v", err)
			}
		})

		if err := repo.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		return repo
	})
}
