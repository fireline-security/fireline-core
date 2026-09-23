package memory_test

import (
	"testing"

	"github.com/fireline-security/fireline-core/internal/storage"
	"github.com/fireline-security/fireline-core/internal/storage/memory"
	"github.com/fireline-security/fireline-core/internal/storage/storagetest"
)

func TestRepository_Contract(t *testing.T) {
	storagetest.RunObservationRepositoryContract(t, func(_ *testing.T) storage.ObservationRepository {
		return memory.New()
	})
}
