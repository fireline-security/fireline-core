// Package storage defines the storage-agnostic seam Fireline core's domain
// layer talks through. ObservationRepository is implemented once per backend
// (internal/storage/postgres, internal/storage/turso, and internal/storage/memory
// for tests); internal/storage/storagetest holds the shared behavior spec every
// implementation must satisfy, so adding a new backend is "implement the
// interface, run the shared suite" rather than a bespoke test plan per backend.
package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/fireline-security/fireline-core/internal/domain"
)

// ErrNotFound is returned by Get when no Observation with the given ID exists.
var ErrNotFound = errors.New("storage: observation not found")

// ObservationRepository stores and retrieves Observations. It has no Update
// or Delete method by design: Observations are immutable once stored (D-01).
// Insert does not reject a fingerprint it has already seen; the same
// underlying issue being re-observed by repeated tool runs is expected.
// Deciding when repeated Observations describe the same Finding is
// correlation work this repository doesn't know about.
type ObservationRepository interface {
	Insert(ctx context.Context, obs domain.Observation) error
	Get(ctx context.Context, id uuid.UUID) (domain.Observation, error)
	ListByFingerprint(ctx context.Context, fp domain.Fingerprint) ([]domain.Observation, error)
	// List returns up to limit Observations, newest (by IngestedAt) first.
	// It has no offset/cursor yet; real pagination is future work once
	// something other than a single prototype page needs it.
	List(ctx context.Context, limit int) ([]domain.Observation, error)
}
