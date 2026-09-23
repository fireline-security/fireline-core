// Package memory provides an in-memory storage.ObservationRepository, used
// for fast unit tests and as a minimal reference implementation of the
// interface.
package memory

import (
	"context"
	"encoding/json"
	"maps"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/storage"
)

// Repository is an in-memory, mutex-guarded storage.ObservationRepository.
// It is safe for concurrent use but not durable: contents are lost when the
// process exits.
type Repository struct {
	mu   sync.RWMutex
	byID map[uuid.UUID]domain.Observation
}

var _ storage.ObservationRepository = (*Repository)(nil)

// New returns an empty Repository.
func New() *Repository {
	return &Repository{byID: make(map[uuid.UUID]domain.Observation)}
}

// Insert stores obs.
func (r *Repository) Insert(_ context.Context, obs domain.Observation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[obs.ID] = cloneObservation(obs)
	return nil
}

// Get returns the Observation with the given id, or storage.ErrNotFound.
func (r *Repository) Get(_ context.Context, id uuid.UUID) (domain.Observation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	obs, ok := r.byID[id]
	if !ok {
		return domain.Observation{}, storage.ErrNotFound
	}
	return cloneObservation(obs), nil
}

// ListByFingerprint returns every Observation sharing fp, oldest first.
func (r *Repository) ListByFingerprint(_ context.Context, fp domain.Fingerprint) ([]domain.Observation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []domain.Observation
	for _, obs := range r.byID {
		if obs.Fingerprint == fp {
			out = append(out, cloneObservation(obs))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IngestedAt.Before(out[j].IngestedAt) })
	return out, nil
}

// List returns up to limit Observations, newest first.
func (r *Repository) List(_ context.Context, limit int) ([]domain.Observation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]domain.Observation, 0, len(r.byID))
	for _, obs := range r.byID {
		out = append(out, cloneObservation(obs))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IngestedAt.After(out[j].IngestedAt) })
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// cloneObservation copies obs so its map/slice/pointer fields don't alias
// the caller's or the store's memory: the same isolation a real database
// gives for free by serializing through the wire.
func cloneObservation(obs domain.Observation) domain.Observation {
	clone := obs
	clone.IdentityComponents = maps.Clone(obs.IdentityComponents)
	clone.RawPayload = append(json.RawMessage(nil), obs.RawPayload...)
	if obs.ObservedAt != nil {
		t := *obs.ObservedAt
		clone.ObservedAt = &t
	}
	return clone
}
