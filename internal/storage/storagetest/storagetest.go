// Package storagetest holds the shared behavior spec every
// storage.ObservationRepository implementation must satisfy. It lives
// outside package storage, in a regular (non-test) file, specifically so
// other packages' tests (internal/storage/memory, internal/storage/postgres,
// internal/storage/turso) can import and run it; a _test.go file cannot be
// imported across packages.
package storagetest

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/storage"
)

// NewRepository builds a fresh, empty ObservationRepository for one subtest.
// Implementations should back it with isolated storage (a new in-memory map,
// a dedicated schema, or an equivalent) so subtests don't observe each
// other's writes.
type NewRepository func(t *testing.T) storage.ObservationRepository

// RunObservationRepositoryContract runs the shared behavior spec against any
// ObservationRepository implementation.
func RunObservationRepositoryContract(t *testing.T, newRepo NewRepository) {
	t.Helper()

	t.Run("insert then get round trip", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		obs := mustObservation(t, "CVE-2024-1", map[string]string{"package": "openssl"})
		if err := repo.Insert(ctx, obs); err != nil {
			t.Fatalf("Insert: %v", err)
		}

		got, err := repo.Get(ctx, obs.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		assertObservationsEqual(t, obs, got)
	})

	t.Run("insert then get round trip preserves a set ObservedAt", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		obs := mustObservation(t, "CVE-2024-1", map[string]string{"package": "openssl"})
		observedAt := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
		obs.ObservedAt = &observedAt
		if err := repo.Insert(ctx, obs); err != nil {
			t.Fatalf("Insert: %v", err)
		}

		got, err := repo.Get(ctx, obs.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ObservedAt == nil {
			t.Fatal("ObservedAt = nil, want it set")
		}
		if !got.ObservedAt.Equal(observedAt) {
			t.Errorf("ObservedAt = %v, want %v", got.ObservedAt, observedAt)
		}
	})

	t.Run("get on missing id returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		_, err := repo.Get(ctx, uuid.New())
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("got error %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("insert does not mutate the caller's value", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		obs := mustObservation(t, "CVE-2024-1", map[string]string{"package": "openssl"})
		wantComponents := maps.Clone(obs.IdentityComponents)
		wantPayload := append(json.RawMessage(nil), obs.RawPayload...)

		if err := repo.Insert(ctx, obs); err != nil {
			t.Fatalf("Insert: %v", err)
		}

		if !maps.Equal(obs.IdentityComponents, wantComponents) {
			t.Errorf("IdentityComponents mutated by Insert: got %v, want %v", obs.IdentityComponents, wantComponents)
		}
		if string(obs.RawPayload) != string(wantPayload) {
			t.Errorf("RawPayload mutated by Insert: got %s, want %s", obs.RawPayload, wantPayload)
		}
	})

	t.Run("list by fingerprint returns every observation sharing it, ordered by ingestion", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		components := map[string]string{"package": "openssl"}
		first := mustObservation(t, "CVE-2024-1", components)
		time.Sleep(2 * time.Millisecond) // guarantee a strictly later IngestedAt than first
		second := mustObservation(t, "CVE-2024-1", components)
		other := mustObservation(t, "CVE-2024-2", components) // different rule id -> different fingerprint

		for _, o := range []domain.Observation{first, second, other} {
			if err := repo.Insert(ctx, o); err != nil {
				t.Fatalf("Insert: %v", err)
			}
		}

		got, err := repo.ListByFingerprint(ctx, first.Fingerprint)
		if err != nil {
			t.Fatalf("ListByFingerprint: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d observations, want 2: %+v", len(got), got)
		}
		if got[0].ID != first.ID || got[1].ID != second.ID {
			t.Fatalf("got IDs [%s, %s] in that order, want [%s, %s]", got[0].ID, got[1].ID, first.ID, second.ID)
		}
	})

	t.Run("list returns observations newest first, capped at limit", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		oldest := mustObservation(t, "CVE-2024-1", map[string]string{"package": "a"})
		if err := repo.Insert(ctx, oldest); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
		newest := mustObservation(t, "CVE-2024-2", map[string]string{"package": "b"})
		if err := repo.Insert(ctx, newest); err != nil {
			t.Fatalf("Insert: %v", err)
		}

		got, err := repo.List(ctx, 10)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d observations, want 2: %+v", len(got), got)
		}
		if got[0].ID != newest.ID || got[1].ID != oldest.ID {
			t.Fatalf("got IDs [%s, %s] in that order, want newest-first [%s, %s]", got[0].ID, got[1].ID, newest.ID, oldest.ID)
		}

		limited, err := repo.List(ctx, 1)
		if err != nil {
			t.Fatalf("List with limit 1: %v", err)
		}
		if len(limited) != 1 || limited[0].ID != newest.ID {
			t.Fatalf("List with limit 1 = %+v, want just the newest observation", limited)
		}
	})
}

func mustObservation(t *testing.T, ruleID string, components map[string]string) domain.Observation {
	t.Helper()
	obs, err := domain.NewObservation(
		domain.SourceRef{Tool: "trivy", RuleID: ruleID},
		domain.IdentityComponents(components),
		"HIGH",
		json.RawMessage(`{"id":"`+ruleID+`"}`),
		nil,
	)
	if err != nil {
		t.Fatalf("NewObservation: %v", err)
	}
	return obs
}

func assertObservationsEqual(t *testing.T, want, got domain.Observation) {
	t.Helper()
	if want.ID != got.ID {
		t.Errorf("ID = %v, want %v", got.ID, want.ID)
	}
	if want.Fingerprint != got.Fingerprint {
		t.Errorf("Fingerprint = %+v, want %+v", got.Fingerprint, want.Fingerprint)
	}
	if want.Source != got.Source {
		t.Errorf("Source = %+v, want %+v", got.Source, want.Source)
	}
	if !maps.Equal(want.IdentityComponents, got.IdentityComponents) {
		t.Errorf("IdentityComponents = %v, want %v", got.IdentityComponents, want.IdentityComponents)
	}
	if want.SeverityRaw != got.SeverityRaw {
		t.Errorf("SeverityRaw = %q, want %q", got.SeverityRaw, want.SeverityRaw)
	}
	if string(want.RawPayload) != string(got.RawPayload) {
		t.Errorf("RawPayload = %s, want %s", got.RawPayload, want.RawPayload)
	}
	if !want.IngestedAt.Equal(got.IngestedAt) {
		t.Errorf("IngestedAt = %v, want %v", got.IngestedAt, want.IngestedAt)
	}
}
