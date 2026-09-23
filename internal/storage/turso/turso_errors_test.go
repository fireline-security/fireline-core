package turso_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/storage/turso"
)

// These exercise turso.Repository's error-return branches by closing the
// underlying *sql.DB first: a closed database/sql.DB reliably returns "sql:
// database is closed" for any subsequent operation without ever touching
// the native driver's connection-open path, unlike an invalid DSN (which
// panics the whole process inside turso-go's Rust layer instead of
// returning a Go error, not something a test can safely trigger).
func TestRepository_OperationsOnClosedDB(t *testing.T) {
	ctx := context.Background()
	repo, err := turso.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := repo.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	obs, err := domain.NewObservation(
		domain.SourceRef{Tool: "trivy", RuleID: "CVE-2024-1"},
		domain.IdentityComponents{"package": "openssl"},
		"HIGH",
		json.RawMessage(`{}`),
		nil,
	)
	if err != nil {
		t.Fatalf("NewObservation: %v", err)
	}

	if err := repo.Insert(ctx, obs); err == nil {
		t.Error("Insert on a closed repository: expected an error, got nil")
	}
	if _, err := repo.Get(ctx, obs.ID); err == nil {
		t.Error("Get on a closed repository: expected an error, got nil")
	}
	if _, err := repo.ListByFingerprint(ctx, obs.Fingerprint); err == nil {
		t.Error("ListByFingerprint on a closed repository: expected an error, got nil")
	}
	if _, err := repo.List(ctx, 10); err == nil {
		t.Error("List on a closed repository: expected an error, got nil")
	}
}

func TestRepository_MigrateOnClosedDB(t *testing.T) {
	ctx := context.Background()
	repo, err := turso.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := repo.Migrate(ctx); err == nil {
		t.Error("Migrate on a closed repository: expected an error, got nil")
	}
}
