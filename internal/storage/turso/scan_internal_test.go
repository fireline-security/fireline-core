package turso

import (
	"context"
	"testing"
	"time"
)

// White-box (package turso, not turso_test) because these need to insert a
// row Repository.Insert could never produce itself: its caller-facing
// types (uuid.UUID, a Go map that always marshals) make a malformed id or
// identity_components column unreachable through the public API. Direct SQL
// against r.db is the only way to exercise scanObservation's parse-error
// branches. Both go through List, not Get: Get filters by `WHERE id = ?`,
// so a malformed id would just fail to match anything (sql.ErrNoRows)
// rather than ever reaching scanObservation.
func TestScanObservation_InvalidID(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	insertRawRow(t, repo, "not-a-uuid", "{}")

	if _, err := repo.List(ctx, 10); err == nil {
		t.Fatal("List over a row with a malformed id: expected an error, got nil")
	}
}

func TestScanObservation_InvalidIdentityComponents(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	insertRawRow(t, repo, "11111111-1111-1111-1111-111111111111", "not json")

	if _, err := repo.List(ctx, 10); err == nil {
		t.Fatal("List over a row with malformed identity_components: expected an error, got nil")
	}
}

func insertRawRow(t *testing.T, repo *Repository, id, identityComponentsJSON string) {
	t.Helper()
	now := time.Now().UTC().Format(timeLayout)
	const q = `
		INSERT INTO observations (
			id, fingerprint_value, fingerprint_version,
			source_tool, source_tool_version, source_rule_id,
			identity_components, severity_raw, raw_payload,
			observed_at, ingested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := repo.db.ExecContext(context.Background(), q,
		id, "fp", 1, "trivy", "", "CVE-2024-1",
		identityComponentsJSON, "HIGH", "{}",
		nil, now,
	); err != nil {
		t.Fatalf("insert raw row: %v", err)
	}
}
