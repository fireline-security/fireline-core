// Package turso provides a Turso-backed storage.ObservationRepository. It
// uses database/sql, since turso-go only exposes a database/sql driver:
// unlike Postgres, there's no lower-level native client to use directly.
// Turso's embedded engine needs no external service: dsn may be a local
// file path or ":memory:", which is what makes this backend's contract
// tests runnable in plain `go test`, unlike Postgres's.
package turso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/tursodatabase/turso-go" // registers the "turso" database/sql driver

	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/storage"
)

const driverName = "turso"

// timeLayout is the format Observation timestamps are written as. It is
// applied explicitly on write rather than passing a time.Time argument,
// because turso-go's own time.Time handling formats with second precision
// only (time.RFC3339) and would silently truncate IngestedAt on every
// insert. On read, turso-go detects date-like TEXT columns and hands back an
// already-parsed time.Time (see scanObservation); this layout is what makes
// that round-trip lossless.
const timeLayout = time.RFC3339Nano

// Repository is a Turso-backed storage.ObservationRepository.
type Repository struct {
	db *sql.DB
}

var _ storage.ObservationRepository = (*Repository)(nil)

// Open opens dsn (a local file path, or ":memory:") and verifies it with a
// ping. Callers must call Close when done.
func Open(ctx context.Context, dsn string) (*Repository, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("turso: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("turso: ping: %w", err)
	}
	return &Repository{db: db}, nil
}

// Close releases the underlying database handle.
func (r *Repository) Close() error {
	return r.db.Close()
}

// Insert stores obs.
func (r *Repository) Insert(ctx context.Context, obs domain.Observation) error {
	components, err := json.Marshal(obs.IdentityComponents)
	if err != nil {
		return fmt.Errorf("turso: marshal identity_components: %w", err)
	}

	var observedAt any
	if obs.ObservedAt != nil {
		observedAt = obs.ObservedAt.UTC().Format(timeLayout)
	}

	const q = `
		INSERT INTO observations (
			id, fingerprint_value, fingerprint_version,
			source_tool, source_tool_version, source_rule_id,
			identity_components, severity_raw, raw_payload,
			observed_at, ingested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if _, err := r.db.ExecContext(ctx, q,
		obs.ID.String(), obs.Fingerprint.Value, obs.Fingerprint.Version,
		obs.Source.Tool, obs.Source.ToolVersion, obs.Source.RuleID,
		string(components), obs.SeverityRaw, string(obs.RawPayload),
		observedAt, obs.IngestedAt.UTC().Format(timeLayout),
	); err != nil {
		return fmt.Errorf("turso: insert observation: %w", err)
	}
	return nil
}

// Get returns the Observation with the given id, or storage.ErrNotFound.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (domain.Observation, error) {
	row := r.db.QueryRowContext(ctx, selectObservations+" WHERE id = ?", id.String())
	obs, err := scanObservation(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Observation{}, storage.ErrNotFound
		}
		return domain.Observation{}, fmt.Errorf("turso: get observation: %w", err)
	}
	return obs, nil
}

// ListByFingerprint returns every Observation sharing fp, oldest first.
func (r *Repository) ListByFingerprint(ctx context.Context, fp domain.Fingerprint) ([]domain.Observation, error) {
	rows, err := r.db.QueryContext(ctx,
		selectObservations+" WHERE fingerprint_value = ? AND fingerprint_version = ? ORDER BY ingested_at",
		fp.Value, fp.Version,
	)
	if err != nil {
		return nil, fmt.Errorf("turso: list by fingerprint: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain.Observation
	for rows.Next() {
		obs, err := scanObservation(rows)
		if err != nil {
			return nil, fmt.Errorf("turso: list by fingerprint: %w", err)
		}
		out = append(out, obs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("turso: list by fingerprint: %w", err)
	}
	return out, nil
}

// List returns up to limit Observations, newest first.
func (r *Repository) List(ctx context.Context, limit int) ([]domain.Observation, error) {
	rows, err := r.db.QueryContext(ctx,
		selectObservations+" ORDER BY ingested_at DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("turso: list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain.Observation
	for rows.Next() {
		obs, err := scanObservation(rows)
		if err != nil {
			return nil, fmt.Errorf("turso: list: %w", err)
		}
		out = append(out, obs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("turso: list: %w", err)
	}
	return out, nil
}

const selectObservations = `
	SELECT id, fingerprint_value, fingerprint_version,
		source_tool, source_tool_version, source_rule_id,
		identity_components, severity_raw, raw_payload,
		observed_at, ingested_at
	FROM observations`

// scanRow is satisfied by both *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

// scanObservation reads one row into a domain.Observation. Fingerprint is
// set verbatim from the stored value and version, never recomputed: see
// domain.Observation's doc comment for why that matters. observed_at and
// ingested_at are scanned as time.Time / sql.NullTime, not strings: turso-go
// detects any TEXT column whose value looks date-like and hands back an
// already-parsed time.Time rather than the raw text, so scanning into a
// string destination for these two columns would fail.
func scanObservation(row scanRow) (domain.Observation, error) {
	var (
		idText                                      string
		fingerprintValue                            string
		fingerprintVersion                          int
		sourceTool, sourceToolVersion, sourceRuleID string
		identityComponentsRaw                       string
		severityRaw                                 string
		rawPayload                                  string
		observedAt                                  sql.NullTime
		ingestedAt                                  time.Time
	)
	if err := row.Scan(
		&idText, &fingerprintValue, &fingerprintVersion,
		&sourceTool, &sourceToolVersion, &sourceRuleID,
		&identityComponentsRaw, &severityRaw, &rawPayload,
		&observedAt, &ingestedAt,
	); err != nil {
		return domain.Observation{}, err
	}

	id, err := uuid.Parse(idText)
	if err != nil {
		return domain.Observation{}, fmt.Errorf("parse id: %w", err)
	}
	var components domain.IdentityComponents
	if err := json.Unmarshal([]byte(identityComponentsRaw), &components); err != nil {
		return domain.Observation{}, fmt.Errorf("unmarshal identity_components: %w", err)
	}

	var observedAtPtr *time.Time
	if observedAt.Valid {
		t := observedAt.Time
		observedAtPtr = &t
	}

	return domain.Observation{
		ID:                 id,
		Fingerprint:        domain.Fingerprint{Value: fingerprintValue, Version: fingerprintVersion},
		Source:             domain.SourceRef{Tool: sourceTool, ToolVersion: sourceToolVersion, RuleID: sourceRuleID},
		IdentityComponents: components,
		SeverityRaw:        severityRaw,
		RawPayload:         json.RawMessage(rawPayload),
		ObservedAt:         observedAtPtr,
		IngestedAt:         ingestedAt,
	}, nil
}
