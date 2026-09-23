// Package postgres provides a PostgreSQL-backed storage.ObservationRepository
// using pgx directly against a connection pool. No ORM.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/storage"
)

// Repository is a PostgreSQL-backed storage.ObservationRepository.
type Repository struct {
	pool *pgxpool.Pool
}

var _ storage.ObservationRepository = (*Repository)(nil)

// Open creates a connection pool for dsn, verifies it with a ping, and
// returns a Repository backed by it. Callers must call Close when done.
func Open(ctx context.Context, dsn string) (*Repository, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Repository{pool: pool}, nil
}

// Close releases the underlying connection pool.
func (r *Repository) Close() {
	r.pool.Close()
}

// Insert stores obs.
func (r *Repository) Insert(ctx context.Context, obs domain.Observation) error {
	components, err := json.Marshal(obs.IdentityComponents)
	if err != nil {
		return fmt.Errorf("postgres: marshal identity_components: %w", err)
	}

	const q = `
		INSERT INTO observations (
			id, fingerprint_value, fingerprint_version,
			source_tool, source_tool_version, source_rule_id,
			identity_components, severity_raw, raw_payload,
			observed_at, ingested_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	if _, err := r.pool.Exec(ctx, q,
		obs.ID.String(), obs.Fingerprint.Value, obs.Fingerprint.Version,
		obs.Source.Tool, obs.Source.ToolVersion, obs.Source.RuleID,
		components, obs.SeverityRaw, obs.RawPayload,
		obs.ObservedAt, obs.IngestedAt,
	); err != nil {
		return fmt.Errorf("postgres: insert observation: %w", err)
	}
	return nil
}

// Get returns the Observation with the given id, or storage.ErrNotFound.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (domain.Observation, error) {
	rows, err := r.pool.Query(ctx, selectObservations+" WHERE id = $1", id.String())
	if err != nil {
		return domain.Observation{}, fmt.Errorf("postgres: get observation: %w", err)
	}
	obs, err := pgx.CollectExactlyOneRow(rows, rowToObservation)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Observation{}, storage.ErrNotFound
		}
		return domain.Observation{}, fmt.Errorf("postgres: get observation: %w", err)
	}
	return obs, nil
}

// ListByFingerprint returns every Observation sharing fp, oldest first.
func (r *Repository) ListByFingerprint(ctx context.Context, fp domain.Fingerprint) ([]domain.Observation, error) {
	rows, err := r.pool.Query(ctx,
		selectObservations+" WHERE fingerprint_value = $1 AND fingerprint_version = $2 ORDER BY ingested_at",
		fp.Value, fp.Version,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: list by fingerprint: %w", err)
	}
	obs, err := pgx.CollectRows(rows, rowToObservation)
	if err != nil {
		return nil, fmt.Errorf("postgres: list by fingerprint: %w", err)
	}
	return obs, nil
}

// List returns up to limit Observations, newest first.
func (r *Repository) List(ctx context.Context, limit int) ([]domain.Observation, error) {
	rows, err := r.pool.Query(ctx,
		selectObservations+" ORDER BY ingested_at DESC LIMIT $1",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: list: %w", err)
	}
	obs, err := pgx.CollectRows(rows, rowToObservation)
	if err != nil {
		return nil, fmt.Errorf("postgres: list: %w", err)
	}
	return obs, nil
}

const selectObservations = `
	SELECT id, fingerprint_value, fingerprint_version,
		source_tool, source_tool_version, source_rule_id,
		identity_components, severity_raw, raw_payload,
		observed_at, ingested_at
	FROM observations`

// rowToObservation scans one row into a domain.Observation. Fingerprint is
// set verbatim from the stored value and version, never recomputed: see
// domain.Observation's doc comment for why that matters. id is read as text
// and parsed explicitly rather than scanned straight into uuid.UUID, so this
// adapter doesn't depend on exactly how pgx's reflection-based codec
// fallback handles a named [16]byte array type.
func rowToObservation(row pgx.CollectableRow) (domain.Observation, error) {
	var (
		idText                                      string
		fingerprintValue                            string
		fingerprintVersion                          int
		sourceTool, sourceToolVersion, sourceRuleID string
		identityComponentsRaw                       []byte
		severityRaw                                 string
		rawPayload                                  []byte
		observedAt                                  *time.Time
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
	if err := json.Unmarshal(identityComponentsRaw, &components); err != nil {
		return domain.Observation{}, fmt.Errorf("unmarshal identity_components: %w", err)
	}

	return domain.Observation{
		ID:                 id,
		Fingerprint:        domain.Fingerprint{Value: fingerprintValue, Version: fingerprintVersion},
		Source:             domain.SourceRef{Tool: sourceTool, ToolVersion: sourceToolVersion, RuleID: sourceRuleID},
		IdentityComponents: components,
		SeverityRaw:        severityRaw,
		RawPayload:         rawPayload,
		ObservedAt:         observedAt,
		IngestedAt:         ingestedAt,
	}, nil
}
