-- +goose Up
CREATE TABLE observations (
    id                   UUID PRIMARY KEY,
    fingerprint_value    TEXT NOT NULL,
    fingerprint_version  SMALLINT NOT NULL,
    source_tool          TEXT NOT NULL,
    source_tool_version  TEXT NOT NULL,
    source_rule_id       TEXT NOT NULL,
    identity_components  JSONB NOT NULL,
    severity_raw         TEXT NOT NULL,
    raw_payload          JSONB NOT NULL,
    observed_at          TIMESTAMPTZ,
    ingested_at          TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_observations_fingerprint ON observations (fingerprint_value, fingerprint_version);

-- +goose Down
DROP TABLE observations;
