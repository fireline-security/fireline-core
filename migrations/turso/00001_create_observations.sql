-- +goose Up
CREATE TABLE observations (
    id                   TEXT PRIMARY KEY,
    fingerprint_value    TEXT NOT NULL,
    fingerprint_version  INTEGER NOT NULL,
    source_tool          TEXT NOT NULL,
    source_tool_version  TEXT NOT NULL,
    source_rule_id       TEXT NOT NULL,
    identity_components  TEXT NOT NULL,
    severity_raw         TEXT NOT NULL,
    raw_payload          TEXT NOT NULL,
    observed_at          TEXT,
    ingested_at          TEXT NOT NULL
);

CREATE INDEX idx_observations_fingerprint ON observations (fingerprint_value, fingerprint_version);

-- +goose Down
DROP TABLE observations;
