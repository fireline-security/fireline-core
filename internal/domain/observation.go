package domain

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// IdentityComponents is the free-form key/value bag a source uses to
// identify what it found. See fireline-spec's observation.schema.json for
// the wire contract this mirrors.
type IdentityComponents map[string]string

// SourceRef names the tool and rule that produced an Observation.
type SourceRef struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
	RuleID      string `json:"rule_id"`
}

// Observation is one immutable claim from one tool run ("Smoke", D-01). It's
// a plain struct: immutability is enforced by ObservationRepository never
// exposing Update or Delete, not by field visibility. Rehydrating a row
// read from storage must set Fingerprint verbatim from the stored value and
// version; recomputing it would silently reassign fingerprints if
// FingerprintAlgoV1 ever changes, breaking replay (D-08).
type Observation struct {
	ID                 uuid.UUID          `json:"id"`
	Fingerprint        Fingerprint        `json:"fingerprint"`
	Source             SourceRef          `json:"source"`
	IdentityComponents IdentityComponents `json:"identity_components"`
	SeverityRaw        string             `json:"severity_raw"`
	RawPayload         json.RawMessage    `json:"raw_payload"`
	ObservedAt         *time.Time         `json:"observed_at,omitempty"`
	IngestedAt         time.Time          `json:"ingested_at"`
}

// Errors returned by Observation.Validate.
var (
	ErrEmptySourceTool  = errors.New("domain: source tool must not be empty")
	ErrEmptyRuleID      = errors.New("domain: source rule id must not be empty")
	ErrNoIdentity       = errors.New("domain: at least one identity component is required")
	ErrEmptySeverityRaw = errors.New("domain: severity_raw must not be empty")
	ErrEmptyRawPayload  = errors.New("domain: raw_payload must not be empty")
)

// NewObservation builds a new Observation from a source's claim: it computes
// the fingerprint and assigns a fresh ID and ingestion time. Use this only
// for Observations the process is originating now, never to rehydrate a row
// already read from storage (see the Observation doc comment).
func NewObservation(
	source SourceRef,
	components IdentityComponents,
	severityRaw string,
	rawPayload json.RawMessage,
	observedAt *time.Time,
) (Observation, error) {
	obs := Observation{
		ID:                 uuid.New(),
		Fingerprint:        ComputeFingerprint(source, components),
		Source:             source,
		IdentityComponents: components,
		SeverityRaw:        severityRaw,
		RawPayload:         rawPayload,
		ObservedAt:         observedAt,
		IngestedAt:         time.Now().UTC(),
	}
	if err := obs.Validate(); err != nil {
		return Observation{}, err
	}
	return obs, nil
}

// Validate checks the structural rules fireline-spec's observation.schema.json
// also encodes for the wire contract. It does not (and cannot) check that
// Fingerprint, ID, or IngestedAt are set correctly: those are invariants of
// how an Observation was constructed, not of its field values.
func (o Observation) Validate() error {
	if o.Source.Tool == "" {
		return ErrEmptySourceTool
	}
	if o.Source.RuleID == "" {
		return ErrEmptyRuleID
	}
	if len(o.IdentityComponents) == 0 {
		return ErrNoIdentity
	}
	if o.SeverityRaw == "" {
		return ErrEmptySeverityRaw
	}
	if len(o.RawPayload) == 0 {
		return ErrEmptyRawPayload
	}
	return nil
}
