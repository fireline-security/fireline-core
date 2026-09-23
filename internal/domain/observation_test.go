package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func validArgs() (SourceRef, IdentityComponents, string, json.RawMessage) {
	return SourceRef{Tool: "trivy", RuleID: "CVE-2024-12345"},
		IdentityComponents{"package": "openssl"},
		"HIGH",
		json.RawMessage(`{"id":"CVE-2024-12345"}`)
}

func TestNewObservation_Valid(t *testing.T) {
	source, components, severity, payload := validArgs()

	before := time.Now().UTC()
	obs, err := NewObservation(source, components, severity, payload, nil)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if obs.ID == uuid.Nil {
		t.Error("expected a non-nil ID")
	}
	if want := ComputeFingerprint(source, components); obs.Fingerprint != want {
		t.Errorf("Fingerprint = %+v, want %+v", obs.Fingerprint, want)
	}
	if obs.IngestedAt.Before(before) || obs.IngestedAt.After(after) {
		t.Errorf("IngestedAt %v not within [%v, %v]", obs.IngestedAt, before, after)
	}
}

func TestNewObservation_DistinctIDsSharedFingerprint(t *testing.T) {
	source, components, severity, payload := validArgs()

	a, err := NewObservation(source, components, severity, payload, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := NewObservation(source, components, severity, payload, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a.ID == b.ID {
		t.Error("two Observations of the same claim should still get distinct IDs")
	}
	if a.Fingerprint != b.Fingerprint {
		t.Error("two Observations of the same claim should share a fingerprint")
	}
}

func TestNewObservation_Invalid(t *testing.T) {
	source, components, severity, payload := validArgs()

	tests := []struct {
		name    string
		source  SourceRef
		comps   IdentityComponents
		sev     string
		payload json.RawMessage
		wantErr error
	}{
		{"empty tool", SourceRef{Tool: "", RuleID: source.RuleID}, components, severity, payload, ErrEmptySourceTool},
		{"empty rule id", SourceRef{Tool: source.Tool, RuleID: ""}, components, severity, payload, ErrEmptyRuleID},
		{"no identity components", source, IdentityComponents{}, severity, payload, ErrNoIdentity},
		{"nil identity components", source, nil, severity, payload, ErrNoIdentity},
		{"empty severity", source, components, "", payload, ErrEmptySeverityRaw},
		{"empty raw payload", source, components, severity, nil, ErrEmptyRawPayload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewObservation(tt.source, tt.comps, tt.sev, tt.payload, nil); !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}
		})
	}
}
