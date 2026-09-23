package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fireline-security/fireline-core/internal/domain"
)

func newTestObservation(t *testing.T, observedAt *time.Time, ingestedAt time.Time) domain.Observation {
	t.Helper()
	return domain.Observation{
		ID:                 uuid.New(),
		Fingerprint:        domain.Fingerprint{Value: "fp-1", Version: domain.FingerprintAlgoV1},
		Source:             domain.SourceRef{Tool: "trivy", RuleID: "CVE-2024-12345"},
		IdentityComponents: domain.IdentityComponents{"package": "openssl"},
		SeverityRaw:        "HIGH",
		RawPayload:         []byte(`{"id":"CVE-2024-12345"}`),
		ObservedAt:         observedAt,
		IngestedAt:         ingestedAt,
	}
}

func TestEngine_MatchImmediateTolerance(t *testing.T) {
	asOf := time.Now().UTC()
	observedAt := asOf.Add(-time.Hour)
	obs := newTestObservation(t, &observedAt, asOf.Add(-time.Hour))

	engine, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "high-severity", When: `severity_raw == "HIGH"`, Tolerance: "0s"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	crossings, err := engine.Evaluate([]domain.Observation{obs}, asOf)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(crossings) != 1 {
		t.Fatalf("got %d crossings, want 1", len(crossings))
	}
	c := crossings[0]
	if c.RuleID != "high-severity" || c.ObservationID != obs.ID || c.Age != time.Hour || c.Tolerance != 0 {
		t.Errorf("unexpected crossing: %+v", c)
	}
}

func TestEngine_MatchWithinTolerance_NoCrossing(t *testing.T) {
	asOf := time.Now().UTC()
	observedAt := asOf.Add(-time.Hour) // only 1h old
	obs := newTestObservation(t, &observedAt, asOf.Add(-time.Hour))

	engine, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "high-severity", When: `severity_raw == "HIGH"`, Tolerance: "168h"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	crossings, err := engine.Evaluate([]domain.Observation{obs}, asOf)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(crossings) != 0 {
		t.Fatalf("got %d crossings, want 0: %+v", len(crossings), crossings)
	}
}

func TestEngine_NilObservedAtFallsBackToIngestedAt(t *testing.T) {
	asOf := time.Now().UTC()
	ingestedAt := asOf.Add(-2 * time.Hour)
	obs := newTestObservation(t, nil, ingestedAt)

	engine, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "high-severity", When: `severity_raw == "HIGH"`, Tolerance: "0s"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	crossings, err := engine.Evaluate([]domain.Observation{obs}, asOf)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(crossings) != 1 {
		t.Fatalf("got %d crossings, want 1", len(crossings))
	}
	if crossings[0].EffectiveObservedAt != ingestedAt {
		t.Errorf("got EffectiveObservedAt %v, want %v (IngestedAt)", crossings[0].EffectiveObservedAt, ingestedAt)
	}
}

func TestNewEngine_BadCELSyntax_NamesRuleID(t *testing.T) {
	_, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "bad-rule", When: "source.tool =="},
		},
	})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "bad-rule") {
		t.Errorf("error %q does not name the offending rule id %q", err.Error(), "bad-rule")
	}
}

func TestNewEngine_InvalidFireline_FailsValidate(t *testing.T) {
	_, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "dup", When: "true"},
			{ID: "dup", When: "false"},
		},
	})
	if !errors.Is(err, domain.ErrRuleDuplicateID) {
		t.Errorf("got error %v, want %v", err, domain.ErrRuleDuplicateID)
	}
}

func TestNewEngine_NonBoolWhen(t *testing.T) {
	_, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "not-bool", When: `"a string, not a bool"`},
		},
	})
	if err == nil {
		t.Fatal("expected an error for a when expression that doesn't evaluate to bool, got nil")
	}
	if !strings.Contains(err.Error(), "not-bool") {
		t.Errorf("error %q does not name the offending rule id %q", err.Error(), "not-bool")
	}
}

func TestEngine_NoDedupByFingerprint(t *testing.T) {
	asOf := time.Now().UTC()
	observedAt := asOf.Add(-time.Hour)

	a := newTestObservation(t, &observedAt, asOf.Add(-time.Hour))
	b := newTestObservation(t, &observedAt, asOf.Add(-time.Hour))
	b.Fingerprint = a.Fingerprint // same fingerprint, distinct ID (set by newTestObservation via uuid.New())
	if a.ID == b.ID {
		t.Fatal("test setup error: expected distinct observation IDs")
	}

	engine, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "high-severity", When: `severity_raw == "HIGH"`, Tolerance: "0s"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	crossings, err := engine.Evaluate([]domain.Observation{a, b}, asOf)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(crossings) != 2 {
		t.Fatalf("got %d crossings, want 2 (no fingerprint dedup)", len(crossings))
	}
}

func TestEngine_Evaluate_DeterministicAcrossCalls(t *testing.T) {
	asOf := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // fixed historical instant, not time.Now()
	observedAt := asOf.Add(-48 * time.Hour)
	obs := newTestObservation(t, &observedAt, asOf.Add(-48*time.Hour))

	engine, err := NewEngine(domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "high-severity", When: `severity_raw == "HIGH"`, Tolerance: "24h"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	first, err := engine.Evaluate([]domain.Observation{obs}, asOf)
	if err != nil {
		t.Fatalf("Evaluate (first): %v", err)
	}
	second, err := engine.Evaluate([]domain.Observation{obs}, asOf)
	if err != nil {
		t.Fatalf("Evaluate (second): %v", err)
	}

	if !reflect.DeepEqual(first, second) {
		t.Errorf("Evaluate is not deterministic for the same (fireline, observations, asOf):\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
