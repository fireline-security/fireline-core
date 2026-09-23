package domain

import (
	"time"

	"github.com/google/uuid"
)

// Crossing is the record of one Rule matching one Observation and clearing
// its tolerance: a Fireline's explainable output (D-04). Fields beyond an
// identifier are either copied verbatim from the Observation or a derived
// timestamp/duration explaining why this Crossing fired now; nothing here
// collapses severity or evidence into a score.
type Crossing struct {
	RuleID          string `json:"rule_id"`
	RuleDescription string `json:"rule_description,omitempty"`

	FirelineName    string `json:"fireline_name"`
	FirelineVersion string `json:"fireline_version"`

	ObservationID uuid.UUID   `json:"observation_id"`
	Fingerprint   Fingerprint `json:"fingerprint"`
	Source        SourceRef   `json:"source"`
	SeverityRaw   string      `json:"severity_raw"`

	// EffectiveObservedAt is ObservedAt, or IngestedAt when ObservedAt is
	// nil. Age is AsOf minus EffectiveObservedAt; Tolerance is the Rule's
	// own grace period. Both are carried so a report shows margin, not just
	// a boolean.
	EffectiveObservedAt time.Time     `json:"effective_observed_at"`
	Age                 time.Duration `json:"age"`
	Tolerance           time.Duration `json:"tolerance"`

	// AsOf is the evaluation time this Crossing was computed against,
	// carried explicitly: this is what makes a serialized Crossing
	// meaningful under replay (D-08) later.
	AsOf time.Time `json:"as_of"`
}
