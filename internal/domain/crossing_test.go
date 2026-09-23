package domain

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCrossing_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	want := Crossing{
		RuleID:          "high-severity",
		RuleDescription: "HIGH severity findings",
		FirelineName:    "baseline",
		FirelineVersion: "1",
		ObservationID:   uuid.New(),
		Fingerprint:     Fingerprint{Value: "abc123", Version: FingerprintAlgoV1},
		Source:          SourceRef{Tool: "trivy", RuleID: "CVE-2024-12345"},
		SeverityRaw:     "HIGH",

		EffectiveObservedAt: now.Add(-48 * time.Hour),
		Age:                 48 * time.Hour,
		Tolerance:           24 * time.Hour,

		AsOf: now,
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Crossing
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got != want {
		t.Errorf("round trip mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}
}
