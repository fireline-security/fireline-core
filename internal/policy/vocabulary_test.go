package policy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/fireline-security/fireline-core/internal/domain"
)

func testObservation(t *testing.T) domain.Observation {
	t.Helper()
	obs, err := domain.NewObservation(
		domain.SourceRef{Tool: "trivy", ToolVersion: "0.50.0", RuleID: "CVE-2024-12345"},
		domain.IdentityComponents{"package": "openssl"},
		"HIGH",
		json.RawMessage(`{"id":"CVE-2024-12345"}`),
		nil,
	)
	if err != nil {
		t.Fatalf("build observation: %v", err)
	}
	return obs
}

func TestActivation_MapsObservationFields(t *testing.T) {
	obs := testObservation(t)
	vars := activation(obs)

	source, ok := vars[varSource].(map[string]string)
	if !ok {
		t.Fatalf("source is %T, want map[string]string", vars[varSource])
	}
	if source["tool"] != "trivy" || source["tool_version"] != "0.50.0" || source["rule_id"] != "CVE-2024-12345" {
		t.Errorf("got source %+v, want tool=trivy tool_version=0.50.0 rule_id=CVE-2024-12345", source)
	}

	comps, ok := vars[varIdentityComponents].(map[string]string)
	if !ok || comps["package"] != "openssl" {
		t.Errorf("got identity_components %+v, want package=openssl", vars[varIdentityComponents])
	}

	if vars[varSeverityRaw] != "HIGH" {
		t.Errorf("got severity_raw %v, want HIGH", vars[varSeverityRaw])
	}

	if vars[varIngestedAt] != obs.IngestedAt {
		t.Errorf("got ingested_at %v, want %v", vars[varIngestedAt], obs.IngestedAt)
	}
}

func TestActivation_NilObservedAt(t *testing.T) {
	obs := testObservation(t)
	obs.ObservedAt = nil

	vars := activation(obs)
	if vars[varObservedAt] != types.NullValue {
		t.Errorf("got observed_at %v, want types.NullValue", vars[varObservedAt])
	}
}

func TestActivation_SetObservedAt(t *testing.T) {
	obs := testObservation(t)
	observedAt := time.Now().UTC().Add(-time.Hour)
	obs.ObservedAt = &observedAt

	vars := activation(obs)
	if vars[varObservedAt] != observedAt {
		t.Errorf("got observed_at %v, want %v", vars[varObservedAt], observedAt)
	}
}

func TestVocabularyOptions_BuildsValidEnv(t *testing.T) {
	if _, err := cel.NewEnv(vocabularyOptions()...); err != nil {
		t.Fatalf("unexpected error building cel env: %v", err)
	}
}
