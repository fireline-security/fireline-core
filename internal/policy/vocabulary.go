package policy

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/fireline-security/fireline-core/internal/domain"
)

// Variable names a Fireline rule's `when` expression may reference. This is
// the entire surface CEL sees of an Observation: no raw Go struct, no
// reflection (D-02: "wrapped in a small readable domain vocabulary rather
// than exposed raw"). Age/tolerance are NOT here: that math happens in Go
// (engine.go), so `when` only ever answers "does this Observation match,"
// never "is it old enough."
const (
	varSource             = "source"
	varIdentityComponents = "identity_components"
	varSeverityRaw        = "severity_raw"
	varObservedAt         = "observed_at"
	varIngestedAt         = "ingested_at"
)

// vocabularyOptions declares every CEL variable a rule may reference.
// observed_at is declared dyn, not timestamp: Observation.ObservedAt can be
// nil, and a rule needs to see that (observed_at == null) as well as
// compare it as a timestamp when set. ingested_at is always set, so it
// stays strictly typed.
func vocabularyOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable(varSource, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(varIdentityComponents, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(varSeverityRaw, cel.StringType),
		cel.Variable(varObservedAt, cel.DynType),
		cel.Variable(varIngestedAt, cel.TimestampType),
	}
}

// activation builds the CEL variable bindings for one Observation.
func activation(obs domain.Observation) map[string]any {
	vars := map[string]any{
		varSource: map[string]string{
			"tool":         obs.Source.Tool,
			"tool_version": obs.Source.ToolVersion,
			"rule_id":      obs.Source.RuleID,
		},
		varIdentityComponents: map[string]string(obs.IdentityComponents),
		varSeverityRaw:        obs.SeverityRaw,
		varIngestedAt:         obs.IngestedAt,
	}
	if obs.ObservedAt != nil {
		vars[varObservedAt] = *obs.ObservedAt
	} else {
		vars[varObservedAt] = types.NullValue
	}
	return vars
}
