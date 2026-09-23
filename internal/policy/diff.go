package policy

import "github.com/fireline-security/fireline-core/internal/domain"

// crossingKey identifies "the same crossing" for diffing purposes: a Rule
// ID paired with an Observation ID.
type crossingKey struct {
	ruleID        string
	observationID string
}

// DiffNewlyCaught returns every element of current whose (RuleID,
// ObservationID) pair does not appear in baseline: what a proposed
// Fireline change would newly catch (D-03), given the same Observations and
// as-of time. Order is preserved from current.
func DiffNewlyCaught(current, baseline []domain.Crossing) []domain.Crossing {
	seen := make(map[crossingKey]struct{}, len(baseline))
	for _, c := range baseline {
		seen[crossingKey{ruleID: c.RuleID, observationID: c.ObservationID.String()}] = struct{}{}
	}

	var newlyCaught []domain.Crossing
	for _, c := range current {
		key := crossingKey{ruleID: c.RuleID, observationID: c.ObservationID.String()}
		if _, ok := seen[key]; ok {
			continue
		}
		newlyCaught = append(newlyCaught, c)
	}
	return newlyCaught
}
