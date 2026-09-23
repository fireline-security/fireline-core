package policy

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/fireline-security/fireline-core/internal/domain"
)

// compiledRule pairs a domain.Rule with its once-compiled CEL program and
// pre-parsed tolerance, computed at NewEngine time.
type compiledRule struct {
	rule      domain.Rule
	program   cel.Program
	tolerance time.Duration
}

// Engine evaluates one compiled domain.Fireline against Observations.
type Engine struct {
	fireline domain.Fireline
	rules    []compiledRule
}

// NewEngine compiles every rule in f. It fails fast, naming the offending
// rule's ID, rather than deferring a bad CEL expression to evaluation time.
func NewEngine(f domain.Fireline) (*Engine, error) {
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("invalid fireline: %w", err)
	}

	env, err := cel.NewEnv(vocabularyOptions()...)
	if err != nil {
		return nil, fmt.Errorf("build cel environment: %w", err)
	}

	rules := make([]compiledRule, 0, len(f.Rules))
	for _, r := range f.Rules {
		ast, iss := env.Compile(r.When)
		if iss.Err() != nil {
			return nil, fmt.Errorf("rule %q: compile %q: %w", r.ID, r.When, iss.Err())
		}
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("rule %q: when must evaluate to bool, got %s", r.ID, ast.OutputType())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rule %q: build program: %w", r.ID, err)
		}
		tolerance, err := r.ToleranceDuration() // already validated by f.Validate(), defensive here
		if err != nil {
			return nil, err
		}
		rules = append(rules, compiledRule{rule: r, program: prg, tolerance: tolerance})
	}

	return &Engine{fireline: f, rules: rules}, nil
}

// Evaluate runs every compiled rule against every Observation, as of asOf.
// It is a pure function of its inputs (no internal time.Now() call), so
// the same (Fireline, Observations, asOf) always produces the same
// Crossings. asOf is supplied by the caller (cmd/fireline defaults it to
// time.Now().UTC(), not this package); that's what keeps historical
// replay (D-08) structurally possible later.
//
// Evaluation is strictly per-Observation: no grouping or deduplication by
// Fingerprint across Observations. That's Finding/correlation work; this
// package doesn't do it.
func (e *Engine) Evaluate(observations []domain.Observation, asOf time.Time) ([]domain.Crossing, error) {
	var crossings []domain.Crossing
	for _, obs := range observations {
		vars := activation(obs)

		effectiveObservedAt := obs.IngestedAt
		if obs.ObservedAt != nil {
			effectiveObservedAt = *obs.ObservedAt
		}
		age := asOf.Sub(effectiveObservedAt)

		for _, cr := range e.rules {
			out, _, err := cr.program.Eval(vars)
			if err != nil {
				return nil, fmt.Errorf("rule %q: evaluate observation %s: %w", cr.rule.ID, obs.ID, err)
			}
			matched, ok := out.Value().(bool)
			if !ok {
				return nil, fmt.Errorf("rule %q: when did not evaluate to a bool for observation %s", cr.rule.ID, obs.ID)
			}
			if !matched || age < cr.tolerance {
				continue
			}

			crossings = append(crossings, domain.Crossing{
				RuleID:              cr.rule.ID,
				RuleDescription:     cr.rule.Description,
				FirelineName:        e.fireline.Name,
				FirelineVersion:     e.fireline.Version,
				ObservationID:       obs.ID,
				Fingerprint:         obs.Fingerprint,
				Source:              obs.Source,
				SeverityRaw:         obs.SeverityRaw,
				EffectiveObservedAt: effectiveObservedAt,
				Age:                 age,
				Tolerance:           cr.tolerance,
				AsOf:                asOf,
			})
		}
	}
	return crossings, nil
}
