package domain

import (
	"errors"
	"fmt"
	"time"
)

// Fireline is a versioned, explainable, deterministic ruleset (D-02). It is
// pure data here (no google/cel-go import), so it stays usable anywhere a
// Fireline's shape matters without pulling in a CEL runtime. Compiling and
// evaluating a Fireline's rules is internal/policy's job.
type Fireline struct {
	Name    string `json:"name"    yaml:"name"`
	Version string `json:"version" yaml:"version"`
	Rules   []Rule `json:"rules"   yaml:"rules"`
}

// Rule is one entry in a Fireline: a CEL boolean expression over a real
// Observation's fields (When), plus an age-based grace period (Tolerance)
// an Observation must clear before it counts as a Crossing. Tolerance is a
// time.ParseDuration-compatible string (e.g. "168h"); empty means "0s".
type Rule struct {
	ID          string `json:"id"                    yaml:"id"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	When        string `json:"when"                  yaml:"when"`
	Tolerance   string `json:"tolerance,omitempty"    yaml:"tolerance,omitempty"`
}

// Errors returned by Fireline.Validate and Rule.Validate.
var (
	ErrFirelineNoName    = errors.New("domain: fireline name must not be empty")
	ErrFirelineNoVersion = errors.New("domain: fireline version must not be empty")
	ErrFirelineNoRules   = errors.New("domain: fireline must have at least one rule")
	ErrRuleNoID          = errors.New("domain: rule id must not be empty")
	ErrRuleDuplicateID   = errors.New("domain: rule ids must be unique within a fireline")
	ErrRuleNoWhen        = errors.New("domain: rule when expression must not be empty")
	ErrRuleBadTolerance  = errors.New("domain: rule tolerance must be a valid, non-negative duration")
)

// Validate checks Fireline's and every Rule's structural validity. It does
// not compile any rule's When expression as CEL: that requires a CEL
// environment and belongs to internal/policy.NewEngine, which fails fast
// per-rule with the same rule ID this error would already carry.
func (f Fireline) Validate() error {
	if f.Name == "" {
		return ErrFirelineNoName
	}
	if f.Version == "" {
		return ErrFirelineNoVersion
	}
	if len(f.Rules) == 0 {
		return ErrFirelineNoRules
	}
	seen := make(map[string]struct{}, len(f.Rules))
	for _, r := range f.Rules {
		if err := r.Validate(); err != nil {
			return err
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("%w: %q", ErrRuleDuplicateID, r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return nil
}

// Validate checks one Rule's structural validity in isolation (no
// cross-rule uniqueness check; that's Fireline.Validate's job).
func (r Rule) Validate() error {
	if r.ID == "" {
		return ErrRuleNoID
	}
	if r.When == "" {
		return fmt.Errorf("%w: rule %q", ErrRuleNoWhen, r.ID)
	}
	_, err := r.ToleranceDuration()
	return err
}

// ToleranceDuration parses Tolerance as a time.Duration, defaulting to 0
// when Tolerance is empty.
func (r Rule) ToleranceDuration() (time.Duration, error) {
	if r.Tolerance == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(r.Tolerance)
	if err != nil {
		return 0, fmt.Errorf("%w: rule %q: %q: %w", ErrRuleBadTolerance, r.ID, r.Tolerance, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%w: rule %q: %q is negative", ErrRuleBadTolerance, r.ID, r.Tolerance)
	}
	return d, nil
}
