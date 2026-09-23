// Package policy compiles and evaluates Firelines (D-02): versioned,
// explainable, deterministic rulesets expressed as reviewable YAML that
// lives in git (D-03), not a database row. A Fireline's rules are CEL
// boolean expressions (google/cel-go) over a small, explicit vocabulary
// derived from domain.Observation (see vocabulary.go), plus an age-based
// tolerance applied in Go, not CEL (see engine.go).
//
// internal/domain intentionally does not import cel-go: Fireline, Rule, and
// Crossing are plain data there. This package is where compilation and
// evaluation actually happen.
//
// Evaluate is a pure function of (Fireline, []Observation, as-of time): it
// never reads the wall clock itself, so replaying an old Fireline version
// against historical Observations (D-08) stays structurally possible
// later. Replay itself, "observation mode" (D-09), and Exception-decay
// (D-10) aren't built yet.
package policy
