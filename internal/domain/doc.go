// Package domain holds Fireline's core types. Observation ("Smoke" in
// product language) is one immutable claim from one tool run (D-01): it is
// never updated or deleted once stored. That invariant is enforced by
// internal/storage.ObservationRepository having no Update or Delete method,
// not by anything in this package. A caller mutating their own local copy
// after Insert has no effect on the persisted row.
//
// Finding, the durable concern that links repeated Observations of the same
// underlying issue over time while keeping disagreement between sources
// visible (D-06, D-07), isn't modeled yet. Deciding when two Observations
// describe the same thing, and making a bad merge explainable and
// reversible, is real design work that belongs to a later phase ("OP 02:
// Watchtower"). Building it now, without a real correlation UI or a second
// source of Observations to correlate against, would mean guessing at
// requirements this package can't yet see.
//
// Fireline, Rule, and Crossing (fireline.go, crossing.go) are the policy
// engine's types (D-02): a versioned, explainable ruleset and the result of
// evaluating it against Observations. Crossing is not Finding: it's a
// per-Observation match-and-tolerance result with no grouping or
// deduplication by Fingerprint across Observations, not a durable,
// correlated concept. See internal/policy's package comment for how these
// compile and evaluate; the Finding guardrail above still holds.
package domain
