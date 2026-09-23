# CEL vocabulary, tolerance, and age

## CEL vocabulary

`when` (see `docs/policy-engine/schema.md`) sees exactly these variables
(`internal/policy/vocabulary.go`): no raw Go struct, no reflection. This
list is `Observation`'s own fields, and only those: `Finding`, `Asset`,
`Exception`, ownership, and exposure aren't modeled anywhere in this repo
yet (see `internal/domain/doc.go` for why `Finding`/correlation specifically
isn't built), so there's nothing else real for a rule to reference.

| Variable               | Type                    | Source                                  |
|------------------------|-------------------------|------------------------------------------|
| `source`                | `map(string, string)`   | `tool`, `tool_version`, `rule_id`        |
| `identity_components`   | `map(string, string)`   | `Observation.IdentityComponents`         |
| `severity_raw`          | `string`                | `Observation.SeverityRaw`                |
| `observed_at`           | `dyn`                   | `Observation.ObservedAt`, or CEL `null` when unset |
| `ingested_at`           | `timestamp`             | `Observation.IngestedAt` (always set)    |

`observed_at` is `dyn`, not `timestamp`, specifically because
`Observation.ObservedAt` is a nilable field: a rule can check
`observed_at == null` as well as compare it as a timestamp when it's set.

Age and tolerance are **not** in this vocabulary. `when` only ever answers
"does this Observation match"; the age/tolerance check happens in Go, not
CEL (below).

## Tolerance and age

For each Observation, `Engine.Evaluate` computes:

- `EffectiveObservedAt`: `ObservedAt` if set, else `IngestedAt`.
- `Age`: `asOf - EffectiveObservedAt`.

A Crossing fires when `when` matches **and** `Age >= Tolerance`. Tolerance is
an age-based grace period, not an occurrence count, because age is the one
axis of `Observation` this repo actually has: an occurrence-count tolerance
would mean grouping Observations by `Fingerprint`, which starts to look like
Finding-style correlation ("has this same issue been seen repeatedly"), the
same thing `internal/domain/doc.go` says isn't built here. So evaluation
stays strictly per-Observation, with no grouping or deduplication by
`Fingerprint` across Observations.
