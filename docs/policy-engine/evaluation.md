# Evaluation, diffing, and the CLI

## `Evaluate`'s contract

- Rules compile once per Fireline, at `NewEngine` construction time. A bad
  CEL expression fails there, naming the offending rule ID, rather than at
  evaluation time.
- `Evaluate(observations, asOf)` is a **pure function** of its inputs: no
  internal `time.Now()` call. `asOf` is resolved once, by the CLI layer.
- No fingerprint-based dedup: two Observations that share a `Fingerprint`
  but have distinct IDs can both produce a Crossing.

## Diffing (`--against`)

`DiffNewlyCaught(current, baseline []domain.Crossing)` (`internal/policy/diff.go`)
returns every `current` Crossing whose `(RuleID, ObservationID)` pair isn't
present in `baseline`. `fireline evaluate --against <file>` evaluates both
Firelines against the same Observations and `asOf`, then reports only what
the current Fireline would newly catch.

## CLI reference: `fireline evaluate`

| Flag          | Default | Meaning                                                        |
|---------------|---------|-----------------------------------------------------------------|
| `--fireline`  | none    | Path to the Fireline YAML to evaluate (required).                |
| `--against`   | none    | Path to a baseline Fireline; if set, only newly-caught Crossings are reported. |
| `--as-of`     | now     | RFC3339 timestamp to evaluate as of.                             |
| `--limit`     | `100`   | Max Observations fetched via `storage.ObservationRepository.List`. |
| `--format`    | `text`  | `text` or `json`.                                                |

`fireline evaluate` always exits `0` on success, whether or not it finds any
Crossings. Exiting non-zero when Crossings are found would make rules
"blocking by default" for CI, a policy-enforcement stance nobody's
confirmed yet, so this command doesn't take it.

## HTTP: `GET /crossings`

`fireline serve --fireline <path>` loads and compiles the Fireline once at
startup, exactly like `evaluate`: a bad Fireline or CEL syntax error fails
`serve` before it starts listening, not on the first request. Each
`GET /crossings` request then re-runs `Evaluate` live against whatever
Observations `storage.ObservationRepository.List(ctx, limit)` returns at
that moment, with `asOf = time.Now().UTC()`. There is no `--as-of` or
`--against` equivalent over HTTP: historical and diff evaluation stay
CLI-only. The response shape matches `GET /observations` exactly: a bare
JSON array, nil coerced to `[]`, the same `?limit=` (default 100) and error
conventions, and, like the rest of `internal/api`, it's read-only, with no
persisted Crossings and no auth.
