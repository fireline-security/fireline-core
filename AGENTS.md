# AGENTS.md

## Purpose

This repo is Fireline's single application binary: API, import jobs,
migrations, policy evaluation, and CLI, all in one Go binary that picks its
storage backend at startup. It is currently a **walking skeleton**: one
domain type (`Observation`), enough of a storage layer to prove
`migrate → insert → read back` against two backends (PostgreSQL and Turso),
and a minimal read-only HTTP API (`internal/api`, served by `fireline serve`)
for [fireline-web](https://github.com/fireline-security/fireline-web)'s
prototype UI to call. Read `README.md`'s "What isn't built yet" before
assuming something is missing by accident.

## What to avoid

- **Don't add `Update` or `Delete` to `ObservationRepository`.** An
  Observation is immutable once stored; that invariant is enforced by this
  interface's shape, not by anything in `internal/domain`. A caller
  mutating their own local copy after `Insert` should have zero effect on
  the persisted row; keep it that way.
- **Don't recompute `Fingerprint` on read.** `rowToObservation` (postgres)
  and `scanObservation` (turso) set it verbatim from the stored value and
  version. Recomputing it would silently reassign fingerprints if
  `FingerprintAlgoV1` ever changes, breaking deterministic replay of
  historical data. That's why the algorithm is versioned.
- **Don't start modeling Finding or correlation logic.** Deciding when two
  Observations describe the same underlying issue, keeping disagreement
  between sources visible, making a bad merge explainable and reversible:
  this needs a real second source of Observations and a correlation UI to
  design against honestly. See `internal/domain/doc.go` for the fuller
  reasoning. If a task seems to need a `Finding` type, stop and raise it
  rather than sketching one in.
- **Don't collapse severity, exploitability, or exposure into one score.**
  Source truth (`SeverityRaw`, `RawPayload`) stays visible and untouched.
- **Don't add a storage backend without running the shared contract
  suite.** Implement `storage.ObservationRepository`, then call
  `storagetest.RunObservationRepositoryContract` against it in a `_test.go`
  file. Passing that suite, not just satisfying the Go type checker, is
  what "implements the interface" means here.
- **Don't edit an already-shipped migration file.** `migrations/postgres`
  and `migrations/turso` are goose migrations; treat every numbered file as
  append-only. A schema change is a new `0000N_*.sql` file in both trees,
  kept in sync with each other.
- **Don't add a Go module dependency on fireline-spec or fireline-adapters.**
  They're separate repos on purpose: no `replace` directive, no
  relative-path assumption. See `docs/wire-contracts.md` for where and why
  this repo hand-copies the wire contract instead.
- **Don't put business logic in `cmd/fireline`.** Commands wire flags/env to
  `internal` packages and format output; anything more belongs in
  `internal`.
- **Don't build the Chainguard application container or Helm charts here
  without checking scope first.** `docker-compose.yml` in this repo is
  local-dev-only (a bare Postgres to point the CLI at); it is explicitly
  not the application's own container. (The CEL policy engine itself was
  checked and scoped with Anders. See `internal/policy` and `fireline
  evaluate`. It's no longer on this list; growing *what* it evaluates
  or exposes still needs its own scope check, per the bullets below.)
- **Don't add Finding, Asset, Exception, ownership, or exposure fields to
  the CEL vocabulary (`internal/policy/vocabulary.go`) or to
  `domain.Rule`/`domain.Fireline`'s schema until those domain types
  exist.** See `docs/policy-engine/vocabulary.md` for why the vocabulary is
  limited to real `Observation` fields.
- **Don't add a database-backed Fireline-definition store without checking
  scope first.** A Fireline is loaded straight from a YAML file path today
  (see `docs/policy-engine/schema.md`); growing persistence for it is a
  later increment, not something to sketch in ahead of it. (`GET /crossings`
  itself was checked and scoped with Anders. See `internal/api` and
  `fireline serve --fireline`. It's no longer on this list; it evaluates
  live per request against the file-loaded Fireline, with no persistence and
  no historical/`--as-of` support over HTTP. That still needs its own scope
  check.)
- **Don't build replay (D-08), Exception-decay (D-10), or "observation
  mode" (D-09) yet.** `internal/policy.Engine.Evaluate` is shaped to keep
  these reachable later (see `docs/policy-engine/evaluation.md`), but
  building them is real, separate design work; don't sketch any in just
  because the evaluation function happens to make them structurally
  reachable.
- **The UI itself lives in fireline-web, not here; don't pull it in.** This
  repo's job is `internal/api`, a backend for that UI to call, not the UI's
  code. If a task seems to need Solid/TypeScript/frontend build tooling in
  this repo, stop and raise it rather than adding it.
- **Don't grow `internal/api` write endpoints, auth, or CORS headers without
  checking scope first.** It's a read-only prototype surface on purpose.
  See `docs/api.md` for what's not built yet.
- **Don't make `internal/api`'s handlers depend on a concrete backend
  (`internal/storage/postgres`/`turso`).** `api.NewHandler` takes a
  `storage.ObservationRepository`, which is exactly what makes `api_test.go`
  runnable against the in-memory fake. Keep it that way so this package
  stays testable in this sandbox without a live database.

## What to ensure

- New code that touches storage passes `storagetest.RunObservationRepositoryContract`
  on every backend it's relevant to, not just the one you're focused on.
- Integration tests needing a live database are gated behind
  `-tags=integration` (see `postgres_test.go`) so `task test` never needs
  Docker; Turso's contract test has no such gate since `:memory:` needs
  nothing external.
- `task lint` (`gofmt`, `go vet`, `golangci-lint`) and `task test` are clean
  before a change is done.
- Storage-backend selection stays driven by `internal/config` (the
  `FIRELINE_STORAGE_BACKEND`/`FIRELINE_POSTGRES_DSN`/`FIRELINE_TURSO_DSN`
  env vars); don't hardcode a backend choice elsewhere.
- If a schema field changes in fireline-spec, update this repo's hand-copies
  (`wireObservation`, the example fixture) in the same change, not later.
- `internal/policy.Engine.Evaluate` stays a pure function of (Fireline,
  `[]Observation`, `asOf time.Time`): no internal `time.Now()` call
  anywhere in the evaluation path. `asOf` is resolved once, in
  `cmd/fireline`'s CLI layer, and passed in; historical replay (D-08)
  depends on this staying true later, not on a rewrite to make it true
  then.
