# fireline-core

Fireline's single application binary: API, import jobs, migrations, policy
evaluation, and CLI, all in one Go binary that picks its storage backend at
startup. This repo is currently a walking skeleton: one domain type
(`Observation`, "Smoke" in product language), enough of a storage layer to
prove `migrate → insert → read back` against two backends, PostgreSQL and
Turso, and a v0 CEL policy engine (`internal/policy`, `fireline evaluate`)
that evaluates rules over real Observation fields. Correlation and the web
interface are later phases; see "What isn't built yet" below for what the
policy engine itself still doesn't do.

## Architecture in one page

- **`internal/domain`** holds `Observation`: one immutable claim from one
  tool run, never updated or deleted once stored. See the package doc
  comment.
- **`internal/storage`** defines `ObservationRepository`, the
  storage-agnostic interface the domain layer talks through, plus
  `storagetest`, a shared behavior spec every backend runs against.
  - **`internal/storage/memory`** is an in-memory fake, used in fast unit
    tests and as a reference implementation of the interface.
  - **`internal/storage/postgres`** is a PostgreSQL adapter using `pgx`
    directly (no ORM).
  - **`internal/storage/turso`** is a Turso adapter using `database/sql`
    (the only interface `turso-go` exposes). Turso's embedded engine needs
    no external service; the DSN can be a local file or `:memory:`, so
    this backend's contract tests run in plain `go test`, unlike Postgres's.
- **`migrations/postgres`, `migrations/turso`** hold embedded `goose` SQL
  migrations, one dialect-specific tree per backend, both `CREATE TABLE
  observations` for the same domain shape.
- **`internal/api`** is a minimal read-only HTTP API (list/get Observations)
  for [fireline-web](https://github.com/fireline-security/fireline-web)'s
  prototype UI to call. See `docs/api.md` for what it doesn't do yet.
- **`internal/policy`** compiles and evaluates a `domain.Fireline`'s CEL
  rules against Observations, reporting `domain.Crossing`s. See
  `docs/policy-engine/` for the vocabulary, tolerance semantics, and
  `Evaluate`'s replay-readiness contract.
- **`cmd/fireline`** is the CLI: `fireline migrate` applies pending
  migrations, `fireline import` inserts one Observation and reads it back,
  `fireline evaluate` compiles a Fireline YAML file and reports the
  Crossings it finds against stored Observations, `fireline serve` serves
  the read API over HTTP.

Storage backend selection is by environment variable, matching the plan for
this binary to be deployed either way without a rebuild:

| Variable                    | Values                | Default    |
|------------------------------|------------------------|------------|
| `FIRELINE_STORAGE_BACKEND`   | `postgres`, `turso`    | `postgres` |
| `FIRELINE_POSTGRES_DSN`      | e.g. `postgres://fireline:fireline@localhost:5432/fireline?sslmode=disable` | none |
| `FIRELINE_TURSO_DSN`         | a local file path, or `:memory:` | none |

## Running it

Postgres, via Docker Compose:

```sh
docker compose up -d
export FIRELINE_POSTGRES_DSN=postgres://fireline:fireline@localhost:5432/fireline?sslmode=disable
go run ./cmd/fireline migrate
go run ./cmd/fireline import
```

Turso, no external service needed at all:

```sh
export FIRELINE_STORAGE_BACKEND=turso
export FIRELINE_TURSO_DSN=fireline.db   # or :memory: for a throwaway run
go run ./cmd/fireline migrate
go run ./cmd/fireline import
```

`import` without `--file` inserts a bundled example Observation
(`cmd/fireline/testdata/fixtures/observation.example.json`) and prints it
back as read from storage: the literal proof that a round trip works.

Once something's imported,
`go run ./cmd/fireline serve --fireline <path>` (default addr `:8080`)
serves `GET /api/v1/observations`, `GET /api/v1/observations/{id}`, and
`GET /api/v1/crossings` (the given Fireline, compiled once at startup,
evaluated live against stored Observations on every request) for
[fireline-web](https://github.com/fireline-security/fireline-web)'s
prototype UI, or `curl`, to read.

### Policy evaluation

```sh
go run ./cmd/fireline evaluate \
  --fireline cmd/fireline/testdata/fixtures/fireline.example.yaml
```

See `docs/policy-engine/` for the Fireline YAML schema, the CEL vocabulary,
and the `--against`/`--as-of`/`--format` flags.

## Testing

```sh
task test              # domain + config + memory-backed contract suite, no external service
task test-integration  # + the Postgres contract suite, via testcontainers-go or POSTGRES_TEST_DSN
```

The Turso contract suite runs as part of `task test` already (it opens
`:memory:`), so there's no separate `turso` integration target.

## Relationship to fireline-spec

fireline-spec is the canonical, versioned source of the Observation wire
contract; fireline-core hand-copies the parts it needs rather than
importing fireline-spec as a Go module. See `docs/wire-contracts.md` for
where and why.

## What isn't built yet

- **Finding / correlation**: deciding when repeated Observations describe
  the same underlying issue, keeping disagreement between sources visible,
  making a bad merge explainable and reversible (D-06, D-07). Needs a real
  second source of Observations and a correlation UI to design against
  honestly; see `internal/domain/doc.go`.
- **The Fireline policy engine's later increments**: replay, "observation
  mode," Exception-decay, and database-backed Fireline storage.
  `GET /crossings` evaluates live against a file-loaded Fireline with no
  `--as-of`/`--against` support over HTTP; see
  `docs/policy-engine/evaluation.md` and `AGENTS.md`.
- **A real API**: `internal/api` is a prototype read surface for
  fireline-web to point at, not the API D-12 eventually wants; see
  `docs/api.md`.
- **Docker/Helm packaging of the application itself**: `docker-compose.yml`
  here is local-dev-only (a bare Postgres to point the CLI at), not the
  Chainguard-based application container D-12 describes.
- **`fireline migrate down` / `status`**: goose supports both; the CLI just
  doesn't expose them yet. Small, natural follow-up once something needs them.
