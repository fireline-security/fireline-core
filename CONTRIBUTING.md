# Contributing to fireline-core

## Dev setup

Requires Go 1.26+. `docker compose up -d` gives you a local Postgres if you
want to exercise that backend; the Turso backend needs nothing beyond the Go
toolchain (it opens a local file or `:memory:`).

```sh
go mod tidy
task build
task test
```

## Adding a storage backend

`internal/storage.ObservationRepository` is the seam: implement it, then run
`internal/storage/storagetest.RunObservationRepositoryContract` against your
implementation in its own `_test.go` (see `internal/storage/memory` for the
smallest example, or `internal/storage/postgres`/`internal/storage/turso`
for one backed by a real database with migrations). That contract suite is
the actual spec: passing it is what "implements the interface correctly"
means here, not just satisfying the Go type checker.

## Code style

`task lint` runs `gofmt`, `go vet`, and `golangci-lint` (config in
`.golangci.yml`). `task fmt` applies `gofmt` and `goimports`.

## Commit messages

Describe the *why*, not just the *what*. The diff already shows what
changed.

## Code comments

`docs/` is the source of truth for design rationale, trade-offs, and scope
decisions (use AGENTS.md/README.md for a repo with nothing in `docs/` yet).
A code comment should point to it, not restate it: `// see docs/<file>.md
for why.`

A doc comment says what a function or type does, in one to three lines.
Add local *why* only for something the code can't already show: an edge
case, a library quirk. Never a design decision or scope caveat; that
belongs in docs/. Keep it plain: no "X, not Y" framing, no "deliberately,"
no hedges like "it's worth noting," and no em dashes.
