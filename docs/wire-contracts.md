# The Observation wire contract

[fireline-spec](https://github.com/fireline-security/fireline-spec) is the
canonical, versioned source of the Observation wire contract
(`schemas/v1/observation.schema.json`) that scanner adapters build against.
fireline-core and fireline-spec are separate Go modules with no dependency
between them: no `replace` directive, no relative-path assumption about
where fireline-spec lives on disk, since that would break for anyone who
hasn't cloned both repos side by side, and would break CI.

Two places in this repo hand-copy the parts of that contract they need
instead, and each is documented at the point it exists so a schema change
is easy to trace:

- `cmd/fireline/importcmd.go`'s `wireObservation` type mirrors the schema's
  fields for the one code path that reads Observation JSON today.
- `cmd/fireline/testdata/fixtures/observation.example.json` is copied
  verbatim from fireline-spec's `fixtures/v1/observation/valid/full.json`.

If fireline-spec's schema changes, update both in the same change, not
later.
