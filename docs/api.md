# The read API

`internal/api` (`NewHandler`, served by `fireline serve`) is a minimal,
read-only HTTP API: enough for a prototype UI to list and inspect
Observations and Crossings.

- `GET /api/v1/observations`: list, newest first.
- `GET /api/v1/observations/{id}`: one Observation.
- `GET /api/v1/crossings`: see `docs/policy-engine/evaluation.md` for what
  this evaluates and how.

It's a prototype surface, not the real API (D-12) eventually wants:

- No write endpoints. `fireline import` is still the only way to insert an
  Observation.
- No auth.
- No CORS handling. A dev frontend (fireline-web) proxies `/api` through to
  this server instead, via its own vite config, so neither side needs CORS
  headers.
- No pagination beyond a flat `limit` query parameter.
