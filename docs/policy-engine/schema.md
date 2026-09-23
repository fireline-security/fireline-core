# Fireline YAML schema

```yaml
name: baseline
version: "1"
rules:
  - id: high-severity-osv
    description: OSV-Scanner findings at HIGH severity, open more than a day
    when: source.tool == "osv-scanner" && severity_raw == "HIGH"
    tolerance: 24h
```

- `name`, `version`: required, non-empty. `version` isn't parsed as semver;
  it's just an opaque label a Fireline carries with it.
- `rules[].id`: required, unique within a Fireline.
- `rules[].when`: required, a CEL boolean expression. See
  `docs/policy-engine/vocabulary.md` for what it can reference.
- `rules[].tolerance`: optional, a `time.ParseDuration`-compatible string
  (e.g. `168h`). Empty means `0s`. See `docs/policy-engine/vocabulary.md`
  for how tolerance and age are computed.

See `cmd/fireline/testdata/fixtures/fireline.example.yaml` for a working
example that matches the bundled example Observation.
