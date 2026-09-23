package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fireline-security/fireline-core/internal/domain"
)

const evalTestFirelineYAML = `
name: baseline
version: "1"
rules:
  - id: high-severity
    when: severity_raw == "HIGH"
    tolerance: 0s
`

func writeFirelineFixture(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fireline.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write fireline fixture: %v", err)
	}
	return path
}

func TestEvaluateCmd_InvalidFormat(t *testing.T) {
	path := writeFirelineFixture(t, evalTestFirelineYAML)

	_, err := runCmd(t, newEvaluateCmd(), "--fireline", path, "--format", "xml")
	if err == nil {
		t.Fatal("expected an error for an invalid --format, got nil")
	}
}

func TestEvaluateCmd_InvalidLimit(t *testing.T) {
	path := writeFirelineFixture(t, evalTestFirelineYAML)

	_, err := runCmd(t, newEvaluateCmd(), "--fireline", path, "--limit", "0")
	if err == nil {
		t.Fatal("expected an error for --limit=0, got nil")
	}
}

func TestEvaluateCmd_InvalidAsOf(t *testing.T) {
	path := writeFirelineFixture(t, evalTestFirelineYAML)

	_, err := runCmd(t, newEvaluateCmd(), "--fireline", path, "--as-of", "not-a-timestamp")
	if err == nil {
		t.Fatal("expected an error for a malformed --as-of, got nil")
	}
}

// setUpEvaluateFixture migrates a fresh file-backed Turso DB and imports the
// bundled example Observation (source.tool=osv-scanner, severity_raw=HIGH,
// observed_at well over fireline.example.yaml's 24h tolerance in the past),
// so evaluate tests exercise the real storage round trip, not a mock.
func setUpEvaluateFixture(t *testing.T) {
	t.Helper()
	setUpTurso(t)
	if _, err := runCmd(t, newImportCmd()); err != nil {
		t.Fatalf("import fixture observation: %v", err)
	}
}

func TestEvaluateCmd_EndToEnd_Text(t *testing.T) {
	setUpEvaluateFixture(t)

	out, err := runCmd(t, newEvaluateCmd(), "--fireline", "testdata/fixtures/fireline.example.yaml")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !strings.Contains(out, "high-severity-osv") {
		t.Errorf("output %q does not mention the expected rule ID", out)
	}
}

func TestEvaluateCmd_EndToEnd_JSON(t *testing.T) {
	setUpEvaluateFixture(t)

	out, err := runCmd(t, newEvaluateCmd(), "--fireline", "testdata/fixtures/fireline.example.yaml", "--format", "json")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	var got []domain.Crossing
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode output: %v\noutput: %s", err, out)
	}
	if len(got) != 1 || got[0].RuleID != "high-severity-osv" {
		t.Fatalf("got %+v, want one crossing for rule high-severity-osv", got)
	}
}

func TestEvaluateCmd_Against_NewlyCaughtOnly(t *testing.T) {
	setUpEvaluateFixture(t)

	// A baseline Fireline that cannot match the bundled fixture's HIGH
	// severity, so --against should report the current Fireline's crossing
	// as newly caught (DiffNewlyCaught treats it as absent from baseline).
	baseline := writeFirelineFixture(t, `
name: baseline
version: "1"
rules:
  - id: low-severity-only
    when: severity_raw == "LOW"
    tolerance: 0s
`)

	out, err := runCmd(t, newEvaluateCmd(),
		"--fireline", "testdata/fixtures/fireline.example.yaml",
		"--against", baseline,
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evaluate --against: %v", err)
	}

	var got []domain.Crossing
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode output: %v\noutput: %s", err, out)
	}
	if len(got) != 1 || got[0].RuleID != "high-severity-osv" {
		t.Fatalf("got %+v, want the one newly-caught crossing", got)
	}
}

func TestEvaluateCmd_Against_BadPath(t *testing.T) {
	setUpEvaluateFixture(t)

	_, err := runCmd(t, newEvaluateCmd(),
		"--fireline", "testdata/fixtures/fireline.example.yaml",
		"--against", filepath.Join(t.TempDir(), "missing.yaml"),
	)
	if err == nil {
		t.Fatal("expected an error for a missing --against file, got nil")
	}
}

func TestEvaluateCmd_Against_BadCELSyntax(t *testing.T) {
	setUpEvaluateFixture(t)

	bad := writeFirelineFixture(t, `
name: baseline
version: "1"
rules:
  - id: bad-rule
    when: "severity_raw =="
    tolerance: 0s
`)

	_, err := runCmd(t, newEvaluateCmd(),
		"--fireline", "testdata/fixtures/fireline.example.yaml",
		"--against", bad,
	)
	if err == nil {
		t.Fatal("expected an error for invalid CEL syntax in --against, got nil")
	}
}

func TestEvaluateCmd_NoCrossings_TextOutput(t *testing.T) {
	setUpEvaluateFixture(t)

	// A rule that cannot match the fixture observation, so Evaluate reports
	// zero Crossings. Exercises writeCrossings' "no crossings" text-format
	// branch, distinct from the has-crossings branch every other text-format
	// test here already covers.
	noMatch := writeFirelineFixture(t, `
name: baseline
version: "1"
rules:
  - id: never-matches
    when: severity_raw == "LOW"
    tolerance: 0s
`)

	out, err := runCmd(t, newEvaluateCmd(), "--fireline", noMatch)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if strings.TrimSpace(out) != "no crossings" {
		t.Errorf("output = %q, want %q", strings.TrimSpace(out), "no crossings")
	}
}

func TestEvaluateCmd_BadStorageBackend(t *testing.T) {
	path := writeFirelineFixture(t, evalTestFirelineYAML)
	t.Setenv("FIRELINE_STORAGE_BACKEND", "mysql")

	_, err := runCmd(t, newEvaluateCmd(), "--fireline", path)
	if err == nil {
		t.Fatal("expected an error for an unknown FIRELINE_STORAGE_BACKEND, got nil")
	}
}
