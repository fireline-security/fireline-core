package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fireline-security/fireline-core/internal/domain"
)

const validFirelineYAML = `
name: baseline
version: "1"
rules:
  - id: high-severity
    description: HIGH severity findings
    when: severity_raw == "HIGH"
    tolerance: 24h
`

func TestLoadFireline_Valid(t *testing.T) {
	f, err := LoadFireline([]byte(validFirelineYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := domain.Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []domain.Rule{
			{
				ID:          "high-severity",
				Description: "HIGH severity findings",
				When:        `severity_raw == "HIGH"`,
				Tolerance:   "24h",
			},
		},
	}
	if f.Name != want.Name || f.Version != want.Version || len(f.Rules) != len(want.Rules) {
		t.Fatalf("got %+v, want %+v", f, want)
	}
	if f.Rules[0] != want.Rules[0] {
		t.Errorf("got rule %+v, want %+v", f.Rules[0], want.Rules[0])
	}
}

func TestLoadFireline_InvalidYAML(t *testing.T) {
	_, err := LoadFireline([]byte("not: [valid"))
	if err == nil {
		t.Fatal("expected a decode error, got nil")
	}
}

func TestLoadFireline_FailsDomainValidate(t *testing.T) {
	_, err := LoadFireline([]byte(`
name: baseline
version: "1"
rules:
  - id: dup
    when: "true"
  - id: dup
    when: "false"
`))
	if !errors.Is(err, domain.ErrRuleDuplicateID) {
		t.Errorf("got error %v, want %v", err, domain.ErrRuleDuplicateID)
	}
}

func TestLoadFirelineFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fireline.yaml")
	if err := os.WriteFile(path, []byte(validFirelineYAML), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	f, err := LoadFirelineFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Name != "baseline" {
		t.Errorf("got name %q, want %q", f.Name, "baseline")
	}
}

func TestLoadFirelineFile_MissingFile(t *testing.T) {
	_, err := LoadFirelineFile(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
}
