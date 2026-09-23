package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fireline-security/fireline-core/internal/domain"
)

func TestImportCmd_DefaultFixture(t *testing.T) {
	setUpTurso(t)

	out, err := runCmd(t, newImportCmd())
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	var got domain.Observation
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode output: %v\noutput: %s", err, out)
	}
	if got.Source.Tool != "osv-scanner" {
		t.Errorf("Source.Tool = %q, want %q", got.Source.Tool, "osv-scanner")
	}
}

func TestImportCmd_CustomFile(t *testing.T) {
	setUpTurso(t)

	path := filepath.Join(t.TempDir(), "observation.json")
	body := `{
		"schema_version": "v1",
		"source": {"tool": "trivy", "rule_id": "CVE-2024-9999"},
		"identity_components": {"package": "openssl"},
		"severity_raw": "HIGH",
		"raw_payload": {"id": "CVE-2024-9999"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := runCmd(t, newImportCmd(), "--file", path)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	var got domain.Observation
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode output: %v\noutput: %s", err, out)
	}
	if got.Source.Tool != "trivy" || got.Source.RuleID != "CVE-2024-9999" {
		t.Errorf("got Source %+v, want tool=trivy rule_id=CVE-2024-9999", got.Source)
	}
}

func TestImportCmd_MissingFile(t *testing.T) {
	setUpTurso(t)

	_, err := runCmd(t, newImportCmd(), "--file", filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected an error for a missing --file, got nil")
	}
}

func TestImportCmd_BadJSON(t *testing.T) {
	setUpTurso(t)

	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := runCmd(t, newImportCmd(), "--file", path)
	if err == nil {
		t.Fatal("expected a decode error for malformed JSON, got nil")
	}
}

func TestImportCmd_FailsDomainValidation(t *testing.T) {
	setUpTurso(t)

	path := filepath.Join(t.TempDir(), "invalid-observation.json")
	// Valid JSON, valid wireObservation shape, but source.tool is empty:
	// decodes fine, then fails domain.NewObservation's own Validate().
	body := `{
		"schema_version": "v1",
		"source": {"tool": "", "rule_id": "CVE-2024-9999"},
		"identity_components": {"package": "openssl"},
		"severity_raw": "HIGH",
		"raw_payload": {"id": "CVE-2024-9999"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := runCmd(t, newImportCmd(), "--file", path)
	if err == nil {
		t.Fatal("expected a domain validation error for an empty source.tool, got nil")
	}
}

func TestImportCmd_BadStorageBackend(t *testing.T) {
	t.Setenv("FIRELINE_STORAGE_BACKEND", "mysql")

	_, err := runCmd(t, newImportCmd())
	if err == nil {
		t.Fatal("expected an error for an unknown FIRELINE_STORAGE_BACKEND, got nil")
	}
}
