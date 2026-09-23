package domain

import "testing"

func TestComputeFingerprint_Deterministic(t *testing.T) {
	source := SourceRef{Tool: "trivy", RuleID: "CVE-2024-12345"}
	components := IdentityComponents{"package": "openssl", "version": "3.0.1"}

	if got1, got2 := ComputeFingerprint(source, components), ComputeFingerprint(source, components); got1 != got2 {
		t.Fatalf("fingerprint not deterministic: %+v != %+v", got1, got2)
	}
}

func TestComputeFingerprint_KeyOrderIndependent(t *testing.T) {
	source := SourceRef{Tool: "trivy", RuleID: "CVE-2024-12345"}
	a := IdentityComponents{"package": "openssl", "version": "3.0.1"}
	b := IdentityComponents{"version": "3.0.1", "package": "openssl"}

	if ComputeFingerprint(source, a) != ComputeFingerprint(source, b) {
		t.Fatal("fingerprint should not depend on map iteration order")
	}
}

func TestComputeFingerprint_DifferentValuesDiffer(t *testing.T) {
	source := SourceRef{Tool: "trivy", RuleID: "CVE-2024-12345"}
	a := IdentityComponents{"package": "openssl", "version": "3.0.1"}
	b := IdentityComponents{"package": "openssl", "version": "3.0.2"}

	if ComputeFingerprint(source, a) == ComputeFingerprint(source, b) {
		t.Fatal("different identity components should produce different fingerprints")
	}
}

func TestComputeFingerprint_ToolVersionExcluded(t *testing.T) {
	components := IdentityComponents{"package": "openssl", "version": "3.0.1"}
	a := SourceRef{Tool: "trivy", ToolVersion: "0.50.0", RuleID: "CVE-2024-12345"}
	b := SourceRef{Tool: "trivy", ToolVersion: "0.55.2", RuleID: "CVE-2024-12345"}

	if ComputeFingerprint(a, components) != ComputeFingerprint(b, components) {
		t.Fatal("fingerprint should be stable across tool version bumps for the same finding")
	}
}

func TestComputeFingerprint_Shape(t *testing.T) {
	fp := ComputeFingerprint(SourceRef{Tool: "trivy", RuleID: "x"}, IdentityComponents{"a": "b"})

	if fp.Version != FingerprintAlgoV1 {
		t.Errorf("Version = %d, want %d", fp.Version, FingerprintAlgoV1)
	}
	if len(fp.Value) != 64 {
		t.Errorf("Value has %d hex chars, want 64 (SHA-256): %q", len(fp.Value), fp.Value)
	}
}
