package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// FingerprintAlgoV1 identifies the current fingerprint algorithm. Bumping it
// when the algorithm changes lets replay (D-08) distinguish an Observation
// whose fingerprint predates a change from one computed under the current
// rules, instead of silently reassigning identity to old data.
const FingerprintAlgoV1 = 1

// Fingerprint identifies what an Observation is about, independent of when or
// how many times it was reported.
type Fingerprint struct {
	Value   string `json:"value"`   // hex-encoded SHA-256
	Version int    `json:"version"` // which algorithm version produced Value
}

// ComputeFingerprint derives a Fingerprint from a source and the identity
// components it reported. It intentionally excludes SourceRef.ToolVersion: a
// scanner's version bumping shouldn't change the identity of the same
// underlying finding. Map key order never affects the result.
func ComputeFingerprint(source SourceRef, components IdentityComponents) Fingerprint {
	keys := make([]string, 0, len(components))
	for k := range components {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(source.Tool)
	b.WriteByte(0)
	b.WriteString(source.RuleID)
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(components[k])
	}

	sum := sha256.Sum256([]byte(b.String()))
	return Fingerprint{
		Value:   hex.EncodeToString(sum[:]),
		Version: FingerprintAlgoV1,
	}
}
