// Package turso embeds fireline-core's Turso migrations so the single
// application binary carries them without relying on files present at
// deploy time (D-12). go:embed cannot reach outside its own directory tree,
// which is why this lives here rather than alongside internal/storage/turso.
package turso

import "embed"

// FS holds this backend's goose migration files.
//
//go:embed *.sql
var FS embed.FS
