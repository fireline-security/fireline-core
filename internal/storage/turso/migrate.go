package turso

import (
	"context"
	"fmt"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"

	tursomigrations "github.com/fireline-security/fireline-core/migrations/turso"
)

// Migrate applies every pending migration using goose's native Turso
// dialect (SQLite-compatible SQL) against Repository's own *sql.DB.
func (r *Repository) Migrate(ctx context.Context) error {
	provider, err := goose.NewProvider(database.DialectTurso, r.db, tursomigrations.FS)
	if err != nil {
		return fmt.Errorf("turso: new migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("turso: apply migrations: %w", err)
	}
	return nil
}
