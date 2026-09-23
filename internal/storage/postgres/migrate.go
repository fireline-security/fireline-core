package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"

	pgmigrations "github.com/fireline-security/fireline-core/migrations/postgres"
)

// Migrate applies every pending migration. It bridges Repository's
// pgxpool.Pool to the *sql.DB goose's Provider needs via pgx/v5/stdlib,
// reusing the pool's own connections rather than opening a second set;
// closing the bridged *sql.DB does not close the underlying pool.
func (r *Repository) Migrate(ctx context.Context) error {
	db := stdlib.OpenDBFromPool(r.pool)
	defer func() { _ = db.Close() }()

	provider, err := goose.NewProvider(database.DialectPostgres, db, pgmigrations.FS)
	if err != nil {
		return fmt.Errorf("postgres: new migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("postgres: apply migrations: %w", err)
	}
	return nil
}
