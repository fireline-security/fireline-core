package main

import (
	"github.com/spf13/cobra"

	"github.com/fireline-security/fireline-core/internal/config"
)

// newMigrateCmd applies every pending migration for the configured backend.
// It doesn't yet offer `down`/`status` subcommands the way goose itself
// does. This pass only needs to prove the migrate-insert-read round trip
// works, and adding them is a small, natural follow-up once something
// actually needs them.
func newMigrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending database migrations for the configured storage backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			opened, err := openRepository(ctx, cfg)
			if err != nil {
				return err
			}
			defer opened.close()

			if err := opened.migrate(ctx); err != nil {
				return err
			}
			cmd.Printf("migrations applied (%s backend)\n", cfg.StorageBackend)
			return nil
		},
	}
}
