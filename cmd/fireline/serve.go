package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/fireline-security/fireline-core/internal/api"
	"github.com/fireline-security/fireline-core/internal/config"
	"github.com/fireline-security/fireline-core/internal/policy"
)

func newServeCmd() *cobra.Command {
	var addr, firelinePath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve fireline-core's read API over HTTP",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Load and compile the Fireline before opening the repository,
			// so a bad Fireline/CEL error fails serve at startup without
			// needing a live backend.
			f, err := policy.LoadFirelineFile(firelinePath)
			if err != nil {
				return err
			}
			engine, err := policy.NewEngine(f)
			if err != nil {
				return err
			}

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

			listener, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}

			srv := &http.Server{
				Handler:           api.NewHandler(opened.repo, engine),
				ReadHeaderTimeout: 5 * time.Second,
			}
			// Shut down gracefully when ctx is canceled: harmless in
			// production today (cobra's default Execute() context is
			// context.Background(), which never cancels, so this has no
			// effect there), but lets a caller with a cancellable context
			// (a future signal.NotifyContext wiring in main.go, or a test)
			// stop the server cleanly instead of only on a Serve error.
			go func() {
				<-ctx.Done()
				_ = srv.Shutdown(context.Background())
			}()

			cmd.Printf("listening on %s (%s backend, fireline %q v%s)\n", listener.Addr(), cfg.StorageBackend, f.Name, f.Version)
			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "address to listen on")
	cmd.Flags().StringVar(&firelinePath, "fireline", "", "path to the Fireline YAML file to evaluate GET /crossings against (required)")
	_ = cmd.MarkFlagRequired("fireline")
	return cmd
}
