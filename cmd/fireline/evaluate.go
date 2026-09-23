package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/fireline-security/fireline-core/internal/config"
	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/policy"
)

const evaluateDefaultLimit = 100 // matches internal/api's defaultListLimit

// newEvaluateCmd loads a Fireline, compiles it, fetches Observations via the
// existing storage.ObservationRepository.List (no new repository method, no
// new storage layer: D-03 already wants a Fireline living in git, not a
// DB row), and reports the Crossings found. Both --fireline and --against
// are loaded and compiled before any repository is opened, so a bad Fireline
// file fails fast without needing a live backend.
func newEvaluateCmd() *cobra.Command {
	var firelinePath, againstPath, asOfRaw, format string
	var limit int

	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate a Fireline against stored Observations and report Crossings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			asOf := time.Now().UTC()
			if asOfRaw != "" {
				t, err := time.Parse(time.RFC3339, asOfRaw)
				if err != nil {
					return fmt.Errorf("parse --as-of: %w", err)
				}
				asOf = t.UTC()
			}
			if format != "text" && format != "json" {
				return fmt.Errorf("--format must be \"text\" or \"json\", got %q", format)
			}
			if limit <= 0 {
				return fmt.Errorf("--limit must be a positive integer, got %d", limit)
			}

			f, err := policy.LoadFirelineFile(firelinePath)
			if err != nil {
				return err
			}
			engine, err := policy.NewEngine(f)
			if err != nil {
				return err
			}

			var baselineEngine *policy.Engine
			if againstPath != "" {
				bf, err := policy.LoadFirelineFile(againstPath)
				if err != nil {
					return fmt.Errorf("load --against fireline: %w", err)
				}
				baselineEngine, err = policy.NewEngine(bf)
				if err != nil {
					return fmt.Errorf("compile --against fireline: %w", err)
				}
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

			observations, err := opened.repo.List(ctx, limit)
			if err != nil {
				return fmt.Errorf("list observations: %w", err)
			}

			crossings, err := engine.Evaluate(observations, asOf)
			if err != nil {
				return fmt.Errorf("evaluate fireline: %w", err)
			}

			if baselineEngine != nil {
				baselineCrossings, err := baselineEngine.Evaluate(observations, asOf)
				if err != nil {
					return fmt.Errorf("evaluate --against fireline: %w", err)
				}
				crossings = policy.DiffNewlyCaught(crossings, baselineCrossings)
			}

			return writeCrossings(cmd, format, crossings)
		},
	}

	cmd.Flags().StringVar(&firelinePath, "fireline", "", "path to the Fireline YAML file to evaluate (required)")
	cmd.Flags().StringVar(&againstPath, "against", "", "path to a baseline Fireline YAML file; if set, only Crossings not already caught by it are reported")
	cmd.Flags().StringVar(&asOfRaw, "as-of", "", "RFC3339 timestamp to evaluate as of (default: now)")
	cmd.Flags().IntVar(&limit, "limit", evaluateDefaultLimit, "maximum number of Observations to fetch and evaluate")
	cmd.Flags().StringVar(&format, "format", "text", "output format: \"text\" or \"json\"")
	_ = cmd.MarkFlagRequired("fireline")

	return cmd
}

func writeCrossings(cmd *cobra.Command, format string, crossings []domain.Crossing) error {
	if format == "json" {
		if crossings == nil {
			crossings = []domain.Crossing{} // never serialize as JSON null, same convention as internal/api
		}
		out, err := json.MarshalIndent(crossings, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal crossings: %w", err)
		}
		cmd.Println(string(out))
		return nil
	}

	if len(crossings) == 0 {
		cmd.Println("no crossings")
		return nil
	}
	for _, c := range crossings {
		cmd.Printf("%s\tobservation=%s\tfingerprint=%s\tseverity=%s\tage=%s\ttolerance=%s\n",
			c.RuleID, c.ObservationID, c.Fingerprint.Value, c.SeverityRaw, c.Age.Round(time.Second), c.Tolerance)
	}
	return nil
}
