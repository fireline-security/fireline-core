package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/fireline-security/fireline-core/internal/config"
	"github.com/fireline-security/fireline-core/internal/domain"
)

//go:embed testdata/fixtures/observation.example.json
var exampleFixtureFS embed.FS

const exampleFixturePath = "testdata/fixtures/observation.example.json"

// wireObservation is a hand-kept mirror of fireline-spec's
// schemas/v1/observation.schema.json; see docs/wire-contracts.md. Checks
// here are Go-level structural checks, not JSON-Schema validation, since
// this reads a trusted local file, not untrusted network input.
type wireObservation struct {
	SchemaVersion      string            `json:"schema_version"`
	Source             wireSource        `json:"source"`
	IdentityComponents map[string]string `json:"identity_components"`
	SeverityRaw        string            `json:"severity_raw"`
	RawPayload         json.RawMessage   `json:"raw_payload"`
	ObservedAt         *time.Time        `json:"observed_at,omitempty"`
}

type wireSource struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
	RuleID      string `json:"rule_id"`
}

// newImportCmd inserts one Observation and reads it back, proving the
// storage round trip end to end: this is the walking skeleton's goal.
func newImportCmd() *cobra.Command {
	var filePath string

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Insert one Observation and read it back",
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := readObservationFile(filePath)
			if err != nil {
				return fmt.Errorf("read observation file: %w", err)
			}

			var wire wireObservation
			if err := json.Unmarshal(data, &wire); err != nil {
				return fmt.Errorf("decode observation: %w", err)
			}

			obs, err := domain.NewObservation(
				domain.SourceRef{Tool: wire.Source.Tool, ToolVersion: wire.Source.ToolVersion, RuleID: wire.Source.RuleID},
				domain.IdentityComponents(wire.IdentityComponents),
				wire.SeverityRaw,
				wire.RawPayload,
				wire.ObservedAt,
			)
			if err != nil {
				return fmt.Errorf("build observation: %w", err)
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

			if err := opened.repo.Insert(ctx, obs); err != nil {
				return fmt.Errorf("insert observation: %w", err)
			}

			got, err := opened.repo.Get(ctx, obs.ID)
			if err != nil {
				return fmt.Errorf("read observation back: %w", err)
			}

			out, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal result: %w", err)
			}
			cmd.Println(string(out))
			return nil
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", "path to a JSON Observation to import (defaults to a bundled example fixture)")
	return cmd
}

func readObservationFile(filePath string) ([]byte, error) {
	if filePath != "" {
		return os.ReadFile(filePath) // #nosec G304 -- filePath is a user-provided CLI flag, not external input
	}
	return exampleFixtureFS.ReadFile(exampleFixturePath)
}
