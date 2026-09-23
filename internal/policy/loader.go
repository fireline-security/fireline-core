package policy

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/fireline-security/fireline-core/internal/domain"
)

// LoadFirelineFile reads and validates a Fireline from a YAML file at path.
// It does not compile any rule's CEL expression; NewEngine does that, so a
// syntax error names the offending rule ID there instead of surfacing here
// as a generic decode error.
func LoadFirelineFile(path string) (domain.Fireline, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a user-provided CLI flag, not external input
	if err != nil {
		return domain.Fireline{}, fmt.Errorf("read fireline file %q: %w", path, err)
	}
	return LoadFireline(data)
}

// LoadFireline decodes YAML bytes into a domain.Fireline and validates its
// structural shape, but not its CEL expressions.
func LoadFireline(data []byte) (domain.Fireline, error) {
	var f domain.Fireline
	if err := yaml.Unmarshal(data, &f); err != nil {
		return domain.Fireline{}, fmt.Errorf("decode fireline yaml: %w", err)
	}
	if err := f.Validate(); err != nil {
		return domain.Fireline{}, fmt.Errorf("invalid fireline: %w", err)
	}
	return f, nil
}
