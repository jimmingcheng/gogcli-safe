package accessctl

import (
	"path/filepath"

	"github.com/steipete/gogcli/internal/config"
)

// DefaultPolicyPath returns the default access policy file path.
func DefaultPolicyPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "access-policy.json"), nil
}
