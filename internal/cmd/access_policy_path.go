package cmd

import (
	"strings"

	"github.com/steipete/gogcli/internal/accessctl"
	"github.com/steipete/gogcli/internal/config"
)

func resolveAccessPolicyPath(flags *RootFlags) (string, error) {
	if flags != nil {
		if path := strings.TrimSpace(flags.AccessPolicy); path != "" {
			return config.ExpandPath(path)
		}
	}

	return accessctl.DefaultPolicyPath()
}
