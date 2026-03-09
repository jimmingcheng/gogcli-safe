package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steipete/gogcli/internal/accessctl"
	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
)

// AccessPolicyCmd is the top-level access-policy management command.
type AccessPolicyCmd struct {
	Show   AccessPolicyShowCmd   `cmd:"" help:"Show current access policy"`
	Set    AccessPolicySetCmd    `cmd:"" help:"Set access policy (overwrites existing)"`
	Add    AccessPolicyAddCmd    `cmd:"" help:"Add address or domain to existing policy"`
	Remove AccessPolicyRemoveCmd `cmd:"" help:"Remove address or domain from existing policy"`
	Test   AccessPolicyTestCmd   `cmd:"" name:"test" help:"Test whether an email is allowed"`
}

type AccessPolicyShowCmd struct{}

func (c *AccessPolicyShowCmd) Run(ctx context.Context) error {
	u := ui.FromContext(ctx)
	path, err := accessctl.DefaultPolicyPath()
	if err != nil {
		return err
	}

	policy, err := accessctl.LoadPolicy(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if outfmt.IsJSON(ctx) {
				return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{"policy": nil, "path": path})
			}
			u.Err().Println("No access policy configured")
			return nil
		}
		return err
	}

	if outfmt.IsJSON(ctx) {
		addresses := sortedKeys(policy.Addresses)
		domains := sortedKeys(policy.Domains)
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
			"path": path,
			"policy": map[string]any{
				"mode":      string(policy.Mode),
				"addresses": addresses,
				"domains":   domains,
			},
		})
	}

	u.Out().Printf("Path: %s", path)
	u.Out().Printf("Mode: %s", policy.Mode)
	u.Out().Println("")
	u.Out().Println("Addresses:")
	for addr := range policy.Addresses {
		u.Out().Printf("  %s", addr)
	}
	u.Out().Println("")
	u.Out().Println("Domains:")
	for domain := range policy.Domains {
		u.Out().Printf("  %s", domain)
	}
	return nil
}

type AccessPolicySetCmd struct {
	Mode      string `name:"mode" required:"" help:"Policy mode: allow or deny"`
	Addresses string `name:"addresses" help:"Comma-separated email addresses"`
	Domains   string `name:"domains" help:"Comma-separated domain names"`
}

func (c *AccessPolicySetCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	mode := accessctl.Mode(strings.ToLower(strings.TrimSpace(c.Mode)))
	if mode != accessctl.ModeAllow && mode != accessctl.ModeDeny {
		return usage("mode must be \"allow\" or \"deny\"")
	}

	addresses := make(map[string]bool)
	for _, addr := range splitCSV(c.Addresses) {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if addr != "" {
			addresses[addr] = true
		}
	}

	domains := make(map[string]bool)
	for _, d := range splitCSV(c.Domains) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			domains[d] = true
		}
	}

	policy := &accessctl.Policy{
		Mode:      mode,
		Addresses: addresses,
		Domains:   domains,
	}

	if err := dryRunExit(ctx, flags, "config.access-policy.set", map[string]any{
		"mode":      string(mode),
		"addresses": sortedKeys(addresses),
		"domains":   sortedKeys(domains),
	}); err != nil {
		return err
	}

	if err := writePolicy(policy); err != nil {
		return err
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
			"saved": true,
			"mode":  string(mode),
		})
	}

	u.Out().Printf("Access policy set: mode=%s, %d addresses, %d domains", mode, len(addresses), len(domains))
	return nil
}

type AccessPolicyAddCmd struct {
	Address string `name:"address" help:"Email address to add"`
	Domain  string `name:"domain" help:"Domain to add"`
}

func (c *AccessPolicyAddCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)
	addr := strings.ToLower(strings.TrimSpace(c.Address))
	domain := strings.ToLower(strings.TrimSpace(c.Domain))
	if addr == "" && domain == "" {
		return usage("specify --address or --domain")
	}

	policy, err := loadOrCreatePolicy()
	if err != nil {
		return err
	}

	if addr != "" {
		policy.Addresses[addr] = true
	}
	if domain != "" {
		policy.Domains[domain] = true
	}

	if err := dryRunExit(ctx, flags, "config.access-policy.add", map[string]any{
		"address": addr,
		"domain":  domain,
	}); err != nil {
		return err
	}

	if err := writePolicy(policy); err != nil {
		return err
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{"added": true})
	}

	if addr != "" {
		u.Out().Printf("Added address: %s", addr)
	}
	if domain != "" {
		u.Out().Printf("Added domain: %s", domain)
	}
	return nil
}

type AccessPolicyRemoveCmd struct {
	Address string `name:"address" help:"Email address to remove"`
	Domain  string `name:"domain" help:"Domain to remove"`
}

func (c *AccessPolicyRemoveCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)
	addr := strings.ToLower(strings.TrimSpace(c.Address))
	domain := strings.ToLower(strings.TrimSpace(c.Domain))
	if addr == "" && domain == "" {
		return usage("specify --address or --domain")
	}

	policy, err := loadOrCreatePolicy()
	if err != nil {
		return err
	}

	if addr != "" {
		delete(policy.Addresses, addr)
	}
	if domain != "" {
		delete(policy.Domains, domain)
	}

	if err := dryRunExit(ctx, flags, "config.access-policy.remove", map[string]any{
		"address": addr,
		"domain":  domain,
	}); err != nil {
		return err
	}

	if err := writePolicy(policy); err != nil {
		return err
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{"removed": true})
	}

	if addr != "" {
		u.Out().Printf("Removed address: %s", addr)
	}
	if domain != "" {
		u.Out().Printf("Removed domain: %s", domain)
	}
	return nil
}

type AccessPolicyTestCmd struct {
	Email string `arg:"" name:"email" help:"Email address to test"`
}

func (c *AccessPolicyTestCmd) Run(ctx context.Context) error {
	u := ui.FromContext(ctx)
	email := strings.TrimSpace(c.Email)
	if email == "" {
		return usage("email is required")
	}

	path, err := accessctl.DefaultPolicyPath()
	if err != nil {
		return err
	}

	policy, err := accessctl.LoadPolicy(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if outfmt.IsJSON(ctx) {
				return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
					"email":   email,
					"allowed": true,
					"reason":  "no policy configured",
				})
			}
			u.Out().Printf("%s: allowed (no policy configured)", email)
			return nil
		}
		return err
	}

	allowed := policy.IsAllowed(email)
	reason := fmt.Sprintf("%s mode", policy.Mode)

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
			"email":   email,
			"allowed": allowed,
			"mode":    string(policy.Mode),
			"reason":  reason,
		})
	}

	if allowed {
		u.Out().Printf("%s: allowed (%s)", email, reason)
	} else {
		u.Out().Printf("%s: BLOCKED (%s)", email, reason)
	}
	return nil
}

func loadOrCreatePolicy() (*accessctl.Policy, error) {
	path, err := accessctl.DefaultPolicyPath()
	if err != nil {
		return nil, err
	}
	policy, err := accessctl.LoadPolicy(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &accessctl.Policy{
				Mode:      accessctl.ModeAllow,
				Addresses: make(map[string]bool),
				Domains:   make(map[string]bool),
			}, nil
		}
		return nil, err
	}
	return policy, nil
}

func writePolicy(policy *accessctl.Policy) error {
	path, err := accessctl.DefaultPolicyPath()
	if err != nil {
		return err
	}

	// Ensure config directory exists
	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
		return fmt.Errorf("ensure config dir: %w", mkdirErr)
	}

	data, err := accessctl.MarshalPolicy(policy)
	if err != nil {
		return err
	}

	// MarshalPolicy already returns indented JSON; just add trailing newline.
	data = append(data, '\n')

	return os.WriteFile(path, data, 0o600)
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
