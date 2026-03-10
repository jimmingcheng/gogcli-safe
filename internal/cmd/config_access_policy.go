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
	Set    AccessPolicySetCmd    `cmd:"" help:"Set access policy (overwrites existing for account)"`
	Add    AccessPolicyAddCmd    `cmd:"" help:"Add address or domain to existing policy"`
	Remove AccessPolicyRemoveCmd `cmd:"" help:"Remove address or domain from existing policy"`
	Test   AccessPolicyTestCmd   `cmd:"" name:"test" help:"Test whether an email is allowed"`
}

type AccessPolicyShowCmd struct {
	Account string `name:"policy-account" help:"Show policy for a specific account (omit to show all)"`
}

func (c *AccessPolicyShowCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)
	path, err := resolveAccessPolicyPath(flags)
	if err != nil {
		return err
	}

	pf, err := accessctl.LoadPolicyFile(path)
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

	account := strings.ToLower(strings.TrimSpace(c.Account))

	// Show a single account
	if account != "" {
		policy := pf.ForAccount(account)
		if policy == nil {
			if outfmt.IsJSON(ctx) {
				return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
					"path":    path,
					"account": account,
					"policy":  nil,
				})
			}
			u.Out().Printf("No policy for account %s (unrestricted)", account)
			return nil
		}

		if outfmt.IsJSON(ctx) {
			return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
				"path":    path,
				"account": account,
				"policy": map[string]any{
					"mode":      string(policy.Mode),
					"addresses": sortedKeys(policy.Addresses),
					"domains":   sortedKeys(policy.Domains),
				},
			})
		}

		u.Out().Printf("Path: %s", path)
		u.Out().Printf("Account: %s", account)
		u.Out().Printf("Mode: %s", policy.Mode)
		u.Out().Println("")
		u.Out().Println("Addresses:")
		for _, addr := range sortedKeys(policy.Addresses) {
			u.Out().Printf("  %s", addr)
		}
		u.Out().Println("")
		u.Out().Println("Domains:")
		for _, domain := range sortedKeys(policy.Domains) {
			u.Out().Printf("  %s", domain)
		}
		return nil
	}

	// Show all accounts
	if outfmt.IsJSON(ctx) {
		accounts := make(map[string]any, len(pf.Accounts))
		for acct, p := range pf.Accounts {
			accounts[acct] = map[string]any{
				"mode":      string(p.Mode),
				"addresses": sortedKeys(p.Addresses),
				"domains":   sortedKeys(p.Domains),
			}
		}
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
			"path":     path,
			"accounts": accounts,
		})
	}

	u.Out().Printf("Path: %s", path)
	if len(pf.Accounts) == 0 {
		u.Out().Println("No accounts configured")
		return nil
	}

	for _, acct := range sortedKeys(accountNames(pf)) {
		p := pf.Accounts[acct]
		u.Out().Println("")
		u.Out().Printf("Account: %s", acct)
		u.Out().Printf("  Mode: %s", p.Mode)
		if len(p.Addresses) > 0 {
			u.Out().Printf("  Addresses: %s", strings.Join(sortedKeys(p.Addresses), ", "))
		}
		if len(p.Domains) > 0 {
			u.Out().Printf("  Domains: %s", strings.Join(sortedKeys(p.Domains), ", "))
		}
	}
	return nil
}

type AccessPolicySetCmd struct {
	Account   string `name:"policy-account" required:"" help:"Account email to set policy for"`
	Mode      string `name:"mode" required:"" help:"Policy mode: allow or deny"`
	Addresses string `name:"addresses" help:"Comma-separated email addresses"`
	Domains   string `name:"domains" help:"Comma-separated domain names"`
}

func (c *AccessPolicySetCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	account := strings.ToLower(strings.TrimSpace(c.Account))
	if account == "" {
		return usage("--policy-account is required")
	}

	mode := accessctl.Mode(strings.ToLower(strings.TrimSpace(c.Mode)))
	if mode != accessctl.ModeAllow && mode != accessctl.ModeDeny {
		return usage("mode must be \"allow\" or \"deny\"")
	}

	addresses := make(map[string]bool)
	for _, addr := range splitCSV(c.Addresses) {
		addr = accessctl.NormalizePolicyAddress(addr)
		if addr != "" {
			addresses[addr] = true
		}
	}

	domains := make(map[string]bool)
	for _, d := range splitCSV(c.Domains) {
		d = accessctl.NormalizePolicyDomain(d)
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
		"account":   account,
		"mode":      string(mode),
		"addresses": sortedKeys(addresses),
		"domains":   sortedKeys(domains),
	}); err != nil {
		return err
	}

	pf, err := loadOrCreatePolicyFile(flags)
	if err != nil {
		return err
	}
	pf.Accounts[account] = policy

	if err := writePolicyFile(flags, pf); err != nil {
		return err
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
			"saved":   true,
			"account": account,
			"mode":    string(mode),
		})
	}

	u.Out().Printf("Access policy set for %s: mode=%s, %d addresses, %d domains", account, mode, len(addresses), len(domains))
	return nil
}

type AccessPolicyAddCmd struct {
	Account string `name:"policy-account" required:"" help:"Account email to modify"`
	Address string `name:"address" help:"Email address to add"`
	Domain  string `name:"domain" help:"Domain to add"`
}

func (c *AccessPolicyAddCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	account := strings.ToLower(strings.TrimSpace(c.Account))
	if account == "" {
		return usage("--policy-account is required")
	}

	addr := accessctl.NormalizePolicyAddress(c.Address)
	domain := accessctl.NormalizePolicyDomain(c.Domain)
	if addr == "" && domain == "" {
		return usage("specify --address or --domain")
	}

	pf, err := loadOrCreatePolicyFile(flags)
	if err != nil {
		return err
	}

	policy := pf.Accounts[account]
	if policy == nil {
		return fmt.Errorf("no policy exists for account %s; use 'set' to create one first", account)
	}

	if addr != "" {
		policy.Addresses[addr] = true
	}
	if domain != "" {
		policy.Domains[domain] = true
	}

	if err := dryRunExit(ctx, flags, "config.access-policy.add", map[string]any{
		"account": account,
		"address": addr,
		"domain":  domain,
	}); err != nil {
		return err
	}

	if err := writePolicyFile(flags, pf); err != nil {
		return err
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{"added": true, "account": account})
	}

	if addr != "" {
		u.Out().Printf("Added address %s to %s", addr, account)
	}
	if domain != "" {
		u.Out().Printf("Added domain %s to %s", domain, account)
	}
	return nil
}

type AccessPolicyRemoveCmd struct {
	Account string `name:"policy-account" required:"" help:"Account email to modify"`
	Address string `name:"address" help:"Email address to remove"`
	Domain  string `name:"domain" help:"Domain to remove"`
}

func (c *AccessPolicyRemoveCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	account := strings.ToLower(strings.TrimSpace(c.Account))
	if account == "" {
		return usage("--policy-account is required")
	}

	addr := accessctl.NormalizePolicyAddress(c.Address)
	domain := accessctl.NormalizePolicyDomain(c.Domain)
	if addr == "" && domain == "" {
		return usage("specify --address or --domain")
	}

	pf, err := loadOrCreatePolicyFile(flags)
	if err != nil {
		return err
	}

	policy := pf.Accounts[account]
	if policy == nil {
		return fmt.Errorf("no policy exists for account %s", account)
	}

	if addr != "" {
		delete(policy.Addresses, addr)
	}
	if domain != "" {
		delete(policy.Domains, domain)
	}

	if err := dryRunExit(ctx, flags, "config.access-policy.remove", map[string]any{
		"account": account,
		"address": addr,
		"domain":  domain,
	}); err != nil {
		return err
	}

	if err := writePolicyFile(flags, pf); err != nil {
		return err
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{"removed": true, "account": account})
	}

	if addr != "" {
		u.Out().Printf("Removed address %s from %s", addr, account)
	}
	if domain != "" {
		u.Out().Printf("Removed domain %s from %s", domain, account)
	}
	return nil
}

type AccessPolicyTestCmd struct {
	Account string `name:"policy-account" required:"" help:"Account email to test against"`
	Email   string `arg:"" name:"email" help:"Email address to test"`
}

func (c *AccessPolicyTestCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)
	email := strings.TrimSpace(c.Email)
	if email == "" {
		return usage("email is required")
	}

	account := strings.ToLower(strings.TrimSpace(c.Account))
	if account == "" {
		return usage("--policy-account is required")
	}

	path, err := resolveAccessPolicyPath(flags)
	if err != nil {
		return err
	}

	policy, err := accessctl.LoadAccountPolicy(path, account)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if outfmt.IsJSON(ctx) {
				return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
					"email":   email,
					"account": account,
					"allowed": true,
					"reason":  "no policy configured",
				})
			}
			u.Out().Printf("%s: allowed (no policy configured)", email)
			return nil
		}
		return err
	}

	if policy == nil {
		if outfmt.IsJSON(ctx) {
			return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
				"email":   email,
				"account": account,
				"allowed": true,
				"reason":  "no policy for account",
			})
		}
		u.Out().Printf("%s: allowed (no policy for account %s)", email, account)
		return nil
	}

	allowed := policy.IsAllowed(email)
	reason := fmt.Sprintf("%s mode", policy.Mode)

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(ctx, os.Stdout, map[string]any{
			"email":   email,
			"account": account,
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

func loadOrCreatePolicyFile(flags *RootFlags) (*accessctl.PolicyFile, error) {
	path, err := resolveAccessPolicyPath(flags)
	if err != nil {
		return nil, err
	}
	pf, err := accessctl.LoadPolicyFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &accessctl.PolicyFile{
				Accounts: make(map[string]*accessctl.Policy),
			}, nil
		}
		return nil, err
	}
	return pf, nil
}

func writePolicyFile(flags *RootFlags, pf *accessctl.PolicyFile) error {
	path, err := resolveAccessPolicyPath(flags)
	if err != nil {
		return err
	}

	// Ensure config directory exists
	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
		return fmt.Errorf("ensure config dir: %w", mkdirErr)
	}

	data, err := accessctl.MarshalPolicyFile(pf)
	if err != nil {
		return err
	}

	// MarshalPolicyFile already returns indented JSON; just add trailing newline.
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

func accountNames(pf *accessctl.PolicyFile) map[string]bool {
	m := make(map[string]bool, len(pf.Accounts))
	for k := range pf.Accounts {
		m[k] = true
	}
	return m
}
