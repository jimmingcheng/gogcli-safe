package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripProxyFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "no proxy flags",
			args: []string{"gmail", "search", "test"},
			want: []string{"gmail", "search", "test"},
		},
		{
			name: "strip --proxy-socket with value",
			args: []string{"--proxy-socket", "/tmp/proxy.sock", "gmail", "search", "test"},
			want: []string{"gmail", "search", "test"},
		},
		{
			name: "strip --proxy-socket= with value",
			args: []string{"--proxy-socket=/tmp/proxy.sock", "gmail", "search", "test"},
			want: []string{"gmail", "search", "test"},
		},
		{
			name: "strip --proxy-nonce-file",
			args: []string{"--proxy-nonce-file", "/tmp/proxy.nonce", "gmail", "search", "test"},
			want: []string{"gmail", "search", "test"},
		},
		{
			name: "strip both",
			args: []string{"--proxy-socket", "/tmp/proxy.sock", "--proxy-nonce-file", "/tmp/nonce", "gmail", "search"},
			want: []string{"gmail", "search"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripProxyFlags(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFirstNonFlagArg(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "simple command", args: []string{"gmail", "search"}, want: "gmail"},
		{name: "flag before command", args: []string{"--json", "gmail"}, want: "gmail"},
		{name: "flag with value before command", args: []string{"--account", "me@gmail.com", "gmail"}, want: "gmail"},
		{name: "flag=value before command", args: []string{"--account=me@gmail.com", "config"}, want: "config"},
		{name: "empty args", args: nil, want: ""},
		{name: "only flags", args: []string{"--json", "--verbose"}, want: ""},
		{name: "uppercase command", args: []string{"Auth"}, want: "auth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firstNonFlagArg(tt.args))
		})
	}
}

func TestBlockedProxyCommands(t *testing.T) {
	blocked := []string{"auth", "config", "login", "logout", "status", "proxy", "version"}
	for _, cmd := range blocked {
		assert.True(t, blockedProxyCommands[cmd], "expected %q to be blocked", cmd)
	}

	allowed := []string{"gmail", "calendar", "drive", "contacts"}
	for _, cmd := range allowed {
		assert.False(t, blockedProxyCommands[cmd], "expected %q to be allowed", cmd)
	}
}

func TestProxySocketFromArgsEnv_PrefersCLI(t *testing.T) {
	t.Setenv("GOG_PROXY_SOCKET", "/tmp/env.sock")

	got := proxySocketFromArgsEnv([]string{"--proxy-socket", "/tmp/cli.sock", "gmail", "search"})
	assert.Equal(t, "/tmp/cli.sock", got)
}

func TestProxyNoncePath_PrefersCLI(t *testing.T) {
	t.Setenv("GOG_PROXY_NONCE_FILE", "/tmp/env.nonce")

	got := proxyNoncePath([]string{"--proxy-nonce-file", "/tmp/cli.nonce", "gmail", "search"}, "/tmp/proxy.sock")
	assert.Equal(t, "/tmp/cli.nonce", got)
}

func TestResolveProxyPolicyPath_UsesGlobalOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "override.json")

	got, err := resolveProxyPolicyPath(&ProxyServeCmd{}, &RootFlags{AccessPolicy: path})
	assert.NoError(t, err)
	assert.Equal(t, path, got)
}

func TestResolveProxyPolicyPath_PrefersCommandPolicyFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "override.json")
	cmdPath := filepath.Join(t.TempDir(), "command.json")

	got, err := resolveProxyPolicyPath(&ProxyServeCmd{Policy: cmdPath}, &RootFlags{AccessPolicy: path})
	assert.NoError(t, err)
	assert.Equal(t, cmdPath, got)
}
