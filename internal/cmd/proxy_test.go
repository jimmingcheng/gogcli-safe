package cmd

import (
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
