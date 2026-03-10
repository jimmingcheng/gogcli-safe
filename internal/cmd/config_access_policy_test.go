package cmd

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
)

func TestAccessPolicyShowCmd_UsesAccessPolicyOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-policy.json")
	if err := os.WriteFile(path, []byte(`{
  "gmail": {
    "accounts": {
      "demo@example.com": {
        "mode": "allow",
        "addresses": ["allowed@example.com"]
      }
    }
  }
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(t, func() {
		u, uiErr := ui.New(ui.Options{Stdout: os.Stdout, Stderr: io.Discard, Color: "never"})
		if uiErr != nil {
			t.Fatalf("ui.New: %v", uiErr)
		}

		ctx := outfmt.WithMode(ui.WithUI(context.Background(), u), outfmt.Mode{JSON: true})
		flags := &RootFlags{AccessPolicy: path}
		if err := runKong(t, &AccessPolicyShowCmd{}, []string{"--policy-account", "demo@example.com"}, ctx, flags); err != nil {
			t.Fatalf("show: %v", err)
		}
	})

	var parsed struct {
		Path    string `json:"path"`
		Account string `json:"account"`
		Policy  struct {
			Mode      string   `json:"mode"`
			Addresses []string `json:"addresses"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json parse: %v", err)
	}
	if parsed.Path != path {
		t.Fatalf("expected override path %q, got %q", path, parsed.Path)
	}
	if parsed.Account != "demo@example.com" || parsed.Policy.Mode != "allow" {
		t.Fatalf("unexpected output: %#v", parsed)
	}
}

func TestAccessPolicySetCmd_WritesAccessPolicyOverridePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "override.json")

	u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
	if uiErr != nil {
		t.Fatalf("ui.New: %v", uiErr)
	}
	ctx := outfmt.WithMode(ui.WithUI(context.Background(), u), outfmt.Mode{})
	flags := &RootFlags{AccessPolicy: path}

	if err := runKong(t, &AccessPolicySetCmd{}, []string{
		"--policy-account", "demo@example.com",
		"--mode", "allow",
		"--addresses", "allowed@example.com",
	}, ctx, flags); err != nil {
		t.Fatalf("set: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "demo@example.com") || !strings.Contains(content, "allowed@example.com") {
		t.Fatalf("expected override file to be written, got %q", content)
	}
}
