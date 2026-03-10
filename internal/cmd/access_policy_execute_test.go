package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"

	"github.com/steipete/gogcli/internal/secrets"
)

func TestExecute_Version_IgnoresMissingAccessPolicyFile(t *testing.T) {
	t.Setenv("GOG_ACCESS_POLICY", filepath.Join(t.TempDir(), "missing-policy.json"))

	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			if err := Execute([]string{"version"}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		})
	})

	if strings.Contains(stderr, "access policy") {
		t.Fatalf("unexpected access-policy error for version: %q", stderr)
	}
}

func TestExecute_AccessPolicySet_CreatesMissingOverrideFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-policy.json")

	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			if err := Execute([]string{
				"--access-policy", path,
				"config", "access-policy", "set",
				"--policy-account", "demo@example.com",
				"--mode", "allow",
				"--domains", "example.com",
			}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		})
	})
	if strings.Contains(stderr, "read access policy") {
		t.Fatalf("unexpected startup failure: %q", stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "demo@example.com") || !strings.Contains(string(data), "example.com") {
		t.Fatalf("unexpected policy contents: %q", string(data))
	}
}

func TestExecute_GmailMessagesSearch_LoadsPolicyForInferredAccount(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "gmail": {
    "accounts": {
      "owner@example.com": {
        "mode": "allow",
        "addresses": ["allowed@example.com"]
      }
    }
  }
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	prevStore := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prevStore })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{defaultAccount: "owner@example.com"}, nil
	}

	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/messages") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/messages/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"messages": []map[string]any{
					{"id": "m1", "threadId": "t1"},
				},
			})
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/messages/m1") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":       "m1",
				"threadId": "t1",
				"payload": map[string]any{
					"headers": []map[string]any{
						{"name": "From", "value": "owner@example.com"},
						{"name": "To", "value": "blocked@example.com"},
						{"name": "Subject", "value": "Blocked"},
						{"name": "Date", "value": "Mon, 02 Jan 2006 15:04:05 -0700"},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/labels") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"labels": []map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	svc, err := gmail.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	newGmailService = func(context.Context, string) (*gmail.Service, error) { return svc, nil }

	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{
				"--json",
				"--access-policy", policyPath,
				"gmail", "messages", "search", "in:anywhere",
			}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		})
	})

	var parsed struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json parse: %v\nout=%q", err, out)
	}
	if len(parsed.Messages) != 0 {
		t.Fatalf("expected inferred-account policy to filter results, got %#v", parsed.Messages)
	}
}
