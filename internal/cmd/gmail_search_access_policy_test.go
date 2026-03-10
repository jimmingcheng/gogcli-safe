package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"

	"github.com/steipete/gogcli/internal/accessctl"
	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
)

func TestGmailMessagesSearchCmd_UsesParticipantFiltering(t *testing.T) {
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
						{"name": "To", "value": "allowed@example.com"},
						{"name": "Subject", "value": "Sent mail"},
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

	u, uiErr := ui.New(ui.Options{Stdout: os.Stdout, Stderr: io.Discard, Color: "never"})
	if uiErr != nil {
		t.Fatalf("ui.New: %v", uiErr)
	}
	ctx := outfmt.WithMode(ui.WithUI(context.Background(), u), outfmt.Mode{})
	ctx = accessctl.WithPolicy(ctx, &accessctl.Policy{
		Mode:      accessctl.ModeAllow,
		Addresses: map[string]bool{"allowed@example.com": true},
		Domains:   map[string]bool{},
	})

	out := captureStdout(t, func() {
		if err := runKong(t, &GmailMessagesSearchCmd{}, []string{"in:anywhere"}, ctx, &RootFlags{Account: "owner@example.com"}); err != nil {
			t.Fatalf("messages search: %v", err)
		}
	})

	if !strings.Contains(out, "m1") {
		t.Fatalf("expected allowed message in output: %q", out)
	}
}

func TestGmailSearchCmd_UsesFilteredThreadSummary(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/threads") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/threads/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"threads": []map[string]any{
					{"id": "t1"},
				},
			})
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/threads/t1") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "t1",
				"messages": []map[string]any{
					{
						"id": "m-blocked",
						"payload": map[string]any{
							"headers": []map[string]any{
								{"name": "From", "value": "owner@example.com"},
								{"name": "To", "value": "blocked@example.com"},
								{"name": "Subject", "value": "Blocked"},
								{"name": "Date", "value": "Mon, 02 Jan 2006 15:04:05 -0700"},
							},
						},
					},
					{
						"id": "m-allowed",
						"payload": map[string]any{
							"headers": []map[string]any{
								{"name": "From", "value": "allowed@example.com"},
								{"name": "To", "value": "owner@example.com"},
								{"name": "Subject", "value": "Allowed"},
								{"name": "Date", "value": "Tue, 03 Jan 2006 15:04:05 -0700"},
							},
						},
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

	u, uiErr := ui.New(ui.Options{Stdout: os.Stdout, Stderr: io.Discard, Color: "never"})
	if uiErr != nil {
		t.Fatalf("ui.New: %v", uiErr)
	}
	ctx := outfmt.WithMode(ui.WithUI(context.Background(), u), outfmt.Mode{})
	ctx = accessctl.WithPolicy(ctx, &accessctl.Policy{
		Mode:      accessctl.ModeAllow,
		Addresses: map[string]bool{"allowed@example.com": true},
		Domains:   map[string]bool{},
	})

	out := captureStdout(t, func() {
		if err := runKong(t, &GmailSearchCmd{}, []string{"in:anywhere"}, ctx, &RootFlags{Account: "owner@example.com"}); err != nil {
			t.Fatalf("thread search: %v", err)
		}
	})

	if !strings.Contains(out, "allowed@example.com") {
		t.Fatalf("expected filtered thread summary to use allowed participant: %q", out)
	}
	if strings.Contains(out, "blocked@example.com") {
		t.Fatalf("expected blocked participant to be removed from summary: %q", out)
	}
}
