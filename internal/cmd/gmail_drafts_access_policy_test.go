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

func TestGmailDraftsListCmd_FiltersRestrictedDrafts(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/drafts/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"drafts": []map[string]any{
					{"id": "d-allowed"},
					{"id": "d-blocked"},
				},
			})
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts/d-allowed") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "d-allowed",
				"message": map[string]any{
					"id":       "m-allowed",
					"threadId": "t-allowed",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "To", "value": "allowed@example.com"},
						},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts/d-blocked") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "d-blocked",
				"message": map[string]any{
					"id":       "m-blocked",
					"threadId": "t-blocked",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "To", "value": "blocked@example.com"},
						},
					},
				},
			})
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

	flags := &RootFlags{Account: "owner@example.com"}
	out := captureStdout(t, func() {
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

		if err := runKong(t, &GmailDraftsListCmd{}, []string{}, ctx, flags); err != nil {
			t.Fatalf("list: %v", err)
		}
	})

	if !strings.Contains(out, "d-allowed") {
		t.Fatalf("expected allowed draft in output: %q", out)
	}
	if strings.Contains(out, "d-blocked") {
		t.Fatalf("expected blocked draft to be filtered out: %q", out)
	}
}

func TestGmailDraftsGetCmd_BlocksRestrictedDraft(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts/d1") && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "d1",
				"message": map[string]any{
					"id": "m1",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "To", "value": "blocked@example.com"},
							{"name": "Subject", "value": "Restricted"},
						},
					},
				},
			})
			return
		}
		http.NotFound(w, r)
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

	u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
	if uiErr != nil {
		t.Fatalf("ui.New: %v", uiErr)
	}
	ctx := outfmt.WithMode(ui.WithUI(context.Background(), u), outfmt.Mode{})
	ctx = accessctl.WithPolicy(ctx, &accessctl.Policy{
		Mode:      accessctl.ModeAllow,
		Addresses: map[string]bool{"allowed@example.com": true},
		Domains:   map[string]bool{},
	})

	err = runKong(t, &GmailDraftsGetCmd{}, []string{"d1"}, ctx, &RootFlags{Account: "owner@example.com"})
	if err == nil || !strings.Contains(err.Error(), "access policy") {
		t.Fatalf("expected access policy error, got %v", err)
	}
}

func TestGmailDraftsSendCmd_BlocksRestrictedDraft(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	sendCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts/d1") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "d1",
				"message": map[string]any{
					"id": "m1",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "To", "value": "blocked@example.com"},
						},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts/send") && r.Method == http.MethodPost:
			sendCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "m1"})
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

	u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
	if uiErr != nil {
		t.Fatalf("ui.New: %v", uiErr)
	}
	ctx := outfmt.WithMode(ui.WithUI(context.Background(), u), outfmt.Mode{})
	ctx = accessctl.WithPolicy(ctx, &accessctl.Policy{
		Mode:      accessctl.ModeAllow,
		Addresses: map[string]bool{"allowed@example.com": true},
		Domains:   map[string]bool{},
	})

	err = runKong(t, &GmailDraftsSendCmd{}, []string{"d1"}, ctx, &RootFlags{Account: "owner@example.com"})
	if err == nil || !strings.Contains(err.Error(), "access policy") {
		t.Fatalf("expected access policy error, got %v", err)
	}
	if sendCalled {
		t.Fatal("expected send endpoint not to be called")
	}
}

func TestGmailDraftsUpdateCmd_BlocksRestrictedExistingRecipients(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	updateCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts/d1") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "d1",
				"message": map[string]any{
					"id":       "m1",
					"threadId": "t1",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "To", "value": "blocked@example.com"},
						},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/gmail/v1/users/me/drafts/d1") && r.Method == http.MethodPut:
			updateCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "d1"})
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

	u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
	if uiErr != nil {
		t.Fatalf("ui.New: %v", uiErr)
	}
	ctx := outfmt.WithMode(ui.WithUI(context.Background(), u), outfmt.Mode{})
	ctx = accessctl.WithPolicy(ctx, &accessctl.Policy{
		Mode:      accessctl.ModeAllow,
		Addresses: map[string]bool{"allowed@example.com": true},
		Domains:   map[string]bool{},
	})

	err = runKong(t, &GmailDraftsUpdateCmd{}, []string{"d1", "--subject", "S", "--body", "B"}, ctx, &RootFlags{Account: "owner@example.com"})
	if err == nil || !strings.Contains(err.Error(), "access policy") {
		t.Fatalf("expected access policy error, got %v", err)
	}
	if updateCalled {
		t.Fatal("expected update endpoint not to be called")
	}
}
