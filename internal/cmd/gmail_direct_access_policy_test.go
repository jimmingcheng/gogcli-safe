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

func accessPolicyTestContext(t *testing.T, jsonMode bool) context.Context {
	t.Helper()

	u, err := ui.New(ui.Options{Stdout: os.Stdout, Stderr: io.Discard, Color: "never"})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}

	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{JSON: jsonMode})
	return accessctl.WithPolicy(ctx, &accessctl.Policy{
		Owner:     "owner@example.com",
		Mode:      accessctl.ModeAllow,
		Addresses: map[string]bool{"allowed@example.com": true},
		Domains:   map[string]bool{},
	})
}

func gmailTestService(t *testing.T, handler http.Handler) *gmail.Service {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	svc, err := gmail.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestGmailMessagesModifyCmd_BlocksRestrictedMessage(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	modifyCalled := false
	newGmailService = func(context.Context, string) (*gmail.Service, error) {
		return gmailTestService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/gmail/v1/users/me/messages/m1") && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "m1",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "From", "value": "owner@example.com"},
							{"name": "To", "value": "blocked@example.com"},
						},
					},
				})
			case strings.Contains(r.URL.Path, "/gmail/v1/users/me/labels") && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"labels": []map[string]any{{"id": "INBOX", "name": "INBOX", "type": "system"}}})
			case strings.HasSuffix(r.URL.Path, "/modify") && r.Method == http.MethodPost:
				modifyCalled = true
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{})
			default:
				http.NotFound(w, r)
			}
		})), nil
	}

	err := runKong(t, &GmailMessagesModifyCmd{}, []string{"m1", "--add", "INBOX"}, accessPolicyTestContext(t, false), &RootFlags{Account: "owner@example.com"})
	if err == nil || !strings.Contains(err.Error(), "access policy") {
		t.Fatalf("expected access policy error, got %v", err)
	}
	if modifyCalled {
		t.Fatal("expected modify endpoint not to be called")
	}
}

func TestGmailBatchDeleteCmd_BlocksRestrictedMessage(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	deleteCalled := false
	newGmailService = func(context.Context, string) (*gmail.Service, error) {
		return gmailTestService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/gmail/v1/users/me/messages/m1") && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "m1",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "From", "value": "owner@example.com"},
							{"name": "To", "value": "blocked@example.com"},
						},
					},
				})
			case strings.HasSuffix(r.URL.Path, "/batchDelete") && r.Method == http.MethodPost:
				deleteCalled = true
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{})
			default:
				http.NotFound(w, r)
			}
		})), nil
	}

	err := runKong(t, &GmailBatchDeleteCmd{}, []string{"m1"}, accessPolicyTestContext(t, false), &RootFlags{Account: "owner@example.com", Force: true})
	if err == nil || !strings.Contains(err.Error(), "access policy") {
		t.Fatalf("expected access policy error, got %v", err)
	}
	if deleteCalled {
		t.Fatal("expected batchDelete endpoint not to be called")
	}
}

func TestGmailThreadModifyCmd_BlocksMixedRestrictedThread(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	modifyCalled := false
	newGmailService = func(context.Context, string) (*gmail.Service, error) {
		return gmailTestService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/gmail/v1/users/me/threads/t1") && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "t1",
					"messages": []map[string]any{
						{
							"id": "m-allowed",
							"payload": map[string]any{
								"headers": []map[string]any{
									{"name": "From", "value": "owner@example.com"},
									{"name": "To", "value": "allowed@example.com"},
								},
							},
						},
						{
							"id": "m-blocked",
							"payload": map[string]any{
								"headers": []map[string]any{
									{"name": "From", "value": "owner@example.com"},
									{"name": "To", "value": "blocked@example.com"},
								},
							},
						},
					},
				})
			case strings.Contains(r.URL.Path, "/gmail/v1/users/me/labels") && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"labels": []map[string]any{{"id": "INBOX", "name": "INBOX", "type": "system"}}})
			case strings.HasSuffix(r.URL.Path, "/modify") && r.Method == http.MethodPost:
				modifyCalled = true
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{})
			default:
				http.NotFound(w, r)
			}
		})), nil
	}

	err := runKong(t, &GmailThreadModifyCmd{}, []string{"t1", "--add", "INBOX"}, accessPolicyTestContext(t, false), &RootFlags{Account: "owner@example.com"})
	if err == nil || !strings.Contains(err.Error(), "access policy") {
		t.Fatalf("expected access policy error, got %v", err)
	}
	if modifyCalled {
		t.Fatal("expected thread modify endpoint not to be called")
	}
}

func TestGmailAttachmentCmd_BlocksRestrictedMessage(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	newGmailService = func(context.Context, string) (*gmail.Service, error) {
		return gmailTestService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/gmail/v1/users/me/messages/m1") && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "m1",
					"payload": map[string]any{
						"headers": []map[string]any{
							{"name": "From", "value": "owner@example.com"},
							{"name": "To", "value": "blocked@example.com"},
						},
					},
				})
			default:
				http.NotFound(w, r)
			}
		})), nil
	}

	err := runKong(t, &GmailAttachmentCmd{}, []string{"m1", "a1"}, accessPolicyTestContext(t, false), &RootFlags{Account: "owner@example.com"})
	if err == nil || !strings.Contains(err.Error(), "access policy") {
		t.Fatalf("expected access policy error, got %v", err)
	}
}

func TestGmailThreadAttachmentsCmd_FiltersRestrictedMessages(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	newGmailService = func(context.Context, string) (*gmail.Service, error) {
		return gmailTestService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/gmail/v1/users/me/threads/t1") && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "t1",
					"messages": []map[string]any{
						{
							"id": "m-allowed",
							"payload": map[string]any{
								"headers": []map[string]any{
									{"name": "From", "value": "owner@example.com"},
									{"name": "To", "value": "allowed@example.com"},
								},
								"parts": []map[string]any{
									{
										"filename": "ok.txt",
										"mimeType": "text/plain",
										"body": map[string]any{
											"attachmentId": "a1",
											"size":         3,
										},
									},
								},
							},
						},
						{
							"id": "m-blocked",
							"payload": map[string]any{
								"headers": []map[string]any{
									{"name": "From", "value": "owner@example.com"},
									{"name": "To", "value": "blocked@example.com"},
								},
								"parts": []map[string]any{
									{
										"filename": "blocked.txt",
										"mimeType": "text/plain",
										"body": map[string]any{
											"attachmentId": "a2",
											"size":         4,
										},
									},
								},
							},
						},
					},
				})
			default:
				http.NotFound(w, r)
			}
		})), nil
	}

	out := captureStdout(t, func() {
		if err := runKong(t, &GmailThreadAttachmentsCmd{}, []string{"t1"}, accessPolicyTestContext(t, true), &RootFlags{Account: "owner@example.com"}); err != nil {
			t.Fatalf("runKong: %v", err)
		}
	})

	var parsed struct {
		Attachments []struct {
			MessageID    string `json:"messageId"`
			AttachmentID string `json:"attachmentId"`
			Filename     string `json:"filename"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json parse: %v\nout=%q", err, out)
	}
	if len(parsed.Attachments) != 1 {
		t.Fatalf("expected 1 allowed attachment, got %#v", parsed.Attachments)
	}
	if parsed.Attachments[0].MessageID != "m-allowed" || parsed.Attachments[0].AttachmentID != "a1" {
		t.Fatalf("unexpected attachment output: %#v", parsed.Attachments[0])
	}
}
