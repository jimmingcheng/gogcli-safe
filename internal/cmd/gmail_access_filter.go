package cmd

import (
	"context"
	"fmt"

	"google.golang.org/api/gmail/v1"

	"github.com/steipete/gogcli/internal/accessctl"
)

// gmailPolicy extracts the access policy from context. Returns nil if none set.
func gmailPolicy(ctx context.Context) *accessctl.Policy {
	return accessctl.PolicyFromContext(ctx)
}

// enforceGmailRead checks whether a message is allowed by the access policy.
// Returns an error if the message is restricted.
func enforceGmailRead(ctx context.Context, msg *gmail.Message) error {
	p := gmailPolicy(ctx)
	if p == nil {
		return nil
	}
	if !accessctl.FilterMessage(p, msg) {
		return fmt.Errorf("access policy: message contains restricted addresses")
	}
	return nil
}

// enforceGmailWriteAll validates to, cc, and bcc recipients.
func enforceGmailWriteAll(ctx context.Context, to, cc, bcc []string) error {
	p := gmailPolicy(ctx)
	if p == nil {
		return nil
	}
	return accessctl.ValidateSendRecipients(p, to, cc, bcc)
}

// augmentGmailQuery adds access policy restrictions to a Gmail search query.
func augmentGmailQuery(ctx context.Context, query string) string {
	p := gmailPolicy(ctx)
	if p == nil {
		return query
	}
	return accessctl.AugmentSearchQuery(p, query)
}

// filterThreadItems filters thread items (search result items) by checking
// the From field against the policy.
func filterThreadItems(ctx context.Context, items []threadItem) []threadItem {
	p := gmailPolicy(ctx)
	if p == nil {
		return items
	}
	var kept []threadItem
	for _, item := range items {
		// Check if the From address is allowed
		from := extractEmail(item.From)
		if from == "" || p.IsAllowed(from) {
			kept = append(kept, item)
		}
	}
	return kept
}

// filterMessageItems filters message items (search result items) by checking
// the From field against the policy.
func filterMessageItems(ctx context.Context, items []messageItem) []messageItem {
	p := gmailPolicy(ctx)
	if p == nil {
		return items
	}
	var kept []messageItem
	for _, item := range items {
		from := extractEmail(item.From)
		if from == "" || p.IsAllowed(from) {
			kept = append(kept, item)
		}
	}
	return kept
}

// filterGmailThread filters messages within a thread per the access policy.
func filterGmailThread(ctx context.Context, thread *gmail.Thread) *gmail.Thread {
	p := gmailPolicy(ctx)
	if p == nil {
		return thread
	}
	return accessctl.FilterThread(p, thread)
}

// extractEmail extracts an email address from an RFC 5322 header value.
// Reuses the accessctl package's extraction logic.
func extractEmail(header string) string {
	addrs := accessctl.ExtractEmails(header)
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}
