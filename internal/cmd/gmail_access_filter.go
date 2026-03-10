package cmd

import (
	"context"
	"fmt"
	"sync"

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
	if !isGmailReadAllowed(ctx, msg) {
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

// filterGmailThread filters messages within a thread per the access policy.
func filterGmailThread(ctx context.Context, thread *gmail.Thread) *gmail.Thread {
	p := gmailPolicy(ctx)
	if p == nil {
		return thread
	}
	return accessctl.FilterThread(p, thread)
}

func isGmailReadAllowed(ctx context.Context, msg *gmail.Message) bool {
	p := gmailPolicy(ctx)
	if p == nil {
		return true
	}
	return accessctl.FilterMessage(p, msg)
}

func enforceGmailDraftAccess(ctx context.Context, draft *gmail.Draft) error {
	to, cc, bcc := draftRecipients(draft)
	return enforceGmailWriteAll(ctx, to, cc, bcc)
}

func draftRecipients(draft *gmail.Draft) (to []string, cc []string, bcc []string) {
	if draft == nil || draft.Message == nil || draft.Message.Payload == nil {
		return nil, nil, nil
	}

	return accessctl.ExtractEmails(headerValue(draft.Message.Payload, "To")),
		accessctl.ExtractEmails(headerValue(draft.Message.Payload, "Cc")),
		accessctl.ExtractEmails(headerValue(draft.Message.Payload, "Bcc"))
}

func filterAllowedMessageIDs(ctx context.Context, svc *gmail.Service, ids []string) ([]string, error) {
	if gmailPolicy(ctx) == nil || len(ids) == 0 {
		return ids, nil
	}

	const maxConcurrency = 10

	type result struct {
		index   int
		id      string
		allowed bool
		err     error
	}

	sem := make(chan struct{}, maxConcurrency)
	results := make(chan result, len(ids))

	var wg sync.WaitGroup
	for i, id := range ids {
		if id == "" {
			continue
		}

		wg.Add(1)
		go func(idx int, messageID string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- result{index: idx, err: ctx.Err()}
				return
			}

			msg, err := svc.Users.Messages.Get("me", messageID).
				Format("metadata").
				MetadataHeaders("From", "To", "Cc", "Bcc").
				Fields("id,payload(headers)").
				Context(ctx).
				Do()
			if err != nil {
				results <- result{index: idx, err: err}
				return
			}

			results <- result{
				index:   idx,
				id:      messageID,
				allowed: isGmailReadAllowed(ctx, msg),
			}
		}(i, id)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	allowed := make([]string, 0, len(ids))
	ordered := make([]result, len(ids))
	var firstErr error
	for r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		ordered[r.index] = r
	}
	if firstErr != nil {
		return nil, firstErr
	}

	for _, r := range ordered {
		if r.allowed && r.id != "" {
			allowed = append(allowed, r.id)
		}
	}

	return allowed, nil
}
