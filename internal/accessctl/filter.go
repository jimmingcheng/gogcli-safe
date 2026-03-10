package accessctl

import (
	"fmt"
	"strings"

	"google.golang.org/api/gmail/v1"
)

// FilterMessage returns false if the message should be hidden per the policy.
// A message is hidden if all participant addresses (From, To, Cc, Bcc) that
// are not the account owner are restricted.
func FilterMessage(p *Policy, msg *gmail.Message) bool {
	if p == nil || msg == nil {
		return true
	}
	emails := collectMessageEmails(msg)
	if len(emails) == 0 {
		return true // no addresses to check — keep the message
	}

	sawNonOwner := false
	for _, email := range emails {
		if p.IsOwner(email) {
			continue
		}
		sawNonOwner = true
		if p.IsAllowed(email) {
			return true
		}
	}
	return !sawNonOwner
}

// FilterThread filters messages within a thread, returning a copy with only
// allowed messages. Returns nil if all messages were filtered out.
func FilterThread(p *Policy, thread *gmail.Thread) *gmail.Thread {
	if p == nil || thread == nil {
		return thread
	}
	var kept []*gmail.Message
	for _, msg := range thread.Messages {
		if FilterMessage(p, msg) {
			kept = append(kept, msg)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	filtered := *thread
	filtered.Messages = kept
	return &filtered
}

// ValidateSendRecipients checks that all recipients are allowed by the policy.
// Returns an error if any recipient is restricted.
func ValidateSendRecipients(p *Policy, to, cc, bcc []string) error {
	if p == nil {
		return nil
	}
	var restricted []string
	for _, addr := range to {
		if !p.IsAllowed(addr) {
			restricted = append(restricted, addr)
		}
	}
	for _, addr := range cc {
		if !p.IsAllowed(addr) {
			restricted = append(restricted, addr)
		}
	}
	for _, addr := range bcc {
		if !p.IsAllowed(addr) {
			restricted = append(restricted, addr)
		}
	}
	if len(restricted) > 0 {
		return fmt.Errorf("access policy: sending to restricted address(es): %s", strings.Join(restricted, ", "))
	}
	return nil
}

func collectMessageEmails(msg *gmail.Message) []string {
	if msg == nil || msg.Payload == nil {
		return nil
	}
	var emails []string
	for _, h := range msg.Payload.Headers {
		switch strings.ToLower(h.Name) {
		case "from", "to", "cc", "bcc":
			emails = append(emails, parseAddresses(h.Value)...)
		}
	}
	return emails
}

func parseAddresses(header string) []string {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	// Use the same extraction logic as normalizeEmail
	var result []string
	parts := strings.Split(header, ",")
	for _, p := range parts {
		email := extractEmail(strings.TrimSpace(p))
		if email != "" {
			result = append(result, email)
		}
	}
	return result
}
