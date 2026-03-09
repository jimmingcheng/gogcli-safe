package accessctl

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
	"strings"
)

// Mode is the access control mode: allow or deny.
type Mode string

const (
	ModeAllow Mode = "allow"
	ModeDeny  Mode = "deny"
)

// Policy defines an email-address-based access control policy for Gmail.
type Policy struct {
	Mode      Mode
	Addresses map[string]bool // normalized lowercase emails
	Domains   map[string]bool // e.g. "example.com"
}

// IsAllowed returns true if the given email address is allowed by the policy.
func (p *Policy) IsAllowed(email string) bool {
	if p == nil {
		return true
	}
	email = normalizeEmail(email)
	if email == "" {
		return true
	}

	matched := p.matchesEntry(email)

	switch p.Mode {
	case ModeAllow:
		return matched
	case ModeDeny:
		return !matched
	default:
		return true
	}
}

// matchesEntry returns true if the email matches any address or domain entry.
func (p *Policy) matchesEntry(email string) bool {
	if p.Addresses[email] {
		return true
	}
	domain := domainOf(email)
	if domain != "" && p.Domains[domain] {
		return true
	}
	return false
}

// FilterAddressList takes an RFC 5322 address list header value and returns
// a filtered version containing only allowed addresses.
func (p *Policy) FilterAddressList(header string) string {
	if p == nil {
		return header
	}
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}

	addrs, err := mail.ParseAddressList(header)
	if err != nil {
		// Fallback: try individual addresses split by comma
		return p.filterAddressListFallback(header)
	}

	var kept []string
	for _, addr := range addrs {
		if addr.Address == "" {
			continue
		}
		if p.IsAllowed(addr.Address) {
			kept = append(kept, addr.String())
		}
	}
	return strings.Join(kept, ", ")
}

func (p *Policy) filterAddressListFallback(header string) string {
	parts := strings.Split(header, ",")
	var kept []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		email := extractEmail(part)
		if email == "" || p.IsAllowed(email) {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, ", ")
}

// ContainsRestricted returns true if any of the given emails are restricted by the policy.
func (p *Policy) ContainsRestricted(emails ...string) bool {
	if p == nil {
		return false
	}
	for _, email := range emails {
		if !p.IsAllowed(email) {
			return true
		}
	}
	return false
}

// policyFile is the JSON config file format.
type policyFile struct {
	Gmail *gmailPolicy `json:"gmail"`
}

type gmailPolicy struct {
	Mode      string   `json:"mode"`
	Addresses []string `json:"addresses"`
	Domains   []string `json:"domains"`
}

// LoadPolicy reads a policy file from disk and returns the Gmail policy.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read access policy: %w", err)
	}
	return ParsePolicy(data)
}

// ParsePolicy parses a policy from JSON bytes.
func ParsePolicy(data []byte) (*Policy, error) {
	var pf policyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse access policy: %w", err)
	}
	if pf.Gmail == nil {
		return nil, fmt.Errorf("access policy: missing \"gmail\" section")
	}

	mode := Mode(strings.ToLower(strings.TrimSpace(pf.Gmail.Mode)))
	if mode != ModeAllow && mode != ModeDeny {
		return nil, fmt.Errorf("access policy: mode must be \"allow\" or \"deny\", got %q", pf.Gmail.Mode)
	}

	addresses := make(map[string]bool, len(pf.Gmail.Addresses))
	for _, addr := range pf.Gmail.Addresses {
		normalized := normalizeEmail(addr)
		if normalized != "" {
			addresses[normalized] = true
		}
	}

	domains := make(map[string]bool, len(pf.Gmail.Domains))
	for _, d := range pf.Gmail.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			domains[d] = true
		}
	}

	return &Policy{
		Mode:      mode,
		Addresses: addresses,
		Domains:   domains,
	}, nil
}

// MarshalPolicy returns the JSON representation of a policy.
func MarshalPolicy(p *Policy) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("nil policy")
	}

	addresses := make([]string, 0, len(p.Addresses))
	for addr := range p.Addresses {
		addresses = append(addresses, addr)
	}

	domainList := make([]string, 0, len(p.Domains))
	for d := range p.Domains {
		domainList = append(domainList, d)
	}

	pf := policyFile{
		Gmail: &gmailPolicy{
			Mode:      string(p.Mode),
			Addresses: addresses,
			Domains:   domainList,
		},
	}

	return json.MarshalIndent(pf, "", "  ")
}

func normalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	// Try parsing as RFC 5322 address
	addr, err := mail.ParseAddress(email)
	if err == nil {
		return strings.ToLower(addr.Address)
	}
	// Fallback: extract from angle brackets or just lowercase
	extracted := extractEmail(email)
	if extracted != "" {
		return strings.ToLower(extracted)
	}
	return strings.ToLower(email)
}

func extractEmail(s string) string {
	s = strings.TrimSpace(s)
	if start := strings.LastIndex(s, "<"); start != -1 {
		if end := strings.LastIndex(s, ">"); end > start {
			email := strings.TrimSpace(s[start+1 : end])
			if strings.Contains(email, "@") {
				return strings.ToLower(email)
			}
		}
	}
	if strings.Contains(s, "@") {
		return strings.ToLower(s)
	}
	return ""
}

// ExtractEmails parses email addresses from an RFC 5322 header value.
func ExtractEmails(header string) []string {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
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

func domainOf(email string) string {
	at := strings.LastIndex(email, "@")
	if at == -1 {
		return ""
	}
	return email[at+1:]
}
