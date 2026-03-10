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
	Owner     string
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

// IsOwner returns true if the given email matches the policy owner account.
func (p *Policy) IsOwner(email string) bool {
	if p == nil {
		return false
	}
	owner := normalizeEmail(p.Owner)
	if owner == "" {
		return false
	}
	return normalizeEmail(email) == owner
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

// PolicyFile is the parsed multi-account policy file. Accounts not present
// in the map are unrestricted (nil policy).
type PolicyFile struct {
	Accounts map[string]*Policy // keyed by lowercase email
}

// ForAccount returns the policy for the given account, or nil if the account
// is not listed (meaning unrestricted).
func (pf *PolicyFile) ForAccount(account string) *Policy {
	if pf == nil {
		return nil
	}
	account = strings.ToLower(strings.TrimSpace(account))
	p := pf.Accounts[account]
	if p == nil {
		return nil
	}
	return p.withOwner(account)
}

// accountPolicy is the per-account JSON shape inside the policy file.
type accountPolicy struct {
	Mode      string   `json:"mode"`
	Addresses []string `json:"addresses"`
	Domains   []string `json:"domains"`
}

// policyFile is the JSON config file format (multi-account).
type policyFile struct {
	Gmail *gmailSection `json:"gmail"`
}

type gmailSection struct {
	Accounts map[string]*accountPolicy `json:"accounts"`
}

// LoadPolicyFile reads a policy file from disk and returns the full PolicyFile.
func LoadPolicyFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read access policy: %w", err)
	}
	return ParsePolicyFile(data)
}

// LoadAccountPolicy reads a policy file and extracts the policy for a single account.
// Returns nil (unrestricted) if the account is empty or not listed.
func LoadAccountPolicy(path, account string) (*Policy, error) {
	pf, err := LoadPolicyFile(path)
	if err != nil {
		return nil, err
	}
	return pf.ForAccount(account), nil
}

// ParsePolicyFile parses a multi-account policy file from JSON bytes.
func ParsePolicyFile(data []byte) (*PolicyFile, error) {
	var pf policyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse access policy: %w", err)
	}
	if pf.Gmail == nil {
		return nil, fmt.Errorf("access policy: missing \"gmail\" section")
	}
	if pf.Gmail.Accounts == nil {
		return nil, fmt.Errorf("access policy: missing \"gmail.accounts\" section")
	}

	result := &PolicyFile{Accounts: make(map[string]*Policy, len(pf.Gmail.Accounts))}
	for acct, ap := range pf.Gmail.Accounts {
		acct = strings.ToLower(strings.TrimSpace(acct))
		if acct == "" || ap == nil {
			continue
		}
		p, err := parseAccountPolicy(ap)
		if err != nil {
			return nil, fmt.Errorf("access policy for %s: %w", acct, err)
		}
		result.Accounts[acct] = p
	}

	return result, nil
}

// ParseAccountPolicy parses a multi-account file and extracts one account's policy.
// Returns nil (unrestricted) if the account is empty or not listed.
func ParseAccountPolicy(data []byte, account string) (*Policy, error) {
	pf, err := ParsePolicyFile(data)
	if err != nil {
		return nil, err
	}
	return pf.ForAccount(account), nil
}

func parseAccountPolicy(ap *accountPolicy) (*Policy, error) {
	mode := Mode(strings.ToLower(strings.TrimSpace(ap.Mode)))
	if mode != ModeAllow && mode != ModeDeny {
		return nil, fmt.Errorf("mode must be \"allow\" or \"deny\", got %q", ap.Mode)
	}

	addresses := make(map[string]bool, len(ap.Addresses))
	for _, addr := range ap.Addresses {
		normalized := normalizeEmail(addr)
		if normalized != "" {
			addresses[normalized] = true
		}
	}

	domains := make(map[string]bool, len(ap.Domains))
	for _, d := range ap.Domains {
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

// MarshalPolicyFile returns the JSON representation of a full multi-account policy file.
func MarshalPolicyFile(pf *PolicyFile) ([]byte, error) {
	if pf == nil {
		return nil, fmt.Errorf("nil policy file")
	}

	accounts := make(map[string]*accountPolicy, len(pf.Accounts))
	for acct, p := range pf.Accounts {
		if p == nil {
			continue
		}
		addresses := make([]string, 0, len(p.Addresses))
		for addr := range p.Addresses {
			addresses = append(addresses, addr)
		}

		domainList := make([]string, 0, len(p.Domains))
		for d := range p.Domains {
			domainList = append(domainList, d)
		}

		accounts[acct] = &accountPolicy{
			Mode:      string(p.Mode),
			Addresses: addresses,
			Domains:   domainList,
		}
	}

	raw := policyFile{
		Gmail: &gmailSection{
			Accounts: accounts,
		},
	}

	return json.MarshalIndent(raw, "", "  ")
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

func (p *Policy) withOwner(owner string) *Policy {
	if p == nil {
		return nil
	}

	return &Policy{
		Owner:     normalizeEmail(owner),
		Mode:      p.Mode,
		Addresses: cloneStringSet(p.Addresses),
		Domains:   cloneStringSet(p.Domains),
	}
}

func cloneStringSet(in map[string]bool) map[string]bool {
	if len(in) == 0 {
		return map[string]bool{}
	}

	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
