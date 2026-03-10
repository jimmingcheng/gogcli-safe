package accessctl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePolicyFile(t *testing.T) {
	data := []byte(`{
		"gmail": {
			"accounts": {
				"alice@gmail.com": {
					"mode": "allow",
					"addresses": ["bob@example.com", "Carol <carol@work.com>"],
					"domains": ["trusted-corp.com"]
				},
				"work@company.com": {
					"mode": "deny",
					"domains": ["spam.com"]
				}
			}
		}
	}`)

	pf, err := ParsePolicyFile(data)
	require.NoError(t, err)
	require.Len(t, pf.Accounts, 2)

	alice := pf.ForAccount("alice@gmail.com")
	require.NotNil(t, alice)
	assert.Equal(t, "alice@gmail.com", alice.Owner)
	assert.Equal(t, ModeAllow, alice.Mode)
	assert.True(t, alice.Addresses["bob@example.com"])
	assert.True(t, alice.Addresses["carol@work.com"])
	assert.True(t, alice.Domains["trusted-corp.com"])

	work := pf.ForAccount("work@company.com")
	require.NotNil(t, work)
	assert.Equal(t, ModeDeny, work.Mode)
	assert.True(t, work.Domains["spam.com"])
}

func TestParsePolicyFile_CaseInsensitiveAccount(t *testing.T) {
	data := []byte(`{
		"gmail": {
			"accounts": {
				"Alice@Gmail.COM": {
					"mode": "allow",
					"addresses": ["bob@example.com"]
				}
			}
		}
	}`)

	pf, err := ParsePolicyFile(data)
	require.NoError(t, err)

	// Lookup should be case-insensitive
	assert.NotNil(t, pf.ForAccount("alice@gmail.com"))
	assert.NotNil(t, pf.ForAccount("ALICE@GMAIL.COM"))
}

func TestParsePolicyFile_UnlistedAccountReturnsNil(t *testing.T) {
	data := []byte(`{
		"gmail": {
			"accounts": {
				"alice@gmail.com": {
					"mode": "allow",
					"addresses": ["bob@example.com"]
				}
			}
		}
	}`)

	pf, err := ParsePolicyFile(data)
	require.NoError(t, err)

	assert.Nil(t, pf.ForAccount("unknown@other.com"))
	assert.Nil(t, pf.ForAccount(""))
}

func TestParsePolicyFile_InvalidMode(t *testing.T) {
	data := []byte(`{
		"gmail": {
			"accounts": {
				"alice@gmail.com": {
					"mode": "invalid"
				}
			}
		}
	}`)
	_, err := ParsePolicyFile(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mode must be")
}

func TestParsePolicyFile_MissingGmail(t *testing.T) {
	data := []byte(`{}`)
	_, err := ParsePolicyFile(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestParsePolicyFile_MissingAccounts(t *testing.T) {
	data := []byte(`{"gmail": {}}`)
	_, err := ParsePolicyFile(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestParseAccountPolicy(t *testing.T) {
	data := []byte(`{
		"gmail": {
			"accounts": {
				"alice@gmail.com": {
					"mode": "allow",
					"addresses": ["bob@example.com"]
				}
			}
		}
	}`)

	p, err := ParseAccountPolicy(data, "alice@gmail.com")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, ModeAllow, p.Mode)

	p2, err := ParseAccountPolicy(data, "unknown@other.com")
	require.NoError(t, err)
	assert.Nil(t, p2)
}

func TestForAccount_NilPolicyFile(t *testing.T) {
	var pf *PolicyFile
	assert.Nil(t, pf.ForAccount("anyone@anywhere.com"))
}

func TestIsAllowed_AllowMode(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{"trusted.com": true},
	}

	assert.True(t, p.IsAllowed("alice@example.com"))
	assert.True(t, p.IsAllowed("Alice@Example.COM"))
	assert.True(t, p.IsAllowed("anyone@trusted.com"))
	assert.False(t, p.IsAllowed("bob@other.com"))
	assert.True(t, p.IsAllowed("")) // empty is always allowed
}

func TestIsAllowed_DenyMode(t *testing.T) {
	p := &Policy{
		Mode:      ModeDeny,
		Addresses: map[string]bool{"spam@evil.com": true},
		Domains:   map[string]bool{"blocked.org": true},
	}

	assert.True(t, p.IsAllowed("alice@example.com"))
	assert.False(t, p.IsAllowed("spam@evil.com"))
	assert.False(t, p.IsAllowed("anyone@blocked.org"))
}

func TestIsAllowed_NilPolicy(t *testing.T) {
	var p *Policy
	assert.True(t, p.IsAllowed("anyone@anywhere.com"))
}

func TestFilterAddressList(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{},
	}

	result := p.FilterAddressList("alice@example.com, bob@other.com")
	assert.Contains(t, result, "alice@example.com")
	assert.NotContains(t, result, "bob@other.com")
}

func TestFilterAddressList_RFC5322(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{},
	}

	result := p.FilterAddressList("Alice <alice@example.com>, Bob <bob@other.com>")
	assert.Contains(t, result, "alice@example.com")
	assert.NotContains(t, result, "bob@other.com")
}

func TestFilterAddressList_NilPolicy(t *testing.T) {
	var p *Policy
	input := "alice@example.com, bob@other.com"
	assert.Equal(t, input, p.FilterAddressList(input))
}

func TestContainsRestricted(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{},
	}

	assert.False(t, p.ContainsRestricted("alice@example.com"))
	assert.True(t, p.ContainsRestricted("bob@other.com"))
	assert.True(t, p.ContainsRestricted("alice@example.com", "bob@other.com"))
}

func TestContainsRestricted_NilPolicy(t *testing.T) {
	var p *Policy
	assert.False(t, p.ContainsRestricted("anyone@anywhere.com"))
}

func TestMarshalPolicyFile(t *testing.T) {
	pf := &PolicyFile{
		Accounts: map[string]*Policy{
			"alice@gmail.com": {
				Mode:      ModeAllow,
				Addresses: map[string]bool{"bob@example.com": true},
				Domains:   map[string]bool{"trusted.com": true},
			},
			"work@company.com": {
				Mode:      ModeDeny,
				Addresses: map[string]bool{},
				Domains:   map[string]bool{"spam.com": true},
			},
		},
	}

	data, err := MarshalPolicyFile(pf)
	require.NoError(t, err)

	pf2, err := ParsePolicyFile(data)
	require.NoError(t, err)
	require.Len(t, pf2.Accounts, 2)

	alice := pf2.ForAccount("alice@gmail.com")
	require.NotNil(t, alice)
	assert.Equal(t, ModeAllow, alice.Mode)
	assert.True(t, alice.Addresses["bob@example.com"])
	assert.True(t, alice.Domains["trusted.com"])

	work := pf2.ForAccount("work@company.com")
	require.NotNil(t, work)
	assert.Equal(t, ModeDeny, work.Mode)
	assert.True(t, work.Domains["spam.com"])
}

func TestMarshalPolicyFile_Nil(t *testing.T) {
	_, err := MarshalPolicyFile(nil)
	assert.Error(t, err)
}

func TestNormalizeEmail(t *testing.T) {
	assert.Equal(t, "alice@example.com", normalizeEmail("Alice@Example.COM"))
	assert.Equal(t, "bob@work.com", normalizeEmail("Bob <bob@work.com>"))
	assert.Equal(t, "", normalizeEmail(""))
}

func TestDomainOf(t *testing.T) {
	assert.Equal(t, "example.com", domainOf("alice@example.com"))
	assert.Equal(t, "", domainOf("nodomain"))
}
