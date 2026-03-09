package accessctl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicy(t *testing.T) {
	data := []byte(`{
		"gmail": {
			"mode": "allow",
			"addresses": ["alice@example.com", "Bob <bob@work.com>"],
			"domains": ["trusted-corp.com"]
		}
	}`)

	p, err := ParsePolicy(data)
	require.NoError(t, err)
	assert.Equal(t, ModeAllow, p.Mode)
	assert.True(t, p.Addresses["alice@example.com"])
	assert.True(t, p.Addresses["bob@work.com"])
	assert.True(t, p.Domains["trusted-corp.com"])
}

func TestLoadPolicy_Deny(t *testing.T) {
	data := []byte(`{
		"gmail": {
			"mode": "deny",
			"addresses": ["spam@evil.com"],
			"domains": ["blocked.org"]
		}
	}`)

	p, err := ParsePolicy(data)
	require.NoError(t, err)
	assert.Equal(t, ModeDeny, p.Mode)
}

func TestLoadPolicy_InvalidMode(t *testing.T) {
	data := []byte(`{"gmail": {"mode": "invalid"}}`)
	_, err := ParsePolicy(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mode must be")
}

func TestLoadPolicy_MissingGmail(t *testing.T) {
	data := []byte(`{}`)
	_, err := ParsePolicy(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
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

func TestMarshalPolicy(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{"trusted.com": true},
	}

	data, err := MarshalPolicy(p)
	require.NoError(t, err)

	p2, err := ParsePolicy(data)
	require.NoError(t, err)
	assert.Equal(t, p.Mode, p2.Mode)
	assert.True(t, p2.Addresses["alice@example.com"])
	assert.True(t, p2.Domains["trusted.com"])
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
