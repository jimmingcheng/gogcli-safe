package accessctl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/gmail/v1"
)

func makeMessage(from, to string) *gmail.Message {
	return &gmail.Message{
		Id: "msg1",
		Payload: &gmail.MessagePart{
			Headers: []*gmail.MessagePartHeader{
				{Name: "From", Value: from},
				{Name: "To", Value: to},
			},
		},
	}
}

func TestFilterMessage_AllowMode(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{},
	}

	// Message from allowed sender — keep
	assert.True(t, FilterMessage(p, makeMessage("alice@example.com", "me@gmail.com")))

	// Message from restricted sender, to restricted recipient — hide
	assert.False(t, FilterMessage(p, makeMessage("bob@other.com", "carol@other.com")))

	// Message from restricted sender TO allowed address — keep
	assert.True(t, FilterMessage(p, makeMessage("bob@other.com", "alice@example.com")))
}

func TestFilterMessage_DenyMode(t *testing.T) {
	p := &Policy{
		Owner:     "me@gmail.com",
		Mode:      ModeDeny,
		Addresses: map[string]bool{"spam@evil.com": true},
		Domains:   map[string]bool{},
	}

	// Message from denied sender to the account owner — hide.
	assert.False(t, FilterMessage(p, makeMessage("spam@evil.com", "me@gmail.com")))

	// Message from denied sender to allowed participant — keep.
	assert.True(t, FilterMessage(p, makeMessage("spam@evil.com", "alice@example.com, me@gmail.com")))

	// Message from allowed sender — keep
	assert.True(t, FilterMessage(p, makeMessage("alice@example.com", "bob@work.com")))
}

func TestFilterMessage_NilPolicy(t *testing.T) {
	assert.True(t, FilterMessage(nil, makeMessage("anyone@anywhere.com", "other@other.com")))
}

func TestFilterMessage_NilMessage(t *testing.T) {
	p := &Policy{Mode: ModeAllow, Addresses: map[string]bool{}, Domains: map[string]bool{}}
	assert.True(t, FilterMessage(p, nil))
}

func TestFilterThread(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{},
	}

	thread := &gmail.Thread{
		Id: "thread1",
		Messages: []*gmail.Message{
			makeMessage("alice@example.com", "me@gmail.com"),
			makeMessage("bob@other.com", "carol@other.com"),
		},
	}

	filtered := FilterThread(p, thread)
	assert.NotNil(t, filtered)
	assert.Len(t, filtered.Messages, 1)
	assert.Equal(t, "msg1", filtered.Messages[0].Id)
}

func TestFilterThread_AllFiltered(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"nobody@nowhere.com": true},
		Domains:   map[string]bool{},
	}

	thread := &gmail.Thread{
		Id: "thread1",
		Messages: []*gmail.Message{
			makeMessage("alice@example.com", "bob@work.com"),
		},
	}

	assert.Nil(t, FilterThread(p, thread))
}

func TestFilterThread_NilPolicy(t *testing.T) {
	thread := &gmail.Thread{
		Id:       "thread1",
		Messages: []*gmail.Message{makeMessage("a@b.com", "c@d.com")},
	}
	assert.Equal(t, thread, FilterThread(nil, thread))
}

func TestValidateSendRecipients(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{},
	}

	assert.NoError(t, ValidateSendRecipients(p, []string{"alice@example.com"}, nil, nil))
	assert.Error(t, ValidateSendRecipients(p, []string{"bob@other.com"}, nil, nil))
	assert.Error(t, ValidateSendRecipients(p, []string{"alice@example.com"}, []string{"bob@other.com"}, nil))

	// Nil policy — always OK
	assert.NoError(t, ValidateSendRecipients(nil, []string{"anyone@anywhere.com"}, nil, nil))
}

func TestAugmentSearchQuery_AllowMode(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{"alice@example.com": true},
		Domains:   map[string]bool{},
	}

	result := AugmentSearchQuery(p, "meeting notes")
	assert.Contains(t, result, "meeting notes")
	assert.Contains(t, result, "from:alice@example.com")
	assert.Contains(t, result, "to:alice@example.com")
	assert.Contains(t, result, "{")
}

func TestAugmentSearchQuery_DenyMode(t *testing.T) {
	p := &Policy{
		Mode:      ModeDeny,
		Addresses: map[string]bool{"spam@evil.com": true},
		Domains:   map[string]bool{},
	}

	result := AugmentSearchQuery(p, "inbox")
	assert.Contains(t, result, "inbox")
	assert.Contains(t, result, "-from:spam@evil.com")
	assert.Contains(t, result, "-to:spam@evil.com")
}

func TestAugmentSearchQuery_DomainMode(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{},
		Domains:   map[string]bool{"trusted.com": true},
	}

	result := AugmentSearchQuery(p, "hello")
	assert.Contains(t, result, "from:@trusted.com")
	assert.Contains(t, result, "to:@trusted.com")
}

func TestAugmentSearchQuery_NilPolicy(t *testing.T) {
	assert.Equal(t, "test query", AugmentSearchQuery(nil, "test query"))
}

func TestAugmentSearchQuery_EmptyEntries(t *testing.T) {
	p := &Policy{
		Mode:      ModeAllow,
		Addresses: map[string]bool{},
		Domains:   map[string]bool{},
	}
	assert.Equal(t, "test", AugmentSearchQuery(p, "test"))
}
