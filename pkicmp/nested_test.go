package pkicmp

import (
	"bytes"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// nestedTestMessage returns the DER of a MAC-protected pkiConf message and the secret protecting it.
func nestedTestMessage(t *testing.T, name string) ([]byte, []byte) {
	t.Helper()
	secret := []byte("nested-test-secret-" + name)
	msg := NewPKIMessage(NewPKIConfBody(), MessageOptions{
		Sender:    NewDirectoryName(pkix.Name{CommonName: name}),
		Recipient: NewDirectoryName(pkix.Name{CommonName: "Test CA"}),
	})
	creds, err := NewMACCredentials(secret)
	require.NoError(t, err)
	require.NoError(t, creds.Protect(msg))
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	return der, secret
}

// nestedDER wraps content in a nested [20] body inside a minimal PKIMessage.
func nestedDER(t *testing.T, content func(b *cryptobyte.Builder)) []byte {
	t.Helper()
	outer := NewPKIMessage(NewPKIConfBody(), MessageOptions{})
	der, err := outer.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(parsed.rawHeader)
		b.AddASN1(cbasn1.Tag(BodyTypeNested), content)
	})
	out, err := b.Bytes()
	require.NoError(t, err)
	return out
}

// RFC 9810 §5.1.3.5 and RFC 4210 §5.1.3.4: NestedMessageContent ::= PKIMessages.
func TestNestedBodyEncodesPKIMessages(t *testing.T) {
	first, _ := nestedTestMessage(t, "first")
	second, _ := nestedTestMessage(t, "second")
	m1, err := ParsePKIMessage(first)
	require.NoError(t, err)
	m2, err := ParsePKIMessage(second)
	require.NoError(t, err)

	outer := NewPKIMessage(NewNestedBody(m1, m2), MessageOptions{})
	der, err := outer.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	require.Equal(t, BodyTypeNested, parsed.Body.Type)

	// [20] holds one SEQUENCE OF PKIMessage, not a bare PKIMessage.
	s := cryptobyte.String(parsed.Body.Raw)
	var content, seq cryptobyte.String
	require.True(t, s.ReadASN1(&content, cbasn1.Tag(BodyTypeNested)))
	require.True(t, content.ReadASN1(&seq, cbasn1.SEQUENCE))
	assert.True(t, content.Empty())
	var elem cryptobyte.String
	require.True(t, seq.ReadASN1Element(&elem, cbasn1.SEQUENCE))
	assert.Equal(t, first, []byte(elem))
	require.True(t, seq.ReadASN1Element(&elem, cbasn1.SEQUENCE))
	assert.Equal(t, second, []byte(elem))
	assert.True(t, seq.Empty())

	msgs, err := parsed.Body.Nested()
	require.NoError(t, err)
	require.Len(t, msgs, 2)
	for i, want := range []string{"first", "second"} {
		var name pkix.Name
		name.FillFromRDNSequence(&msgs[i].Header.Sender.DirectoryName)
		assert.Equal(t, want, name.CommonName)
	}
}

// A received message must keep the bytes its protection covers when forwarded.
func TestNestedBodyKeepsProtectedBytes(t *testing.T) {
	der, secret := nestedTestMessage(t, "device")
	inner, err := ParsePKIMessage(der)
	require.NoError(t, err)

	// Changing a decoded field changes what MarshalBinary would encode, but not
	// the bytes the protection was computed over.
	inner.Header.MessageTime = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

	outer := NewPKIMessage(NewNestedBody(inner), MessageOptions{})
	outerDER, err := outer.MarshalBinary()
	require.NoError(t, err)
	assert.True(t, bytes.Contains(outerDER, der))

	parsed, err := ParsePKIMessage(outerDER)
	require.NoError(t, err)
	msgs, err := parsed.Body.Nested()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	_, err = msgs[0].Verify(VerifyOptions{SharedSecret: secret})
	require.NoError(t, err)
}

// An unprotected message has no protected bytes to keep and is encoded from its fields.
func TestNestedBodyEncodesUnprotectedMessage(t *testing.T) {
	inner := NewPKIMessage(NewPKIConfBody(), MessageOptions{})
	want, err := inner.MarshalBinary()
	require.NoError(t, err)

	outer := NewPKIMessage(NewNestedBody(inner), MessageOptions{})
	der, err := outer.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	msgs, err := parsed.Body.Nested()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	got, err := msgs[0].MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// RFC 9810 §5.1.3.5: PKIMessages is SIZE (1..MAX).
func TestNestedBodyMarshalErrors(t *testing.T) {
	_, err := NewPKIMessage(NewNestedBody(), MessageOptions{}).MarshalBinary()
	assert.Error(t, err)

	_, err = NewPKIMessage(NewNestedBody(nil), MessageOptions{}).MarshalBinary()
	assert.Error(t, err)
}

// Malformed nested bodies, including a PKIMessage placed directly in [20], are rejected.
func TestNestedBodyParseErrors(t *testing.T) {
	inner, _ := nestedTestMessage(t, "device")

	tests := map[string]func(b *cryptobyte.Builder){
		"empty sequence": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(*cryptobyte.Builder) {})
		},
		"bare PKIMessage": func(b *cryptobyte.Builder) {
			b.AddBytes(inner)
		},
		"trailing data": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(inner) })
			b.AddASN1NULL()
		},
		"element not a sequence": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1NULL() })
		},
		"invalid PKIMessage": func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1NULL() })
			})
		},
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			msg, err := ParsePKIMessage(nestedDER(t, content))
			require.NoError(t, err)
			msgs, err := msg.Body.Nested()
			assert.Error(t, err)
			assert.Nil(t, msgs)
		})
	}
}
