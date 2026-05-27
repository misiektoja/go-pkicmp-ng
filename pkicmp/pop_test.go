package pkicmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyPOP(t *testing.T) {
	t.Run("valid POP", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)

		reqMsg := &CertReqMsg{
			CertReq: CertRequest{
				CertReqID: 0,
				CertTemplate: CertTemplate{
					Subject:   NewDirectoryName(pkix.Name{CommonName: "test"}),
					PublicKey: pubDER,
				},
			},
		}
		require.NoError(t, reqMsg.GeneratePOP(key))

		// Round-trip to populate Raw field.
		reqMsg = roundTripCertReqMsg(t, reqMsg)

		err = VerifyPOP(reqMsg)
		assert.NoError(t, err)
	})

	t.Run("invalid POP wrong key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubDER, err := x509.MarshalPKIXPublicKey(&wrongKey.PublicKey)
		require.NoError(t, err)

		reqMsg := &CertReqMsg{
			CertReq: CertRequest{
				CertReqID: 0,
				CertTemplate: CertTemplate{
					Subject:   NewDirectoryName(pkix.Name{CommonName: "test"}),
					PublicKey: pubDER,
				},
			},
		}
		// Sign with key but template has wrongKey's public key.
		require.NoError(t, reqMsg.GeneratePOP(key))

		reqMsg = roundTripCertReqMsg(t, reqMsg)

		err = VerifyPOP(reqMsg)
		assert.Error(t, err)
	})

	t.Run("nil POP is valid", func(t *testing.T) {
		reqMsg := &CertReqMsg{CertReq: CertRequest{CertReqID: 0}}
		assert.NoError(t, VerifyPOP(reqMsg))
	})

	t.Run("raVerified rejected", func(t *testing.T) {
		reqMsg := &CertReqMsg{
			CertReq: CertRequest{CertReqID: 0},
			Popo:    &proofOfPossession{RAVerified: true},
		}
		err := VerifyPOP(reqMsg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "raVerified")
	})

	t.Run("no public key", func(t *testing.T) {
		reqMsg := &CertReqMsg{
			CertReq: CertRequest{CertReqID: 0},
			Popo:    &proofOfPossession{Signature: &popoSigningKey{}},
		}
		err := VerifyPOP(reqMsg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no public key")
	})
}

// roundTripCertReqMsg marshals and unmarshals a CertReqMsg to populate Raw fields.
func roundTripCertReqMsg(t *testing.T, reqMsg *CertReqMsg) *CertReqMsg {
	t.Helper()
	msgs := CertReqMessages{*reqMsg}
	body := NewIRBody(&msgs)
	msg := NewPKIMessage(body, MessageOptions{})
	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := ParsePKIMessage(der)
	require.NoError(t, err)
	ir, err := parsed.Body.IR()
	require.NoError(t, err)
	require.Len(t, *ir, 1)
	result := &(*ir)[0]
	return result
}
