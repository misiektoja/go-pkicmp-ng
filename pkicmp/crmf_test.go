package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// RFC 4211 §3 (CertReqMessages ASN.1 tests)
func TestCertReqMessagesASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		m := CertReqMessages{
			{
				CertReq: CertRequest{
					CertReqID: 1,
					CertTemplate: CertTemplate{
						Subject: NewDirectoryName(pkix.RDNSequence{
							{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test"}},
						}),
					},
				},
			},
		}

		var b cryptobyte.Builder
		m.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled CertReqMessages
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		assert.Len(t, unmarshaled, 1)
		assert.Equal(t, m[0].CertReq.CertReqID, unmarshaled[0].CertReq.CertReqID)
		assert.Equal(t, m[0].CertReq.CertTemplate.Subject.DirectoryName, unmarshaled[0].CertReq.CertTemplate.Subject.DirectoryName)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00})
		var unmarshaled CertReqMessages
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}

func TestCertReqMsgGeneratePOP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	req := CertReqMsg{
		CertReq: CertRequest{
			CertReqID: 1,
			CertTemplate: CertTemplate{
				PublicKey: pubBytes,
			},
		},
	}

	err = req.GeneratePOP(key)
	require.NoError(t, err)
	require.NotNil(t, req.Popo)
	require.NotNil(t, req.Popo.Signature)

	// RFC 4211 §4.1: when poposkInput is omitted, POP signs CertRequest.
	digest := mustPOPSignatureDigest(t, req.CertReq, req.Popo.Signature)

	t.Run("successful validation", func(t *testing.T) {
		valid := ecdsa.VerifyASN1(&key.PublicKey, digest, req.Popo.Signature.Signature)
		assert.True(t, valid, "POP signature verification failed")
	})

	t.Run("negative validation with tampered cert request", func(t *testing.T) {
		tamperedReq := req.CertReq
		tamperedReq.CertReqID++

		tamperedDigest := mustPOPSignatureDigest(t, tamperedReq, req.Popo.Signature)
		valid := ecdsa.VerifyASN1(&key.PublicKey, tamperedDigest, req.Popo.Signature.Signature)
		assert.False(t, valid, "tampered request must fail POP signature verification")
	})

	t.Run("negative validation with wrong key", func(t *testing.T) {
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		valid := ecdsa.VerifyASN1(&wrongKey.PublicKey, digest, req.Popo.Signature.Signature)
		assert.False(t, valid, "verification with wrong key must fail")
	})
}

func mustPOPSignatureDigest(t *testing.T, certReq CertRequest, popSig *POPOSigningKey) []byte {
	t.Helper()

	sigAlg, err := SigAlgFromOID(popSig.Algorithm.Algorithm)
	require.NoError(t, err)

	hash := HashFromSigAlg(sigAlg)
	require.NotEqual(t, crypto.Hash(0), hash)

	mctx := &MarshalContext{MinRequiredPVNO: PVNO2}
	var b cryptobyte.Builder
	certReq.marshal(mctx, &b)
	certReqDER, err := b.Bytes()
	require.NoError(t, err)

	h := hash.New()
	if h == nil {
		t.Fatalf("pkicmp: unsupported hash function for signature algorithm %v", sigAlg)
	}
	if _, err := h.Write(certReqDER); err != nil {
		t.Fatalf("pkicmp: hash CertRequest for POP: %v", err)
	}
	return h.Sum(nil)
}

// RFC 4211 §3 (CertRequest ASN.1 tests)
func TestCertRequestASN1(t *testing.T) {
	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00})
		var unmarshaled CertRequest
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})

	t.Run("InvalidCertReqID", func(t *testing.T) {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// Not an INTEGER
			b.AddASN1OctetString([]byte{0x01})
		})
		marshaled, _ := b.Bytes()
		s := cryptobyte.String(marshaled)
		var unmarshaled CertRequest
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}

// RFC 4211 §2 (CertTemplate ASN.1 tests)
func TestCertTemplateASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshalFull", func(t *testing.T) {
		tmpl := CertTemplate{
			Subject: NewDirectoryName(pkix.RDNSequence{
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test Template"}},
			}),
			PublicKey:  []byte{0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03},
			Extensions: []byte{0x30, 0x03, 0x02, 0x01, 0x01},
		}

		var b cryptobyte.Builder
		tmpl.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled CertTemplate
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		assert.Equal(t, tmpl.PublicKey, unmarshaled.PublicKey)
		assert.Equal(t, tmpl.Extensions, unmarshaled.Extensions)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00})
		var unmarshaled CertTemplate
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}

// RFC 4211 §4 (ProofOfPossession ASN.1 tests)
func TestProofOfPossessionASN1(t *testing.T) {
	t.Run("RAVerified", func(t *testing.T) {
		p := ProofOfPossession{RAVerified: true}
		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled ProofOfPossession
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.True(t, unmarshaled.RAVerified)
	})

	t.Run("RAVerifiedRaw", func(t *testing.T) {
		// Manually create a [0] NULL tag
		s := cryptobyte.String([]byte{0x80, 0x00})
		var unmarshaled ProofOfPossession
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.True(t, unmarshaled.RAVerified)
	})

	t.Run("Signature", func(t *testing.T) {
		p := ProofOfPossession{
			Signature: &POPOSigningKey{
				Algorithm: AlgorithmIdentifier{
					Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
				},
				Signature: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			},
		}
		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled ProofOfPossession
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.Signature)
		assert.Equal(t, p.Signature.Signature, unmarshaled.Signature.Signature)
	})

	t.Run("KeyEnciphermentWithEnvelopedData", func(t *testing.T) {
		p := ProofOfPossession{
			KeyEncipherment: &POPOPrivKey{
				EncryptedKey: &EnvelopedData{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
			},
		}

		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled ProofOfPossession
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.KeyEncipherment.EncryptedKey)
	})

	t.Run("KeyAgreementWithSubsequentMessage", func(t *testing.T) {
		subsequentMessage := int64(0) // encrCert
		p := ProofOfPossession{
			KeyAgreement: &POPOPrivKey{
				SubsequentMessage: &subsequentMessage,
			},
		}

		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled ProofOfPossession
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.KeyAgreement.SubsequentMessage)
	})

	t.Run("UnmarshalUnsupported", func(t *testing.T) {
		// [2] keyEncipherment (not supported yet)
		// Wait, I actually implemented it. Let's trigger a real unsupported one.
		s := cryptobyte.String([]byte{0xbf, 0x1f, 0x00}) // high tag
		var unmarshaled ProofOfPossession
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}

func TestPOPOPrivKeyASN1(t *testing.T) {
	t.Run("EncryptedKey", func(t *testing.T) {
		p := POPOPrivKey{
			EncryptedKey: &EnvelopedData{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		}

		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled POPOPrivKey
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.EncryptedKey)
	})

	t.Run("SubsequentMessage", func(t *testing.T) {
		subsequentMessage := int64(0)
		p := POPOPrivKey{
			SubsequentMessage: &subsequentMessage,
		}
		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled POPOPrivKey
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.SubsequentMessage)
	})

	t.Run("MissingSubsequentMessage", func(t *testing.T) {
		// [1] subsequentMessage but empty content
		s := cryptobyte.String([]byte{0x81, 0x00})
		var unmarshaled POPOPrivKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00})
		var unmarshaled POPOPrivKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})

	t.Run("UnmarshalTruncated", func(t *testing.T) {
		// [1] subsequentMessage but missing integer data
		s := cryptobyte.String([]byte{0x81, 0x01})
		var unmarshaled POPOPrivKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})

	t.Run("UnmarshalUnsupportedVariant", func(t *testing.T) {
		// [3] agreeMAC (not implemented yet)
		s := cryptobyte.String([]byte{0x83, 0x00})
		var unmarshaled POPOPrivKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported POPOPrivKey variant")
	})

	t.Run("UnmarshalDeprecatedVariant", func(t *testing.T) {
		// [0] thisMessage (deprecated, not implemented)
		s := cryptobyte.String([]byte{0x80, 0x00})
		var unmarshaled POPOPrivKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported POPOPrivKey variant")
	})

	t.Run("InvalidTag", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x02, 0x01, 0x01}) // INTEGER
		var unmarshaled POPOPrivKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}

func TestChallengeASN1(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		c := Challenge{
			Witness: []byte{0x01, 0x02},
		}

		var b cryptobyte.Builder
		c.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled Challenge
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.Equal(t, c.Witness, unmarshaled.Witness)
	})

	t.Run("WithEnvelopedDataTriggeringPVNO3", func(t *testing.T) {
		c := Challenge{
			Witness:       []byte{0x01, 0x02},
			EncryptedRand: &EnvelopedData{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		}

		var b cryptobyte.Builder
		c.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled Challenge
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.EncryptedRand)
	})
}

func TestPOPOSigningKeyASN1(t *testing.T) {
	t.Run("WithPoposkInput", func(t *testing.T) {
		gn := NewDirectoryName(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Sender"}}})
		pski := &POPOSigningKeyInput{
			Sender:    &gn,
			PublicKey: []byte{0x30, 0x00},
		}
		psk := &POPOSigningKey{
			PoposkInput: pski,
			Algorithm:   AlgorithmIdentifier{Algorithm: OIDSHA256},
			Signature:   []byte{0x01, 0x02},
		}

		var b cryptobyte.Builder
		psk.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled POPOSigningKey
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.PoposkInput)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00})
		var unmarshaled POPOSigningKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})

	t.Run("InvalidOptionalTags", func(t *testing.T) {
		t.Run("InvalidPoposkInputTag", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// tag [0] but not constructed
				b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddUint8(0x01)
				})
			})
			marshaled, _ := b.Bytes()
			s := cryptobyte.String(marshaled)
			var unmarshaled POPOSigningKey
			err := unmarshaled.unmarshal(&s)
			assert.Error(t, err)
		})

		t.Run("InvalidSignatureBitString", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// Algorithm
				alg := AlgorithmIdentifier{Algorithm: OIDSHA256}
				alg.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, b)
				// Not a BIT STRING
				b.AddASN1Int64(123)
			})
			marshaled, _ := b.Bytes()
			s := cryptobyte.String(marshaled)
			var unmarshaled POPOSigningKey
			err := unmarshaled.unmarshal(&s)
			assert.Error(t, err)
		})
	})
}

// RFC 4211 §4.1 (POPOSigningKeyInput ASN.1 tests)
func TestPOPOSigningKeyInputASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		gn := NewDirectoryName(pkix.RDNSequence{
			{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "POPO Sender"}},
		})
		input := POPOSigningKeyInput{
			Sender:    &gn,
			PublicKey: []byte{0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03},
		}

		var b cryptobyte.Builder
		input.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled POPOSigningKeyInput
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		assert.NotNil(t, unmarshaled.Sender)
		assert.Equal(t, input.PublicKey, unmarshaled.PublicKey)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00})
		var unmarshaled POPOSigningKeyInput
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})

	t.Run("InvalidSenderTag", func(t *testing.T) {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// tag [0] but length is missing/invalid
			b.AddUint8(0xa0)
			b.AddUint8(0xff)
		})
		marshaled, _ := b.Bytes()
		s := cryptobyte.String(marshaled)
		var unmarshaled POPOSigningKeyInput
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})

	t.Run("MissingPublicKey", func(t *testing.T) {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// Empty sequence (no publicKey)
		})
		marshaled, _ := b.Bytes()
		s := cryptobyte.String(marshaled)
		var unmarshaled POPOSigningKeyInput
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}
