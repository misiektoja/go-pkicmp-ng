package pkicmp

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func TestProtectionVerifierRouter(t *testing.T) {
	t.Run("PBM", func(t *testing.T) {
		v, err := ProtectionVerifier(AlgorithmIdentifier{Algorithm: OIDPasswordBasedMac})
		assert.NoError(t, err)
		assert.IsType(t, &pbmVerifier{}, v)
	})
	t.Run("Signature", func(t *testing.T) {
		v, err := ProtectionVerifier(AlgorithmIdentifier{Algorithm: OIDSHA256WithRSAEncryption})
		assert.NoError(t, err)
		assert.IsType(t, &signatureVerifier{}, v)
	})
	t.Run("Unsupported", func(t *testing.T) {
		_, err := ProtectionVerifier(AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}})
		assert.Error(t, err)
	})
}

func TestPBMParameterASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		p := PBMParameter{
			Salt:           []byte{0x01, 0x02},
			OWF:            AlgorithmIdentifier{Algorithm: OIDSHA256},
			IterationCount: 100,
			MAC:            AlgorithmIdentifier{Algorithm: OIDHMACWithSHA256},
		}
		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled PBMParameter
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.Equal(t, p.IterationCount, unmarshaled.IterationCount)
		assert.Equal(t, p.Salt, unmarshaled.Salt)
	})

	t.Run("RejectsOutOfRangeIterationCount", func(t *testing.T) {
		p := PBMParameter{
			Salt:           []byte{0x01, 0x02},
			OWF:            AlgorithmIdentifier{Algorithm: OIDSHA256},
			IterationCount: DefaultPBMMaxIterationCount + 1,
			MAC:            AlgorithmIdentifier{Algorithm: OIDHMACWithSHA256},
		}
		var b cryptobyte.Builder
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled PBMParameter
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "iterationCount too large")
	})
}

func TestDerivePBMKey(t *testing.T) {
	k := derivePBMKey([]byte("secret"), []byte("salt"), 10, crypto.SHA256)
	assert.NotEmpty(t, k)
}

func TestPBMVerifierErrors(t *testing.T) {
	t.Run("SecretNotSet", func(t *testing.T) {
		v := &pbmVerifier{}
		err := v.Verify([]byte("data"), []byte("prot"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shared secret not set")
	})
	t.Run("InvalidParams", func(t *testing.T) {
		v := &pbmVerifier{secret: []byte("secret")}
		v.alg.Parameters = []byte{0x00} // Not a sequence
		err := v.Verify([]byte("data"), []byte("prot"))
		assert.Error(t, err)
	})
}

func TestSignatureVerifierErrors(t *testing.T) {
	t.Run("UnsupportedAlg", func(t *testing.T) {
		v := &signatureVerifier{alg: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}}
		err := v.Verify([]byte("data"), []byte("prot"))
		assert.Error(t, err)
	})
	t.Run("NoCerts", func(t *testing.T) {
		v := &signatureVerifier{alg: AlgorithmIdentifier{Algorithm: OIDSHA256WithRSAEncryption}}
		err := v.Verify([]byte("data"), []byte("prot"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})
}

type errorSigner struct{}

func (s *errorSigner) Public() crypto.PublicKey { return nil }
func (s *errorSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("sign error")
}

func TestSignatureProtectorErrors(t *testing.T) {
	t.Run("SignError", func(t *testing.T) {
		p := &signatureProtector{
			signer: &errorSigner{},
			alg:    AlgorithmIdentifier{Algorithm: OIDSHA256WithRSAEncryption},
		}
		_, err := p.Protect([]byte("data"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sign error")
	})
	t.Run("UnsupportedAlg", func(t *testing.T) {
		p := &signatureProtector{
			alg: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		}
		_, err := p.Protect([]byte("data"))
		assert.Error(t, err)
	})
}

func TestVerifyPBMErrorCases(t *testing.T) {
	data := []byte("data")
	prot := []byte("prot")
	secret := []byte("secret")

	t.Run("UnsupportedOWF", func(t *testing.T) {
		p := PBMParameter{OWF: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}}
		err := verifyPBM(data, prot, secret, p)
		assert.Error(t, err)
	})
	t.Run("UnsupportedMAC", func(t *testing.T) {
		p := PBMParameter{
			OWF: AlgorithmIdentifier{Algorithm: OIDSHA256},
			MAC: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		}
		err := verifyPBM(data, prot, secret, p)
		assert.Error(t, err)
	})

	t.Run("UnavailableMAC", func(t *testing.T) {
		// Mock a parameter with a known but unavailable MAC algorithm
		// We'll skip this as it's hard to trigger without modifying algorithms.go
	})

	t.Run("IterationCountTooLarge", func(t *testing.T) {
		p := PBMParameter{
			OWF:            AlgorithmIdentifier{Algorithm: OIDSHA256},
			MAC:            AlgorithmIdentifier{Algorithm: OIDHMACWithSHA256},
			IterationCount: DefaultPBMMaxIterationCount + 1,
		}
		err := verifyPBM(data, prot, secret, p)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "iterationCount too large")
	})
}

func TestNewPBMProtectorIterationBounds(t *testing.T) {
	_, err := NewPBMProtector([]byte("secret"), []byte("saltsalt"), 0, OIDSHA256, OIDHMACWithSHA256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iterationCount too small")

	_, err = NewPBMProtector([]byte("secret"), []byte("saltsalt"), DefaultPBMMaxIterationCount+1, OIDSHA256, OIDHMACWithSHA256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iterationCount too large")
}

func TestNewPBMProtectorSaltValidation(t *testing.T) {
	t.Run("RejectsEmptySalt", func(t *testing.T) {
		_, err := NewPBMProtector([]byte("secret"), []byte{}, 1000, OIDSHA256, OIDHMACWithSHA256)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "salt too short")
	})
	t.Run("RejectsShortSalt", func(t *testing.T) {
		_, err := NewPBMProtector([]byte("secret"), []byte("short"), 1000, OIDSHA256, OIDHMACWithSHA256)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "salt too short")
	})
	t.Run("AcceptsMinimumSalt", func(t *testing.T) {
		_, err := NewPBMProtector([]byte("secret"), []byte("12345678"), 1000, OIDSHA256, OIDHMACWithSHA256)
		assert.NoError(t, err)
	})
}

func TestNewPBMProtectorAlgorithmValidation(t *testing.T) {
	t.Run("RejectsUnknownOWF", func(t *testing.T) {
		_, err := NewPBMProtector([]byte("secret"), []byte("saltsalt"), 1000, asn1.ObjectIdentifier{1, 2, 3}, OIDHMACWithSHA256)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported hash algorithm")
	})
	t.Run("RejectsUnknownMAC", func(t *testing.T) {
		_, err := NewPBMProtector([]byte("secret"), []byte("saltsalt"), 1000, OIDSHA256, asn1.ObjectIdentifier{1, 2, 3})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported HMAC algorithm")
	})
}

func TestMACProtectorErrorCases(t *testing.T) {
	t.Run("InvalidParams", func(t *testing.T) {
		p := &pbmProtector{alg: AlgorithmIdentifier{Parameters: []byte{0x00}}}
		_, err := p.Protect([]byte("data"))
		assert.Error(t, err)
	})

	t.Run("UnsupportedOWF", func(t *testing.T) {
		params := PBMParameter{OWF: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}}
		var b cryptobyte.Builder
		params.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		pder, _ := b.Bytes()
		p := &pbmProtector{alg: AlgorithmIdentifier{Parameters: pder}}
		_, err := p.Protect([]byte("data"))
		assert.Error(t, err)
	})

	t.Run("UnsupportedMAC", func(t *testing.T) {
		params := PBMParameter{
			OWF: AlgorithmIdentifier{Algorithm: OIDSHA256},
			MAC: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		}
		var b cryptobyte.Builder
		params.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		pder, _ := b.Bytes()
		p := &pbmProtector{alg: AlgorithmIdentifier{Parameters: pder}}
		_, err := p.Protect([]byte("data"))
		assert.Error(t, err)
	})
}

func TestPKIMessageProtectedPartErrors(t *testing.T) {
	t.Run("MissingHeader", func(t *testing.T) {
		msg := &PKIMessage{RawBody: []byte{0x01}}
		_, err := msg.protectedPart()
		assert.Error(t, err)
	})
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{RawHeader: []byte{0x01}}
		_, err := msg.protectedPart()
		assert.Error(t, err)
	})
}
