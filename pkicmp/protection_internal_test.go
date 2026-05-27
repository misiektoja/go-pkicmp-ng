package pkicmp

import (
	"crypto"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func mustMACCreds(secret []byte) *MACCredentials {
	c, _ := NewMACCredentials(secret)
	return c
}

func TestPBMParameterASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		p := pbmParameter{
			Salt:           []byte{0x01, 0x02},
			OWF:            AlgorithmIdentifier{Algorithm: oidSHA256},
			IterationCount: 100,
			MAC:            AlgorithmIdentifier{Algorithm: oidHMACWithSHA256},
		}
		var b cryptobyte.Builder
		p.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled pbmParameter
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.Equal(t, p.IterationCount, unmarshaled.IterationCount)
		assert.Equal(t, p.Salt, unmarshaled.Salt)
	})

	t.Run("RejectsOutOfRangeIterationCount", func(t *testing.T) {
		p := pbmParameter{
			Salt:           []byte{0x01, 0x02},
			OWF:            AlgorithmIdentifier{Algorithm: oidSHA256},
			IterationCount: defaultPBMMaxIterationCount + 1,
			MAC:            AlgorithmIdentifier{Algorithm: oidHMACWithSHA256},
		}
		var b cryptobyte.Builder
		p.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled pbmParameter
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})
}

func TestDerivePBMKey(t *testing.T) {
	k, err := derivePBMKey([]byte("secret"), []byte("salt"), 10, crypto.SHA256, crypto.SHA256)
	assert.NoError(t, err)
	assert.NotEmpty(t, k)
}

func TestValidatePBMIterationCount(t *testing.T) {
	t.Run("TooSmall", func(t *testing.T) {
		err := validatePBMIterationCount(0)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too small")
	})
	t.Run("TooLarge", func(t *testing.T) {
		err := validatePBMIterationCount(defaultPBMMaxIterationCount + 1)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})
	t.Run("Valid", func(t *testing.T) {
		assert.NoError(t, validatePBMIterationCount(1000))
	})
}

func TestProtectWithMACErrors(t *testing.T) {
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{}
		err := msg.protectWithMAC([]byte("secret"))
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
	t.Run("EmptySecret", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMAC([]byte{})
		var pe *ProtectionError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, ReasonMissingSharedSecret, pe.Reason)
	})
	t.Run("UnsupportedOWF", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMACOptions(macOptions{
			Secret:    []byte("secret"),
			Algorithm: oidPasswordBasedMac,
			OWF:       asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("UnsupportedMAC", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMACOptions(macOptions{
			Secret:    []byte("secret"),
			Algorithm: oidPasswordBasedMac,
			MAC:       asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("IterationCountTooLarge", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{Body: body}
		err := msg.protectWithMACOptions(macOptions{
			Secret:         []byte("secret"),
			Algorithm:      oidPasswordBasedMac,
			IterationCount: defaultPBMMaxIterationCount + 1,
		})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})
}

func TestPBMAC1ParameterASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		salt := []byte{0x01, 0x02, 0x03, 0x04}
		params, err := marshalPBMAC1Params(salt, 5000, 32, oidHMACWithSHA256, oidHMACWithSHA256)
		require.NoError(t, err)

		// Unmarshal and verify round-trip.
		var pbmac1Params struct {
			KeyDerivationFunc algorithmIdentifierASN1
			MessageAuthScheme algorithmIdentifierASN1
		}
		_, err = asn1.Unmarshal(params, &pbmac1Params)
		require.NoError(t, err)
		assert.True(t, pbmac1Params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2))
		assert.True(t, pbmac1Params.MessageAuthScheme.Algorithm.Equal(oidHMACWithSHA256))

		var pbkdf2Params struct {
			Salt           []byte
			IterationCount int
			KeyLength      int
			PRF            algorithmIdentifierASN1
		}
		_, err = asn1.Unmarshal(pbmac1Params.KeyDerivationFunc.Parameters.FullBytes, &pbkdf2Params)
		require.NoError(t, err)
		assert.Equal(t, salt, pbkdf2Params.Salt)
		assert.Equal(t, 5000, pbkdf2Params.IterationCount)
		assert.Equal(t, 32, pbkdf2Params.KeyLength)
		assert.True(t, pbkdf2Params.PRF.Algorithm.Equal(oidHMACWithSHA256))
	})
}

func TestProtectWithPBMAC1Errors(t *testing.T) {
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{}
		err := msg.protectWithPBMAC1Options(pbmac1Options{Secret: []byte("secret")})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
	t.Run("EmptySecret", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{Secret: []byte{}})
		var pe *ProtectionError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, ReasonMissingSharedSecret, pe.Reason)
	})
	t.Run("UnsupportedPRF", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{
			Secret: []byte("secret"),
			PRF:    asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("UnsupportedMAC", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{
			Secret: []byte("secret"),
			MAC:    asn1.ObjectIdentifier{1, 2, 3},
		})
		assert.Error(t, err)
	})
	t.Run("IterationCountTooLarge", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		err := msg.protectWithPBMAC1Options(pbmac1Options{
			Secret:         []byte("secret"),
			IterationCount: defaultPBMMaxIterationCount + 1,
		})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "iterationCount too large")
	})
}

func TestProtectWithSignatureErrors(t *testing.T) {
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{}
		err := msg.protectWithSignature(nil, nil)
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
}

func TestPKIMessageProtectedPartErrors(t *testing.T) {
	t.Run("MissingHeader", func(t *testing.T) {
		msg := &PKIMessage{rawBody: []byte{0x01}}
		_, err := msg.protectedPart()
		assert.Error(t, err)
	})
	t.Run("MissingBody", func(t *testing.T) {
		msg := &PKIMessage{rawHeader: []byte{0x01}}
		_, err := msg.protectedPart()
		assert.Error(t, err)
	})
}

func TestVerifyErrors(t *testing.T) {
	t.Run("NoProtectionAlg", func(t *testing.T) {
		msg := &PKIMessage{Body: NewPKIConfBody()}
		_, err := msg.Verify(VerifyOptions{})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "message has no protection algorithm")
	})
	t.Run("EmptyProtection", func(t *testing.T) {
		msg := &PKIMessage{
			Header: PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidPasswordBasedMac}},
			Body:   NewPKIConfBody(),
		}
		_, err := msg.Verify(VerifyOptions{SharedSecret: []byte("s")})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "message is not protected")
	})
	t.Run("NilBody", func(t *testing.T) {
		msg := &PKIMessage{
			Header:     PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidPasswordBasedMac}},
			Protection: []byte{0x01},
		}
		_, err := msg.Verify(VerifyOptions{SharedSecret: []byte("s")})
		var pe *ParseError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Detail, "missing message body")
	})
	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		msg := &PKIMessage{
			Header:     PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}},
			Body:       NewPKIConfBody(),
			Protection: []byte{0x01},
		}
		_, err := msg.Verify(VerifyOptions{})
		var ve *VerificationError
		require.ErrorAs(t, err, &ve)
		assert.Equal(t, ReasonUnsupportedAlgorithm, ve.Reason)
	})
}
