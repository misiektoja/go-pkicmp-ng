package pkicmp

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC 9481 §2.1 & §3 (Algorithm mapping tests)
func TestHashFromOID(t *testing.T) {
	// SHA1 is deprecated per RFC 9481 §7.1 but accepted for compatibility.
	t.Run("SHA1-Deprecated", func(t *testing.T) {
		got, err := hashFromOID(OIDSHA1)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA1, got)
	})

	t.Run("SHA256", func(t *testing.T) {
		got, err := hashFromOID(OIDSHA256)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA256, got)
	})

	t.Run("SHA384", func(t *testing.T) {
		got, err := hashFromOID(OIDSHA384)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA384, got)
	})

	t.Run("SHA512", func(t *testing.T) {
		got, err := hashFromOID(OIDSHA512)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA512, got)
	})

	t.Run("Unsupported", func(t *testing.T) {
		_, err := hashFromOID(asn1.ObjectIdentifier{1, 2, 3})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported hash algorithm")
	})
}

// RFC 9481 §6.2.1 (HMAC Mapping tests)
func TestHMACHashFromOID(t *testing.T) {
	// SHA1 is deprecated per RFC 9481 §7.1 but accepted for compatibility.
	t.Run("HMAC-SHA1-Deprecated", func(t *testing.T) {
		got, err := hmacHashFromOID(OIDHMACWithSHA1)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA1, got)
	})

	t.Run("HMAC-SHA256", func(t *testing.T) {
		got, err := hmacHashFromOID(OIDHMACWithSHA256)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA256, got)
	})

	t.Run("HMAC-SHA384", func(t *testing.T) {
		got, err := hmacHashFromOID(OIDHMACWithSHA384)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA384, got)
	})

	t.Run("HMAC-SHA512", func(t *testing.T) {
		got, err := hmacHashFromOID(OIDHMACWithSHA512)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA512, got)
	})

	t.Run("Unsupported", func(t *testing.T) {
		_, err := hmacHashFromOID(asn1.ObjectIdentifier{1, 2, 3})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported HMAC algorithm")
	})
}

// RFC 9481 §3 (Signature Algorithm Mapping tests)
func TestSigAlgFromOID(t *testing.T) {
	t.Run("RSA-SHA256", func(t *testing.T) {
		got, err := SigAlgFromOID(OIDSHA256WithRSAEncryption)
		assert.NoError(t, err)
		assert.Equal(t, x509.SHA256WithRSA, got)
	})

	t.Run("RSA-SHA384", func(t *testing.T) {
		got, err := SigAlgFromOID(OIDSHA384WithRSAEncryption)
		assert.NoError(t, err)
		assert.Equal(t, x509.SHA384WithRSA, got)
	})

	t.Run("RSA-SHA512", func(t *testing.T) {
		got, err := SigAlgFromOID(OIDSHA512WithRSAEncryption)
		assert.NoError(t, err)
		assert.Equal(t, x509.SHA512WithRSA, got)
	})

	t.Run("ECDSA-SHA256", func(t *testing.T) {
		got, err := SigAlgFromOID(OIDECDSAWithSHA256)
		assert.NoError(t, err)
		assert.Equal(t, x509.ECDSAWithSHA256, got)
	})

	t.Run("ECDSA-SHA384", func(t *testing.T) {
		got, err := SigAlgFromOID(OIDECDSAWithSHA384)
		assert.NoError(t, err)
		assert.Equal(t, x509.ECDSAWithSHA384, got)
	})

	t.Run("ECDSA-SHA512", func(t *testing.T) {
		got, err := SigAlgFromOID(OIDECDSAWithSHA512)
		assert.NoError(t, err)
		assert.Equal(t, x509.ECDSAWithSHA512, got)
	})

	t.Run("Ed25519", func(t *testing.T) {
		got, err := SigAlgFromOID(OIDEd25519)
		assert.NoError(t, err)
		assert.Equal(t, x509.PureEd25519, got)
	})

	t.Run("Unsupported", func(t *testing.T) {
		got, err := SigAlgFromOID(asn1.ObjectIdentifier{1, 2, 3})
		assert.Error(t, err)
		assert.Equal(t, x509.UnknownSignatureAlgorithm, got)
	})
}

func TestHashFromSigAlg(t *testing.T) {
	t.Run("RSA-SHA256", func(t *testing.T) {
		assert.Equal(t, crypto.SHA256, HashFromSigAlg(x509.SHA256WithRSA))
	})

	t.Run("ECDSA-SHA256", func(t *testing.T) {
		assert.Equal(t, crypto.SHA256, HashFromSigAlg(x509.ECDSAWithSHA256))
	})

	t.Run("RSA-SHA384", func(t *testing.T) {
		assert.Equal(t, crypto.SHA384, HashFromSigAlg(x509.SHA384WithRSA))
	})

	t.Run("ECDSA-SHA384", func(t *testing.T) {
		assert.Equal(t, crypto.SHA384, HashFromSigAlg(x509.ECDSAWithSHA384))
	})

	t.Run("RSA-SHA512", func(t *testing.T) {
		assert.Equal(t, crypto.SHA512, HashFromSigAlg(x509.SHA512WithRSA))
	})

	t.Run("ECDSA-SHA512", func(t *testing.T) {
		assert.Equal(t, crypto.SHA512, HashFromSigAlg(x509.ECDSAWithSHA512))
	})

	t.Run("Unknown", func(t *testing.T) {
		assert.Equal(t, crypto.Hash(0), HashFromSigAlg(x509.UnknownSignatureAlgorithm))
	})
}
