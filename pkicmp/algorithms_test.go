package pkicmp

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 9481 §2.1 & §3 (Algorithm mapping tests)
func TestHashFromOID(t *testing.T) {
	// SHA1 is deprecated per RFC 9481 §7.1 but accepted for compatibility.
	t.Run("SHA1-Deprecated", func(t *testing.T) {
		got, err := hashFromOID(oidSHA1)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA1, got)
	})

	t.Run("SHA256", func(t *testing.T) {
		got, err := hashFromOID(oidSHA256)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA256, got)
	})

	t.Run("SHA384", func(t *testing.T) {
		got, err := hashFromOID(oidSHA384)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA384, got)
	})

	t.Run("SHA512", func(t *testing.T) {
		got, err := hashFromOID(oidSHA512)
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
		got, err := hmacHashFromOID(oidHMACWithSHA1)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA1, got)
	})

	t.Run("HMAC-SHA256", func(t *testing.T) {
		got, err := hmacHashFromOID(oidHMACWithSHA256)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA256, got)
	})

	t.Run("HMAC-SHA384", func(t *testing.T) {
		got, err := hmacHashFromOID(oidHMACWithSHA384)
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA384, got)
	})

	t.Run("HMAC-SHA512", func(t *testing.T) {
		got, err := hmacHashFromOID(oidHMACWithSHA512)
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
		got, err := sigAlgFromOID(oidSHA256WithRSAEncryption)
		assert.NoError(t, err)
		assert.Equal(t, x509.SHA256WithRSA, got)
	})

	t.Run("RSA-SHA384", func(t *testing.T) {
		got, err := sigAlgFromOID(oidSHA384WithRSAEncryption)
		assert.NoError(t, err)
		assert.Equal(t, x509.SHA384WithRSA, got)
	})

	t.Run("RSA-SHA512", func(t *testing.T) {
		got, err := sigAlgFromOID(oidSHA512WithRSAEncryption)
		assert.NoError(t, err)
		assert.Equal(t, x509.SHA512WithRSA, got)
	})

	t.Run("ECDSA-SHA256", func(t *testing.T) {
		got, err := sigAlgFromOID(oidECDSAWithSHA256)
		assert.NoError(t, err)
		assert.Equal(t, x509.ECDSAWithSHA256, got)
	})

	t.Run("ECDSA-SHA384", func(t *testing.T) {
		got, err := sigAlgFromOID(oidECDSAWithSHA384)
		assert.NoError(t, err)
		assert.Equal(t, x509.ECDSAWithSHA384, got)
	})

	t.Run("ECDSA-SHA512", func(t *testing.T) {
		got, err := sigAlgFromOID(oidECDSAWithSHA512)
		assert.NoError(t, err)
		assert.Equal(t, x509.ECDSAWithSHA512, got)
	})

	t.Run("Ed25519", func(t *testing.T) {
		got, err := sigAlgFromOID(oidEd25519)
		assert.NoError(t, err)
		assert.Equal(t, x509.PureEd25519, got)
	})

	t.Run("Unsupported", func(t *testing.T) {
		got, err := sigAlgFromOID(asn1.ObjectIdentifier{1, 2, 3})
		assert.Error(t, err)
		assert.Equal(t, x509.UnknownSignatureAlgorithm, got)
	})
}

func TestHashFromSigAlg(t *testing.T) {
	t.Run("RSA-SHA256", func(t *testing.T) {
		assert.Equal(t, crypto.SHA256, hashFromSigAlg(x509.SHA256WithRSA))
	})

	t.Run("ECDSA-SHA256", func(t *testing.T) {
		assert.Equal(t, crypto.SHA256, hashFromSigAlg(x509.ECDSAWithSHA256))
	})

	t.Run("RSA-SHA384", func(t *testing.T) {
		assert.Equal(t, crypto.SHA384, hashFromSigAlg(x509.SHA384WithRSA))
	})

	t.Run("ECDSA-SHA384", func(t *testing.T) {
		assert.Equal(t, crypto.SHA384, hashFromSigAlg(x509.ECDSAWithSHA384))
	})

	t.Run("RSA-SHA512", func(t *testing.T) {
		assert.Equal(t, crypto.SHA512, hashFromSigAlg(x509.SHA512WithRSA))
	})

	t.Run("ECDSA-SHA512", func(t *testing.T) {
		assert.Equal(t, crypto.SHA512, hashFromSigAlg(x509.ECDSAWithSHA512))
	})

	t.Run("Unknown", func(t *testing.T) {
		assert.Equal(t, crypto.Hash(0), hashFromSigAlg(x509.UnknownSignatureAlgorithm))
	})
}

// RFC 9481 §3 pairs EdDSA with SHA-512, which the client and server both need
// for certHash. It is the case a per-package copy of this mapping kept missing.
func TestCertHash(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		assert.Equal(t, crypto.SHA512, hashFromSigAlg(x509.PureEd25519))

		pub, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ed25519"}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		require.Equal(t, x509.PureEd25519, cert.SignatureAlgorithm)

		got, err := CertHash(cert)
		require.NoError(t, err)
		want := sha512.Sum512(cert.Raw)
		assert.Equal(t, want[:], got)
	})

	t.Run("Unknown", func(t *testing.T) {
		_, err := CertHash(&x509.Certificate{SignatureAlgorithm: x509.UnknownSignatureAlgorithm})
		assert.Error(t, err)
	})
}
