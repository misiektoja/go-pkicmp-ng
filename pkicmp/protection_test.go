package pkicmp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/go-pkicmp/pkicmp"
)

func TestPBMRoundTrip(t *testing.T) {
	secret := []byte("shared-secret")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	protector, err := pkicmp.NewPBMProtector(
		secret,
		salt,
		1024,
		pkicmp.OIDSHA256,
		pkicmp.OIDHMACWithSHA256,
	)
	require.NoError(t, err)

	body, err := pkicmp.NewPKIConfBody()
	require.NoError(t, err)

	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			TransactionID: []byte("trans-1"),
		},
		Body: body,
	}

	err = msg.Protect(protector)
	require.NoError(t, err)

	// Verify protection algorithm is set correctly
	assert.Equal(t, pkicmp.OIDPasswordBasedMac, msg.Header.ProtectionAlg.Algorithm)

	// Round-trip through marshaling
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	// Verify using Verifier
	verifier, err := pkicmp.ProtectionVerifier(*parsed.Header.ProtectionAlg)
	require.NoError(t, err)

	macVerifier, ok := verifier.(pkicmp.MACVerifier)
	require.True(t, ok)
	macVerifier.SetSharedSecret(secret)

	err = parsed.Verify(macVerifier)
	assert.NoError(t, err)

	// Verify that tampering with header bytes fails
	parsed.RawHeader[len(parsed.RawHeader)-1] ^= 0xFF
	err = parsed.Verify(macVerifier)
	assert.Error(t, err, "verification must fail if header bytes are tampered")

	// Verify with wrong secret fails
	macVerifier.SetSharedSecret([]byte("wrong-secret"))
	err = parsed.Verify(macVerifier)
	assert.Error(t, err)
}

func TestPBMVerificationErrors(t *testing.T) {
	secret := []byte("shared-secret")
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	protector, _ := pkicmp.NewPBMProtector(secret, salt, 1024, pkicmp.OIDSHA256, pkicmp.OIDHMACWithSHA256)
	body, _ := pkicmp.NewPKIConfBody()
	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{TransactionID: []byte("trans-1")},
		Body:   body,
	}
	_ = msg.Protect(protector)

	t.Run("RejectsTruncatedMAC", func(t *testing.T) {
		msg.Protection = msg.Protection[:len(msg.Protection)/2]
		verifier, _ := pkicmp.ProtectionVerifier(*msg.Header.ProtectionAlg)
		verifier.(pkicmp.MACVerifier).SetSharedSecret(secret)
		assert.Error(t, msg.Verify(verifier))
	})

	t.Run("RejectsExtendedMAC", func(t *testing.T) {
		_ = msg.Protect(protector) // Re-protect
		msg.Protection = append(msg.Protection, 0xFF, 0xFF)
		verifier, _ := pkicmp.ProtectionVerifier(*msg.Header.ProtectionAlg)
		verifier.(pkicmp.MACVerifier).SetSharedSecret(secret)
		assert.Error(t, msg.Verify(verifier))
	})

	t.Run("RejectsEmptyProtection", func(t *testing.T) {
		_ = msg.Protect(protector) // Re-protect
		msg.Protection = []byte{}
		verifier, _ := pkicmp.ProtectionVerifier(*msg.Header.ProtectionAlg)
		verifier.(pkicmp.MACVerifier).SetSharedSecret(secret)
		assert.Error(t, msg.Verify(verifier))
	})

	t.Run("RejectsEmptySecret", func(t *testing.T) {
		_ = msg.Protect(protector) // Re-protect
		verifier, _ := pkicmp.ProtectionVerifier(*msg.Header.ProtectionAlg)
		verifier.(pkicmp.MACVerifier).SetSharedSecret([]byte{})
		assert.Error(t, msg.Verify(verifier))
	})
}

func TestSignatureRoundTrip(t *testing.T) {
	// 1. Setup keys and cert
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Signer",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// 2. Setup protector
	protector, err := pkicmp.NewSignatureProtector(priv, cert)
	require.NoError(t, err)

	body, err := pkicmp.NewPKIConfBody()
	require.NoError(t, err)

	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{
			TransactionID: []byte("trans-sig"),
		},
		Body: body,
	}

	err = msg.Protect(protector)
	require.NoError(t, err)

	// 3. Marshal and Parse
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	// 4. Verify
	verifier, err := pkicmp.ProtectionVerifier(*parsed.Header.ProtectionAlg)
	require.NoError(t, err)

	sigVerifier, ok := verifier.(pkicmp.SignatureVerifier)
	require.True(t, ok)
	sigVerifier.SetTrustedCerts([]pkicmp.CMPCertificate{{Raw: cert.Raw}})

	err = parsed.Verify(sigVerifier)
	assert.NoError(t, err)
}

func TestSignatureVerificationErrors(t *testing.T) {
	// Setup CA and signer
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Signer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	signerDER, _ := x509.CreateCertificate(rand.Reader, &signerTemplate, &caTemplate, &signerKey.PublicKey, caKey)
	signerCert, _ := x509.ParseCertificate(signerDER)

	body, _ := pkicmp.NewPKIConfBody()
	msg := &pkicmp.PKIMessage{
		Header: pkicmp.PKIHeader{TransactionID: []byte("trans-sig")},
		Body:   body,
	}
	protector, _ := pkicmp.NewSignatureProtector(signerKey, signerCert)
	_ = msg.Protect(protector)

	t.Run("RejectsWrongKey", func(t *testing.T) {
		wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		wrongProtector, _ := pkicmp.NewSignatureProtector(wrongKey, signerCert)
		_ = msg.Protect(wrongProtector)

		verifier, _ := pkicmp.ProtectionVerifier(*msg.Header.ProtectionAlg)
		sv := verifier.(pkicmp.SignatureVerifier)
		sv.SetTrustedCerts([]pkicmp.CMPCertificate{{Raw: signerCert.Raw}})
		roots := x509.NewCertPool()
		roots.AddCert(caCert)
		sv.SetTrustPool(roots)

		assert.Error(t, msg.Verify(verifier))
	})

	t.Run("RejectsUntrustedCA", func(t *testing.T) {
		_ = msg.Protect(protector) // Re-protect with correct key

		otherCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherCATemplate := x509.Certificate{
			SerialNumber:          big.NewInt(99),
			Subject:               pkix.Name{CommonName: "Other CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		otherCADER, _ := x509.CreateCertificate(rand.Reader, &otherCATemplate, &otherCATemplate, &otherCAKey.PublicKey, otherCAKey)
		otherCACert, _ := x509.ParseCertificate(otherCADER)

		verifier, _ := pkicmp.ProtectionVerifier(*msg.Header.ProtectionAlg)
		sv := verifier.(pkicmp.SignatureVerifier)
		sv.SetTrustedCerts([]pkicmp.CMPCertificate{{Raw: signerCert.Raw}})
		roots := x509.NewCertPool()
		roots.AddCert(otherCACert) // Wrong CA
		sv.SetTrustPool(roots)

		assert.Error(t, msg.Verify(verifier))
	})

	t.Run("RejectsExpiredCert", func(t *testing.T) {
		expiredTemplate := x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "Expired"},
			NotBefore:    time.Now().Add(-2 * time.Hour),
			NotAfter:     time.Now().Add(-1 * time.Hour),
		}
		expiredDER, _ := x509.CreateCertificate(rand.Reader, &expiredTemplate, &caTemplate, &signerKey.PublicKey, caKey)
		expiredCert, _ := x509.ParseCertificate(expiredDER)

		expiredProtector, _ := pkicmp.NewSignatureProtector(signerKey, expiredCert)
		_ = msg.Protect(expiredProtector)

		verifier, _ := pkicmp.ProtectionVerifier(*msg.Header.ProtectionAlg)
		sv := verifier.(pkicmp.SignatureVerifier)
		sv.SetTrustedCerts([]pkicmp.CMPCertificate{{Raw: expiredCert.Raw}})
		roots := x509.NewCertPool()
		roots.AddCert(caCert)
		sv.SetTrustPool(roots)

		assert.Error(t, msg.Verify(verifier))
	})
}
