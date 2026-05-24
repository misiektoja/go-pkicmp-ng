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

func mustCreds(secret []byte) *pkicmp.MACCredentials {
	c, _ := pkicmp.NewMACCredentials(secret)
	return c
}

func TestPBMRoundTrip(t *testing.T) {
	secret := []byte("shared-secret")

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	err := msg.ProtectWithMAC(secret)
	require.NoError(t, err)

	assert.Equal(t, pkicmp.OIDPasswordBasedMac, msg.Header.ProtectionAlg.Algorithm)
	assert.NotEmpty(t, msg.Protection)

	// Round-trip through marshaling.
	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{Credentials: mustCreds(secret)})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMCustomOptions(t *testing.T) {
	secret := []byte("custom-secret")

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	err := msg.ProtectWithMACOptions(pkicmp.MACOptions{
		Secret:         secret,
		Algorithm:      pkicmp.OIDPasswordBasedMac,
		IterationCount: 5000,
		OWF:            pkicmp.OIDSHA512,
		MAC:            pkicmp.OIDHMACWithSHA512,
	})
	require.NoError(t, err)

	assert.Equal(t, pkicmp.OIDPasswordBasedMac, msg.Header.ProtectionAlg.Algorithm)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{Credentials: mustCreds(secret)})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMAC1RoundTrip(t *testing.T) {
	secret := []byte("shared-secret")

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	err := msg.ProtectWithPBMAC1(secret)
	require.NoError(t, err)

	assert.Equal(t, pkicmp.OIDPBMAC1, msg.Header.ProtectionAlg.Algorithm)
	assert.NotEmpty(t, msg.Protection)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{Credentials: mustCreds(secret)})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMAC1CustomOptions(t *testing.T) {
	secret := []byte("custom-secret")

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	err := msg.ProtectWithPBMAC1Options(pkicmp.PBMAC1Options{
		Secret:         secret,
		IterationCount: 5000,
		PRF:            pkicmp.OIDHMACWithSHA512,
		MAC:            pkicmp.OIDHMACWithSHA512,
	})
	require.NoError(t, err)

	assert.Equal(t, pkicmp.OIDPBMAC1, msg.Header.ProtectionAlg.Algorithm)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{Credentials: mustCreds(secret)})
	require.NoError(t, err)
	assert.True(t, vr.MACVerified)
}

func TestPBMAC1WrongSecret(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	require.NoError(t, msg.ProtectWithPBMAC1([]byte("correct-secret")))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{Credentials: mustCreds([]byte("wrong-secret"))})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)
}

func TestSignatureRoundTrip(t *testing.T) {
	caKey, caCert, signerKey, signerCert := generateCAAndSigner(t)
	_ = caKey

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	err := msg.ProtectWithSignature(signerKey, signerCert)
	require.NoError(t, err)

	der, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(caCert)

	vr, err := parsed.Verify(pkicmp.VerifyOptions{
		TrustPool:  trustedCAs,
		ExtraCerts: parsed.ExtraCerts,
		SenderKID:  parsed.Header.SenderKID,
	})
	require.NoError(t, err)
	assert.False(t, vr.MACVerified)
}

func TestSignatureAutoPopulatesExtraCerts(t *testing.T) {
	caKey, caCert, signerKey, signerCert := generateCAAndSigner(t)
	_ = caKey

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	// Provide an intermediate in the chain.
	err := msg.ProtectWithSignature(signerKey, signerCert, caCert)
	require.NoError(t, err)

	// ExtraCerts should contain signerCert + caCert.
	assert.Len(t, msg.ExtraCerts, 2)
	assert.Equal(t, signerCert.Raw, msg.ExtraCerts[0].Raw)
	assert.Equal(t, caCert.Raw, msg.ExtraCerts[1].Raw)
}

func TestSignatureSetsHeaderSenderKID(t *testing.T) {
	_, _, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	err := msg.ProtectWithSignature(signerKey, signerCert)
	require.NoError(t, err)

	assert.Equal(t, signerCert.SubjectKeyId, msg.Header.SenderKID)
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	require.NoError(t, msg.ProtectWithMAC([]byte("correct-secret")))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{Credentials: mustCreds([]byte("wrong-secret"))})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)
}

func TestVerifyRejectsUntrustedCA(t *testing.T) {
	_, _, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	require.NoError(t, msg.ProtectWithSignature(signerKey, signerCert))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	// Use a different CA as trust anchor.
	otherCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCACert := selfSignedCA(t, otherCAKey, "Other CA")
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(otherCACert)

	_, err = parsed.Verify(pkicmp.VerifyOptions{
		TrustPool:  trustedCAs,
		ExtraCerts: parsed.ExtraCerts,
		SenderKID:  parsed.Header.SenderKID,
	})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonSignatureFailed, ve.Reason)
}

func TestVerifyRejectsNoProtection(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})

	_, err := msg.Verify(pkicmp.VerifyOptions{Credentials: mustCreds([]byte("secret"))})
	var pe *pkicmp.ParseError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Detail, "message has no protection algorithm")
}

func TestVerifyRejectsMissingSharedSecret(t *testing.T) {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	require.NoError(t, msg.ProtectWithMAC([]byte("secret")))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingSharedSecret, ve.Reason)
}

func TestVerifyRejectsMissingTrustPool(t *testing.T) {
	_, _, signerKey, signerCert := generateCAAndSigner(t)

	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
	require.NoError(t, msg.ProtectWithSignature(signerKey, signerCert))

	der, err := msg.MarshalBinary()
	require.NoError(t, err)
	parsed, err := pkicmp.ParsePKIMessage(der)
	require.NoError(t, err)

	_, err = parsed.Verify(pkicmp.VerifyOptions{
		ExtraCerts: parsed.ExtraCerts,
	})
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingTrustAnchors, ve.Reason)
}

func TestVerifyResultMACVerified(t *testing.T) {
	t.Run("TrueForMAC", func(t *testing.T) {
		body := pkicmp.NewPKIConfBody()
		msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
		require.NoError(t, msg.ProtectWithMAC([]byte("secret")))

		der, _ := msg.MarshalBinary()
		parsed, _ := pkicmp.ParsePKIMessage(der)

		vr, err := parsed.Verify(pkicmp.VerifyOptions{Credentials: mustCreds([]byte("secret"))})
		require.NoError(t, err)
		assert.True(t, vr.MACVerified)
	})

	t.Run("FalseForSignature", func(t *testing.T) {
		caKey, caCert, signerKey, signerCert := generateCAAndSigner(t)
		_ = caKey

		body := pkicmp.NewPKIConfBody()
		msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{})
		require.NoError(t, msg.ProtectWithSignature(signerKey, signerCert))

		der, _ := msg.MarshalBinary()
		parsed, _ := pkicmp.ParsePKIMessage(der)

		trustedCAs := x509.NewCertPool()
		trustedCAs.AddCert(caCert)

		vr, err := parsed.Verify(pkicmp.VerifyOptions{
			TrustPool:  trustedCAs,
			ExtraCerts: parsed.ExtraCerts,
			SenderKID:  parsed.Header.SenderKID,
		})
		require.NoError(t, err)
		assert.False(t, vr.MACVerified)
	})
}

func TestTrustedCAPubs(t *testing.T) {
	// Create a fake CA cert for caPubs.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caCert := selfSignedCA(t, caKey, "CAPubs CA")

	rep := &pkicmp.CertRepMessage{
		CAPubs:   []pkicmp.CMPCertificate{{Raw: caCert.Raw}},
		Response: []pkicmp.CertResponse{{CertReqID: 0, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}}},
	}

	t.Run("ReturnsCertsWhenMACVerified", func(t *testing.T) {
		vr := &pkicmp.VerifyResult{MACVerified: true}
		certs := rep.TrustedCAPubs(vr)
		require.Len(t, certs, 1)
		assert.Equal(t, caCert.Raw, certs[0].Raw)
	})

	t.Run("ReturnsNilWhenNotMACVerified", func(t *testing.T) {
		vr := &pkicmp.VerifyResult{MACVerified: false}
		certs := rep.TrustedCAPubs(vr)
		assert.Nil(t, certs)
	})

	t.Run("ReturnsNilWhenVerifyResultNil", func(t *testing.T) {
		certs := rep.TrustedCAPubs(nil)
		assert.Nil(t, certs)
	})
}

// --- helpers ---

func generateCAAndSigner(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caCert := selfSignedCA(t, caKey, "Test CA")

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Signer"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		SubjectKeyId:          []byte{0xAA, 0xBB, 0xCC},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, caCert, &signerKey.PublicKey, caKey)
	require.NoError(t, err)
	signerCert, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)

	return caKey, caCert, signerKey, signerCert
}

func selfSignedCA(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
