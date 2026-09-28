//go:build integration

package ncm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pkicmp-ng/client"
	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

func TestNCMEnrollPasswordBasedMac(t *testing.T) {
	cfg := loadConfig(t)
	creds, opts := cfg.macCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		enrollP10CR(t, cfg, cl, cfg.subject(cfg.enrollmentName("mac")), creds, opts...)
	})
}

func TestNCMEnrollSignature(t *testing.T) {
	cfg := loadConfig(t)
	creds := cfg.signatureCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		enrollP10CR(t, cfg, cl, cfg.subject(cfg.enrollmentName("sig")), creds)
	})
}

// NCM answers a second P10CR for an identity it has already certified with a new certificate. This is
// how a client without key update renews.
func TestNCMReenrollP10CR(t *testing.T) {
	cfg := loadConfig(t)
	if !cfg.reenroll {
		t.Skip("NCM_CMP_REENROLL is false")
	}
	creds, opts := cfg.enrollmentCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		subject := cfg.subject(cfg.enrollmentName("reenroll"))
		firstKey, first, _ := enrollP10CR(t, cfg, cl, subject, creds, opts...)
		secondKey, second, _ := enrollP10CR(t, cfg, cl, subject, creds, opts...)

		assert.NotEqual(t, first.SerialNumber, second.SerialNumber, "re-enrollment returned the serial number of the first certificate")
		assert.False(t, firstKey.PublicKey.Equal(&secondKey.PublicKey), "re-enrollment reused the first key")
	})
}

func TestNCMKeyUpdate(t *testing.T) {
	cfg := loadConfig(t)
	if !cfg.kur {
		t.Skip("NCM_CMP_KUR is false")
	}
	creds, opts := cfg.enrollmentCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		keyUpdate(t, cfg, cl, creds, opts, "kur", newKey)
	})
}

// Updating a certificate for the key it already certifies needs a profile that certifies the same key
// twice. The client names the replaced certificate in the CRMF oldCertID control, which NCM needs once
// a key carries more than one certificate.
func TestNCMKeyUpdateSameKey(t *testing.T) {
	cfg := loadConfig(t)
	if !cfg.kurSameKey {
		t.Skip("NCM_CMP_KUR or NCM_CMP_KUR_SAME_KEY is false")
	}
	creds, opts := cfg.enrollmentCredentials(t)

	cfg.forEachTransport(t, func(t *testing.T, cl *client.Client) {
		keyUpdate(t, cfg, cl, creds, opts, "kur-same", nil)
	})
}

// keyUpdate enrolls a certificate through P10CR and updates it through KUR, reusing its key when newKey is nil.
func keyUpdate(t *testing.T, cfg *ncmConfig, cl *client.Client, creds pkicmp.Credentials, opts []client.RequestOption, purpose string, newKey *rsa.PrivateKey) {
	t.Helper()

	// The updated certificate is always a generated identity, because a profile that authorizes only
	// NCM_CMP_COMMON_NAME could not certify it next to the enrollment tests.
	oldKey, oldCert, intermediates := enrollP10CR(t, cfg, cl, cfg.subject(generatedName(purpose)), creds, opts...)
	if newKey == nil {
		newKey = oldKey
	}

	// The certificate being replaced protects the request, so NCM authenticates the update by it
	// rather than by the enrollment credentials.
	oldCreds, err := pkicmp.NewSignatureCredentials(oldKey, oldCert, intermediates...)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), operationTimeout)
	defer cancel()
	result, err := cl.SendKUR(ctx, newKey, oldCreds, client.WithTemplateSubject(oldCert.Subject))
	require.NoError(t, err, "SendKUR")

	// verifyIssued also establishes that the new certificate certifies newKey, which for a same-key
	// update is the key of the certificate it replaces.
	verifyIssued(t, cfg, result, newKey.Public())
	assert.NotEqual(t, oldCert.SerialNumber, result.Certificate.SerialNumber, "key update returned the serial number it replaced")
}
