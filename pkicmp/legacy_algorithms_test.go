package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- builds deprecated SHA-1 signatures that must be refused by default
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// WithPBMAlgorithms selects the PasswordBasedMac OWF and MAC, including the
// RFC 4210 Appendix D.2 SHA-1 profile. The result verifies.
func TestWithPBMAlgorithms(t *testing.T) {
	secret := []byte("pbm-algorithms-secret")
	for _, tc := range []struct {
		name     string
		owf, mac crypto.Hash
		wantOWF  asn1.ObjectIdentifier
		wantMAC  asn1.ObjectIdentifier
	}{
		{"RFC4210SHA1", crypto.SHA1, crypto.SHA1, oidSHA1, oidPBMMac_HMACSHA1},
		{"SHA256OWFWithHMACSHA1", crypto.SHA256, crypto.SHA1, oidSHA256, oidPBMMac_HMACSHA1},
		{"SHA224", crypto.SHA224, crypto.SHA224, oidSHA224, oidHMACWithSHA224},
		{"SHA384", crypto.SHA384, crypto.SHA384, oidSHA384, oidHMACWithSHA384},
		{"SHA512", crypto.SHA512, crypto.SHA512, oidSHA512, oidHMACWithSHA512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := NewMACCredentials(secret, WithPBMAlgorithms(tc.owf, tc.mac))
			require.NoError(t, err)
			msg := NewPKIMessage(NewPKIConfBody(), MessageOptions{})
			require.NoError(t, creds.Protect(msg))

			der, err := msg.MarshalBinary()
			require.NoError(t, err)
			parsed, err := ParsePKIMessage(der)
			require.NoError(t, err)
			require.True(t, parsed.Header.ProtectionAlg.Algorithm.Equal(oidPasswordBasedMac))
			var params pbmParameter
			s := cryptobyte.String(parsed.Header.ProtectionAlg.Parameters)
			require.NoError(t, params.unmarshal(&s))
			assert.True(t, params.OWF.Algorithm.Equal(tc.wantOWF), "OWF %v", params.OWF.Algorithm)
			assert.True(t, params.MAC.Algorithm.Equal(tc.wantMAC), "MAC %v", params.MAC.Algorithm)

			_, err = parsed.Verify(VerifyOptions{SharedSecret: secret})
			assert.NoError(t, err)
		})
	}
}

// An unsupported hash or a MAC longer than the OWF output fails when the credentials are created.
func TestWithPBMAlgorithmsRejectsUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name     string
		owf, mac crypto.Hash
	}{
		{"MD5OWF", crypto.MD5, crypto.SHA256},
		{"MD5MAC", crypto.SHA256, crypto.MD5},
		{"MACLongerThanOWF", crypto.SHA1, crypto.SHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := NewMACCredentials([]byte("secret"), WithPBMAlgorithms(tc.owf, tc.mac))
			assert.Nil(t, creds)
			var pe *ProtectionError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, ReasonUnsupportedAlgorithm, pe.Reason)
		})
	}
}

// A PasswordBasedMac OWF the library does not implement is reported as an unsupported algorithm.
func TestVerifyPBMUnsupportedOWF(t *testing.T) {
	params := pbmParameter{
		Salt:           make([]byte, 16),
		OWF:            AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}},
		IterationCount: 1000,
		MAC:            AlgorithmIdentifier{Algorithm: oidPBMMac_HMACSHA1},
	}
	var b cryptobyte.Builder
	params.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
	der, err := b.Bytes()
	require.NoError(t, err)
	msg := &PKIMessage{
		Header:     PKIHeader{ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidPasswordBasedMac, Parameters: der}},
		Body:       NewPKIConfBody(),
		Protection: []byte{0x01},
	}

	_, err = msg.Verify(VerifyOptions{SharedSecret: []byte("secret")})
	var ve *VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, ReasonUnsupportedAlgorithm, ve.Reason)
}

// sha1Signer signs a digest the way sha1WithRSAEncryption or ecdsa-with-SHA1 requires.
type sha1Signer struct {
	key crypto.Signer
	oid asn1.ObjectIdentifier
}

// sha1TestSigners returns an RSA and an ECDSA key with their SHA-1 signature algorithms.
func sha1TestSigners(t *testing.T) map[string]sha1Signer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return map[string]sha1Signer{
		"sha1WithRSAEncryption": {key: rsaKey, oid: oidSHA1WithRSAEncryption},
		"ecdsa-with-SHA1":       {key: ecKey, oid: oidECDSAWithSHA1},
	}
}

// sign returns a SHA-1 signature over data.
func (s sha1Signer) sign(t *testing.T, data []byte) []byte {
	t.Helper()
	digest := sha1.Sum(data) // #nosec G401 -- the point of the test
	sig, err := s.key.Sign(rand.Reader, digest[:], crypto.SHA1)
	require.NoError(t, err)
	return sig
}

// SHA-1 message signatures are refused unless AllowSHA1Signatures is set.
func TestVerifySHA1SignatureOptIn(t *testing.T) {
	for name, signer := range sha1TestSigners(t) {
		t.Run(name, func(t *testing.T) {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "legacy-device"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
			}
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.key.Public(), signer.key)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(certDER)
			require.NoError(t, err)

			msg := NewPKIMessage(NewPKIConfBody(), MessageOptions{Sender: NewDirectoryNameFromRawDER(cert.RawSubject)})
			msg.Header.ProtectionAlg = &AlgorithmIdentifier{Algorithm: signer.oid}
			require.NoError(t, msg.marshalForProtection())
			data, err := msg.protectedPart()
			require.NoError(t, err)
			msg.Protection = signer.sign(t, data)

			_, err = msg.Verify(VerifyOptions{TrustedCert: cert})
			var ve *VerificationError
			require.ErrorAs(t, err, &ve)
			assert.Equal(t, ReasonUnsupportedAlgorithm, ve.Reason)

			_, err = msg.Verify(VerifyOptions{TrustedCert: cert, AllowSHA1Signatures: true})
			assert.NoError(t, err)
		})
	}
}

// SHA-1 proof of possession signatures are refused unless AllowSHA1Signatures is set.
func TestVerifyPOPWithOptionsSHA1(t *testing.T) {
	for name, signer := range sha1TestSigners(t) {
		t.Run(name, func(t *testing.T) {
			pubDER, err := x509.MarshalPKIXPublicKey(signer.key.Public())
			require.NoError(t, err)
			reqMsg := &CertReqMsg{
				CertReq: CertRequest{
					CertTemplate: CertTemplate{
						Subject:   NewDirectoryName(pkix.Name{CommonName: "legacy-pop"}),
						PublicKey: pubDER,
					},
				},
			}
			require.NoError(t, reqMsg.GeneratePOP(signer.key))
			reqMsg = roundTripCertReqMsg(t, reqMsg)
			reqMsg.Popo.Signature.Algorithm = AlgorithmIdentifier{Algorithm: signer.oid}
			reqMsg.Popo.Signature.Signature = signer.sign(t, reqMsg.CertReq.Raw)

			err = VerifyPOP(reqMsg)
			var ve *VerificationError
			require.ErrorAs(t, err, &ve)
			assert.Equal(t, ReasonUnsupportedAlgorithm, ve.Reason)

			assert.NoError(t, VerifyPOPWithOptions(reqMsg, POPOptions{AllowSHA1Signatures: true}))
		})
	}
}
