package pkicmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// VerifyOptions provides trust material for message protection verification.
//
// Verification dispatches based on the message's ProtectionAlg OID — not on
// the credential type. This allows a client to verify responses regardless of
// which protection mode the server chose:
//
//   - MAC-protected response: uses the shared secret from Credentials.
//   - Signature-protected response: uses TrustPool for chain verification.
//
// Both fields may be populated simultaneously. The verifier ignores whichever
// is irrelevant for the actual algorithm in the message.
//
// RFC 9810 §5.1.3.
type VerifyOptions struct {
	// Credentials provides the shared secret for MAC-protected messages.
	// For signature-protected messages this field is ignored (TrustPool is
	// used instead). May be nil if only signature verification is needed.
	Credentials Credentials

	// TrustPool holds root CA certificates for verifying signature-protected
	// messages. For MAC-protected messages this field is ignored. May be nil
	// if only MAC verification is needed.
	TrustPool *x509.CertPool

	// ExtraCerts provides candidate signer certificates (typically from
	// msg.ExtraCerts) for signature chain building.
	ExtraCerts []CMPCertificate

	// SenderKID filters candidate signer certificates by SubjectKeyId
	// (typically msg.Header.SenderKID).
	SenderKID []byte
}

// VerifyResult is returned on successful verification.
type VerifyResult struct {
	// MACVerified is true when the message was verified using a shared secret
	// (PBM, PBMAC1, or KEM-MAC). This determines whether caPubs from the
	// message body may be trusted (RFC 9810 §5.3.2).
	MACVerified bool
}

// Verify verifies the message protection and returns verification metadata.
// The algorithm is determined from Header.ProtectionAlg.
// Verify uses the algorithm OID from the header to select the correct
// verification path (MAC or signature) and ignores irrelevant fields.
// RFC 9810 §5.1.3.
func (m *PKIMessage) Verify(opts VerifyOptions) (*VerifyResult, error) {
	if m.Header.ProtectionAlg == nil {
		return nil, &ParseError{Detail: "message has no protection algorithm"}
	}
	if len(m.Protection) == 0 {
		return nil, &ParseError{Detail: "message is not protected"}
	}
	if m.Body == nil {
		return nil, &ParseError{Detail: "missing message body"}
	}

	alg := m.Header.ProtectionAlg.Algorithm

	// Dispatch based on algorithm OID.
	if alg.Equal(OIDPasswordBasedMac) {
		return m.verifyPBM(opts)
	}
	if _, err := sigAlgFromOID(alg); err == nil {
		return m.verifySignature(opts)
	}

	return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("OID %v", alg)}
}

// verifyPBM verifies Password-Based MAC protection.
// RFC 9810 §5.1.3.1.
func (m *PKIMessage) verifyPBM(opts VerifyOptions) (*VerifyResult, error) {
	var secret []byte
	if opts.Credentials != nil {
		secret = opts.Credentials.SharedSecret()
	}
	if len(secret) == 0 {
		return nil, &VerificationError{Reason: ReasonMissingSharedSecret}
	}

	var p PBMParameter
	params := cryptobyte.String(m.Header.ProtectionAlg.Parameters)
	if err := p.unmarshal(&params); err != nil {
		return nil, err
	}

	if err := validatePBMIterationCount(p.IterationCount); err != nil {
		return nil, err
	}

	hash, err := hashFromOID(p.OWF.Algorithm)
	if err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("hash %v not available", p.OWF.Algorithm)}
	}

	macHash, err := hmacHashFromOID(p.MAC.Algorithm)
	if err != nil {
		return nil, err
	}
	if !macHash.Available() {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("MAC hash %v not available", p.MAC.Algorithm)}
	}

	data, err := m.protectedPart()
	if err != nil {
		return nil, err
	}

	k, err := derivePBMKey(secret, p.Salt, p.IterationCount, hash, macHash)
	if err != nil {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	mac := hmac.New(macHash.New, k)
	mac.Write(data)
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expected, m.Protection) != 1 {
		return nil, &VerificationError{Reason: ReasonBadMAC}
	}

	return &VerifyResult{MACVerified: true}, nil
}

// verifySignature verifies signature-based protection.
// RFC 9810 §5.1.3.3: Verify using certificates from extraCerts, validated
// against a trust pool.
// RFC 9810 §8.9: The message sender MUST be authenticated with existing
// trust anchors.
func (m *PKIMessage) verifySignature(opts VerifyOptions) (*VerifyResult, error) {
	if opts.TrustPool == nil {
		return nil, &VerificationError{Reason: ReasonMissingTrustAnchors}
	}

	sigAlg, err := sigAlgFromOID(m.Header.ProtectionAlg.Algorithm)
	if err != nil {
		return nil, err
	}

	data, err := m.protectedPart()
	if err != nil {
		return nil, err
	}

	// Build intermediates pool from ExtraCerts for chain verification.
	intermediates := x509.NewCertPool()
	for _, cert := range opts.ExtraCerts {
		x509Cert, err := cert.Parse()
		if err != nil {
			continue
		}
		intermediates.AddCert(x509Cert)
	}

	// RFC 9810 §5.1.3.3: Verify the signature using certificates from extraCerts.
	for _, cert := range opts.ExtraCerts {
		x509Cert, err := cert.Parse()
		if err != nil {
			continue
		}
		// RFC 9810 §5.1.1: senderKID identifies the key used for protection.
		if len(opts.SenderKID) > 0 {
			if len(x509Cert.SubjectKeyId) == 0 || !bytes.Equal(x509Cert.SubjectKeyId, opts.SenderKID) {
				continue
			}
		}
		// Verify trust chain.
		verifyOpts := x509.VerifyOptions{
			Roots:         opts.TrustPool,
			Intermediates: intermediates,
		}
		if _, err := x509Cert.Verify(verifyOpts); err != nil {
			continue
		}
		// Check signature over protected part.
		if err := x509Cert.CheckSignature(sigAlg, data, m.Protection); err == nil {
			return &VerifyResult{MACVerified: false}, nil
		}
	}

	return nil, &VerificationError{Reason: ReasonSignatureFailed}
}
