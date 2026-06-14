package pkicmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
)

// VerifyOptions provides trust material for message protection verification.
//
// Verification dispatches based on the message's ProtectionAlg OID — not on
// the credential type. This allows a client to verify responses regardless of
// which protection mode the server chose:
//
//   - MAC-protected response: uses the SharedSecret field.
//   - Signature-protected response: uses TrustPool for chain verification.
//
// Both fields may be populated simultaneously. The verifier ignores whichever
// is irrelevant for the actual algorithm in the message.
//
// RFC 9810 §5.1.3.
type VerifyOptions struct {
	// SharedSecret is the shared secret for MAC-protected messages.
	// For signature-protected messages this field is ignored (TrustPool is
	// used instead). May be nil if only signature verification is needed.
	SharedSecret []byte

	// TrustPool holds root CA certificates for verifying signature-protected
	// messages. For MAC-protected messages this field is ignored. May be nil
	// if only MAC verification is needed.
	TrustPool *x509.CertPool

	// TrustedCert is a pre-trusted certificate for verifying signature-protected
	// messages. When set, the signature is verified directly against this
	// certificate without chain validation. This is used when the verifier has
	// already resolved the sender's certificate from its own database.
	// Takes precedence over TrustPool/ExtraCerts.
	TrustedCert *x509.Certificate

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

	// ProtectionParams is a [MACCredentialOption] that captures the decoded
	// protection parameters from a verified MAC-protected message.
	// Pass it to [NewMACCredentials] to protect a response with the same
	// algorithm suite (fresh salt is generated). Nil for signature-verified messages.
	// RFC 9810 §5.1.3.
	ProtectionParams MACCredentialOption
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
	if alg.Equal(oidPasswordBasedMac) {
		return m.verifyPBM(opts)
	}
	if alg.Equal(oidPBMAC1) {
		return m.verifyPBMAC1(opts)
	}
	if _, err := sigAlgFromOID(alg); err == nil {
		return m.verifySignature(opts)
	}

	return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("OID %v", alg)}
}

// verifyPBM verifies Password-Based MAC protection.
// RFC 9810 §5.1.3.1.
func (m *PKIMessage) verifyPBM(opts VerifyOptions) (*VerifyResult, error) {
	secret := opts.SharedSecret
	if len(secret) == 0 {
		return nil, &VerificationError{Reason: ReasonMissingSharedSecret}
	}

	var p pbmParameter
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

	return &VerifyResult{
		MACVerified: true,
		ProtectionParams: func(c *macCredentialConfig) {
			c.algorithm = oidPasswordBasedMac
			c.iterationCount = p.IterationCount
			c.owf = p.OWF.Algorithm
			c.mac = p.MAC.Algorithm
			c.owfParameters = p.OWF.Parameters
			c.macParameters = p.MAC.Parameters
		},
	}, nil
}

// verifyPBMAC1 verifies PBMAC1 protection.
// RFC 8018 §7.1, RFC 9481 §6.1.2.
func (m *PKIMessage) verifyPBMAC1(opts VerifyOptions) (*VerifyResult, error) {
	secret := opts.SharedSecret
	if len(secret) == 0 {
		return nil, &VerificationError{Reason: ReasonMissingSharedSecret}
	}

	// Parse PBMAC1-params (RFC 8018 §A.5).
	var pbmac1Params struct {
		KeyDerivationFunc algorithmIdentifierASN1
		MessageAuthScheme algorithmIdentifierASN1
	}
	if _, err := asn1.Unmarshal(m.Header.ProtectionAlg.Parameters, &pbmac1Params); err != nil {
		return nil, &ParseError{Detail: "invalid PBMAC1-params: " + err.Error()}
	}

	if !pbmac1Params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("KDF OID %v", pbmac1Params.KeyDerivationFunc.Algorithm)}
	}

	// Parse PBKDF2-params from keyDerivationFunc.Parameters.
	var pbkdf2Params struct {
		Salt           []byte
		IterationCount int
		KeyLength      int
		PRF            algorithmIdentifierASN1
	}
	if _, err := asn1.Unmarshal(pbmac1Params.KeyDerivationFunc.Parameters.FullBytes, &pbkdf2Params); err != nil {
		return nil, &ParseError{Detail: "invalid PBKDF2-params: " + err.Error()}
	}

	if err := validatePBMIterationCount(pbkdf2Params.IterationCount); err != nil {
		return nil, err
	}

	prfHash, err := hmacHashFromOID(pbkdf2Params.PRF.Algorithm)
	if err != nil {
		return nil, err
	}
	if !prfHash.Available() {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("PRF hash %v not available", pbkdf2Params.PRF.Algorithm)}
	}
	macHash, err := hmacHashFromOID(pbmac1Params.MessageAuthScheme.Algorithm)
	if err != nil {
		return nil, err
	}
	if !macHash.Available() {
		return nil, &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("MAC hash %v not available", pbmac1Params.MessageAuthScheme.Algorithm)}
	}

	if err := validatePBKDF2KeyLength(pbkdf2Params.KeyLength, macHash); err != nil {
		return nil, err
	}

	data, err := m.protectedPart()
	if err != nil {
		return nil, err
	}

	// Derive key using PBKDF2 (RFC 8018 §5.2).
	k := pbkdf2.Key(secret, pbkdf2Params.Salt, pbkdf2Params.IterationCount, pbkdf2Params.KeyLength, prfHash.New)
	h := hmac.New(macHash.New, k)
	h.Write(data)
	expected := h.Sum(nil)

	if subtle.ConstantTimeCompare(expected, m.Protection) != 1 {
		return nil, &VerificationError{Reason: ReasonBadMAC}
	}

	return &VerifyResult{
		MACVerified: true,
		ProtectionParams: func(c *macCredentialConfig) {
			c.algorithm = oidPBMAC1
			c.iterationCount = pbkdf2Params.IterationCount
			c.keyLength = pbkdf2Params.KeyLength
			c.owf = pbkdf2Params.PRF.Algorithm
			c.mac = pbmac1Params.MessageAuthScheme.Algorithm
		},
	}, nil
}

// verifySignature verifies signature-based protection.
// RFC 9810 §5.1.3.3: Verify using certificates from extraCerts, validated
// against a trust pool.
// RFC 9810 §8.9: The message sender MUST be authenticated with existing
// trust anchors.
func (m *PKIMessage) verifySignature(opts VerifyOptions) (*VerifyResult, error) {
	sigAlg, err := sigAlgFromOID(m.Header.ProtectionAlg.Algorithm)
	if err != nil {
		return nil, err
	}

	data, err := m.protectedPart()
	if err != nil {
		return nil, err
	}

	// Direct verification against a pre-trusted certificate (server-side lookup).
	if opts.TrustedCert != nil {
		if err := opts.TrustedCert.CheckSignature(sigAlg, data, m.Protection); err != nil {
			return nil, &VerificationError{Reason: ReasonSignatureFailed}
		}
		return &VerifyResult{MACVerified: false}, nil
	}

	// Chain-based verification using TrustPool and ExtraCerts.
	if opts.TrustPool == nil {
		return nil, &VerificationError{Reason: ReasonMissingTrustAnchors}
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
