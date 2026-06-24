package pkicmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
)

// ProtectionMechanism identifies a class of message protection.
type ProtectionMechanism int

const (
	// ProtectionAny accepts whichever mechanism the message carries. A server
	// needs this to serve both shared-secret and certificate-based clients,
	// because it cannot know which one a peer will use for the first message.
	ProtectionAny ProtectionMechanism = iota
	// ProtectionMAC accepts only shared-secret protection (PasswordBasedMac or PBMAC1).
	ProtectionMAC
	// ProtectionSignature accepts only signature-based protection.
	ProtectionSignature
)

// VerifyOptions provides trust material for message protection verification.
//
// Verification dispatches on the message's ProtectionAlg OID, so a caller that
// supplies both a shared secret and a trust pool accepts whichever mechanism
// the peer chose. Set RequiredProtection to pin the mechanism instead.
//
//   - MAC-protected message: uses the SharedSecret field.
//   - Signature-protected message: uses TrustPool for chain verification.
//
// RFC 9810 §5.1.3.
type VerifyOptions struct {
	// RequiredProtection restricts which protection mechanism is accepted.
	// The zero value, ProtectionAny, accepts either one.
	//
	// Within a single PKI management operation the mechanism must not change:
	// RFC 9483 §3.1 requires "the same kind of protection ... for all messages
	// of that PKI management operation", and RFC 9810 §5.2.3 reserves the
	// failInfo bit wrongIntegrity for a message that arrives "password based
	// instead of signature or vice versa". Callers that know which mechanism
	// they started an operation with should pin it here, otherwise a peer can
	// substitute the mechanism it finds easier to satisfy.
	RequiredProtection ProtectionMechanism

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

	// RequireDigitalSignatureKeyUsage rejects a CMP protection certificate that
	// carries a keyUsage extension without the digitalSignature bit, as
	// RFC 9483 §3.5 requires.
	//
	// It is off by default because deployed CAs do not follow the rule. Nokia
	// NCM 26.7 protects its CMP responses with the issuing CA certificate, whose
	// keyUsage is keyCertSign and cRLSign only, so enabling this rejects every
	// response from that server. Turn it on when every peer is known to conform.
	RequireDigitalSignatureKeyUsage bool
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

	// ProtectionCertificate is the certificate whose signature was accepted.
	// Nil for MAC-verified messages.
	//
	// A peer is allowed to send extraCerts only on the first message of a PKI
	// management operation (RFC 9810 §5.1), so a later message in the same
	// operation can arrive with no candidate signer at all. Callers that keep
	// this certificate can offer it back through [VerifyOptions.ExtraCerts] to
	// verify those later messages, which still have to satisfy the chain,
	// sender and signature checks against it.
	ProtectionCertificate *x509.Certificate
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

	// Dispatch based on algorithm OID, after checking it against the mechanism
	// the caller requires. Without this the peer picks the mechanism, which lets
	// it substitute one the caller never intended to accept.
	if alg.Equal(oidPasswordBasedMac) || alg.Equal(oidPBMAC1) {
		if opts.RequiredProtection == ProtectionSignature {
			return nil, &VerificationError{Reason: ReasonUnexpectedProtection, Err: fmt.Errorf("message is MAC-protected but signature-based protection is required")}
		}
		if alg.Equal(oidPasswordBasedMac) {
			return m.verifyPBM(opts)
		}
		return m.verifyPBMAC1(opts)
	}
	if _, err := sigAlgFromOID(alg); err == nil {
		if opts.RequiredProtection == ProtectionMAC {
			return nil, &VerificationError{Reason: ReasonUnexpectedProtection, Err: fmt.Errorf("message is signature-protected but MAC-based protection is required")}
		}
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
	pbkdf2Params, err := parsePBKDF2Params(pbmac1Params.KeyDerivationFunc.Parameters.FullBytes)
	if err != nil {
		return nil, err
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

	// RFC 8018 §A.5: keyLength is OPTIONAL. When the peer omits it, §7.1 leaves the
	// length to the MAC scheme, which for HMAC is the digest size.
	if pbkdf2Params.KeyLength == 0 {
		pbkdf2Params.KeyLength = macHash.Size()
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
		// The chain path gets expiry checking from x509.Verify. This path does
		// not, so without this an expired certificate left in the verifier's
		// database would keep authenticating forever.
		now := time.Now()
		if now.Before(opts.TrustedCert.NotBefore) || now.After(opts.TrustedCert.NotAfter) {
			return nil, &VerificationError{Reason: ReasonCertificateExpired}
		}
		if opts.RequireDigitalSignatureKeyUsage && !permittedToSign(opts.TrustedCert) {
			return nil, &VerificationError{Reason: ReasonKeyUsageNotPermitted}
		}
		if err := opts.TrustedCert.CheckSignature(sigAlg, data, m.Protection); err != nil {
			return nil, &VerificationError{Reason: ReasonSignatureFailed}
		}
		return &VerifyResult{MACVerified: false, ProtectionCertificate: opts.TrustedCert}, nil
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

	// senderMismatch records that a candidate was rejected only because it did
	// not belong to the named sender, so the caller can tell an identity problem
	// apart from a cryptographic one. keyUsageRejected does the same for a
	// certificate that is trusted and correctly named but not allowed to sign.
	senderMismatch := false
	keyUsageRejected := false

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
		// Verify trust chain. ExtKeyUsageAny is required because an empty
		// KeyUsages makes crypto/x509 demand serverAuth, which no CMP
		// specification asks for and which rejects the RFC 9810 §4.5
		// certificates id-kp-cmcCA, id-kp-cmcRA and id-kp-cmKGA.
		verifyOpts := x509.VerifyOptions{
			Roots:         opts.TrustPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := x509Cert.Verify(verifyOpts); err != nil {
			continue
		}
		// RFC 9483 §3.5: the sender field must match the subject of the CMP
		// protection certificate. Chaining to a trust anchor only proves the
		// certificate is trusted, not that it belongs to the claimed sender, so
		// without this any certificate under any configured anchor would pass.
		if !senderMatchesCertificate(m.Header.Sender, x509Cert) {
			senderMismatch = true
			continue
		}
		if opts.RequireDigitalSignatureKeyUsage && !permittedToSign(x509Cert) {
			keyUsageRejected = true
			continue
		}
		// Check signature over protected part.
		if err := x509Cert.CheckSignature(sigAlg, data, m.Protection); err == nil {
			return &VerifyResult{MACVerified: false, ProtectionCertificate: x509Cert}, nil
		}
	}

	if senderMismatch {
		return nil, &VerificationError{Reason: ReasonSenderMismatch}
	}
	if keyUsageRejected {
		return nil, &VerificationError{Reason: ReasonKeyUsageNotPermitted}
	}
	return nil, &VerificationError{Reason: ReasonSignatureFailed}
}

// permittedToSign reports whether a CMP protection certificate may sign, per the RFC 9483 §3.5 digitalSignature rule.
func permittedToSign(cert *x509.Certificate) bool {
	// The requirement is conditional on the extension being present, so a
	// certificate without keyUsage is unconstrained and remains acceptable.
	// crypto/x509 reports KeyUsage as zero in both cases, so the extension list
	// is what distinguishes "absent" from "present and empty".
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionKeyUsage) {
			return cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
		}
	}
	return true
}

// senderMatchesCertificate reports whether the header sender names the subject of the protection certificate.
func senderMatchesCertificate(sender GeneralName, cert *x509.Certificate) bool {
	// RFC 4210 §5.1.1 requires a NULL DN when the sender does not know its own
	// name, and GeneralName has variants other than directoryName. There is no
	// directory name to compare in those cases, so the binding does not apply
	// and authenticity rests on the trust chain alone.
	if len(sender.DirectoryName) == 0 {
		return true
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil {
		return false
	}
	// Compare the decoded forms so that a name encoded as PrintableString in one
	// place and UTF8String in the other still matches.
	return sender.DirectoryName.String() == subject.String()
}
