package pkicmp

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Credentials is the interface representing material used to protect a CMP message.
// The library provides [MACCredentials] and [SignatureCredentials], but custom
// implementations are possible for hardware tokens, testing, or non-standard schemes.
type Credentials interface {
	// Protect applies protection to the message.
	Protect(msg *PKIMessage) error
}

// MACCredentialOption is a functional option for [NewMACCredentials].
type MACCredentialOption func(*macCredentialConfig)

type macCredentialConfig struct {
	algorithm      asn1.ObjectIdentifier
	iterationCount int
	keyLength      int
	owf            asn1.ObjectIdentifier // PBM OWF or PBMAC1 PRF
	mac            asn1.ObjectIdentifier
	owfParameters  []byte               // raw ASN.1 params for PBM OWF echo-back
	macParameters  []byte               // raw ASN.1 params for PBM MAC echo-back
	protectionAlg  *AlgorithmIdentifier // raw AlgID from WithProtectionAlgorithm
}

// WithPBM configures PasswordBasedMac protection (RFC 4210 §5.1.3.1).
// By default, [MACCredentials] uses PBMAC1 (RFC 8018), which is the
// RECOMMENDED algorithm per RFC 9481 §7.
func WithPBM() MACCredentialOption {
	return func(c *macCredentialConfig) { c.algorithm = oidPasswordBasedMac }
}

// WithMACIterationCount sets the PBKDF iteration count.
func WithMACIterationCount(n int) MACCredentialOption {
	return func(c *macCredentialConfig) { c.iterationCount = n }
}

// WithProtectionAlgorithm echoes the protection parameters from a received
// message's [AlgorithmIdentifier]. The server uses this to protect responses
// with the same algorithm suite as the request (fresh salt is generated).
// RFC 9810 §5.1.3.
func WithProtectionAlgorithm(alg *AlgorithmIdentifier) MACCredentialOption {
	return func(c *macCredentialConfig) {
		if alg != nil {
			c.protectionAlg = alg
		}
	}
}

// MACCredentials holds a shared secret for Password-Based MAC protection.
// Create with [NewMACCredentials].
//
// Callers should set Header.SenderKID before calling Protect to identify the
// shared secret to the recipient (RFC 9810 §5.1.1).
type MACCredentials struct {
	secret []byte
	cfg    macCredentialConfig
}

// NewMACCredentials creates credentials for shared-secret MAC protection.
// Returns an error if the secret is empty.
// The secret is copied — the caller may safely mutate the original slice after this call.
// By default, PBMAC1 (RFC 8018) with HMAC-SHA-256 is used, which is the
// RECOMMENDED algorithm per RFC 9481 §7. Use [WithPBM] for PasswordBasedMac.
// Use [WithMACIterationCount] to override the iteration count.
// Use [WithProtectionAlgorithm] to echo protection parameters from a received message.
func NewMACCredentials(secret []byte, opts ...MACCredentialOption) (*MACCredentials, error) {
	if len(secret) == 0 {
		return nil, &ProtectionError{Reason: ReasonMissingSharedSecret}
	}
	s := make([]byte, len(secret))
	copy(s, secret)
	c := &MACCredentials{secret: s}
	for _, opt := range opts {
		opt(&c.cfg)
	}
	return c, nil
}

func (c *MACCredentials) Protect(msg *PKIMessage) error {
	if c.cfg.protectionAlg != nil {
		return msg.protectWithMACAlgorithm(c.secret, c.cfg.protectionAlg)
	}
	alg := c.cfg.algorithm
	if alg == nil {
		alg = oidPBMAC1 // RFC 9481 §7: PBMAC1 is RECOMMENDED over PasswordBasedMac.
	}
	if alg.Equal(oidPBMAC1) {
		return msg.protectWithPBMAC1Options(pbmac1Options{
			Secret:         c.secret,
			IterationCount: c.cfg.iterationCount,
			KeyLength:      c.cfg.keyLength,
			PRF:            c.cfg.owf,
			MAC:            c.cfg.mac,
		})
	}
	return msg.protectWithMACOptions(macOptions{
		Secret:         c.secret,
		Algorithm:      alg,
		IterationCount: c.cfg.iterationCount,
		OWF:            c.cfg.owf,
		MAC:            c.cfg.mac,
		OWFParameters:  c.cfg.owfParameters,
		MACParameters:  c.cfg.macParameters,
	})
}

// SharedSecret returns the shared secret held by this credentials object.
// This is used internally by the server to protect responses with the same secret.
func (c *MACCredentials) SharedSecret() []byte {
	return c.secret
}

// SignatureCredentials holds a signing key and certificate for signature-based
// protection. Create with [NewSignatureCredentials].
type SignatureCredentials struct {
	key   crypto.Signer
	cert  *x509.Certificate
	chain []*x509.Certificate // optional intermediate certificates
}

// NewSignatureCredentials creates credentials for certificate-based signature
// protection. Returns an error if key is nil, cert is nil, or the key does not
// match the certificate's public key.
func NewSignatureCredentials(key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) (*SignatureCredentials, error) {
	if key == nil {
		return nil, &ProtectionError{Reason: ReasonMissingSigner}
	}
	if cert == nil {
		return nil, &ProtectionError{Reason: ReasonMissingSigner, Err: fmt.Errorf("certificate is nil")}
	}
	pubDER, err1 := x509.MarshalPKIXPublicKey(key.Public())
	certPubDER, err2 := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(pubDER, certPubDER) != 1 {
		return nil, &ProtectionError{Reason: ReasonMissingSigner, Err: fmt.Errorf("private key does not match certificate public key")}
	}
	return &SignatureCredentials{key: key, cert: cert, chain: chain}, nil
}

// Certificate returns the signing certificate.
func (c *SignatureCredentials) Certificate() *x509.Certificate {
	return c.cert
}

func (c *SignatureCredentials) Protect(msg *PKIMessage) error {
	return msg.protectWithSignature(c.key, c.cert, c.chain...)
}
