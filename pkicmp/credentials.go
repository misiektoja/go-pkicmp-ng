package pkicmp

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
)

// Credentials is the interface representing material used to protect a CMP message.
// The library provides [MACCredentials] and [SignatureCredentials], but custom
// implementations are possible for hardware tokens, testing, or non-standard schemes.
type Credentials interface {
	// Protect applies protection to the message.
	Protect(msg *PKIMessage) error
	// SharedSecret returns the secret for MAC verification, or nil for signature-based credentials.
	SharedSecret() []byte
}

// MACCredentials holds a shared secret for Password-Based MAC protection.
// Create with [NewMACCredentials].
//
// Callers should set Header.SenderKID before calling Protect to identify the
// shared secret to the recipient (RFC 9810 §5.1.1).
type MACCredentials struct {
	secret []byte
}

// NewMACCredentials creates credentials for shared-secret (PBM) protection.
// Returns an error if the secret is empty.
// The secret is copied — the caller may safely mutate the original slice after this call.
func NewMACCredentials(secret []byte) (*MACCredentials, error) {
	if len(secret) == 0 {
		return nil, &ProtectionError{Reason: ReasonMissingSharedSecret}
	}
	s := make([]byte, len(secret))
	copy(s, secret)
	return &MACCredentials{secret: s}, nil
}

func (c *MACCredentials) Protect(msg *PKIMessage) error {
	return msg.ProtectWithMAC(c.secret)
}

func (c *MACCredentials) SharedSecret() []byte {
	return c.secret
}

// SignatureCredentials holds a signing key and certificate for signature-based
// protection. Create with [NewSignatureCredentials].
type SignatureCredentials struct {
	Key   crypto.Signer
	Cert  *x509.Certificate
	Chain []*x509.Certificate // optional intermediate certificates
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
	return &SignatureCredentials{Key: key, Cert: cert, Chain: chain}, nil
}

func (c *SignatureCredentials) Protect(msg *PKIMessage) error {
	return msg.ProtectWithSignature(c.Key, c.Cert, c.Chain...)
}

func (c *SignatureCredentials) SharedSecret() []byte {
	return nil
}

