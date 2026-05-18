package server

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// Option configures a Server.
type Option func(*serverConfig)

// SecretLookup resolves shared secrets for verifying MAC-protected messages.
// The implementation decides whether to require senderKID by returning an error
// when empty (RFC 9810 §5.1.1).
type SecretLookup interface {
	LookupSecret(senderKID []byte) ([]byte, error)
}

// SecretLookupFunc adapts a function to the SecretLookup interface.
type SecretLookupFunc func(senderKID []byte) ([]byte, error)

func (f SecretLookupFunc) LookupSecret(senderKID []byte) ([]byte, error) { return f(senderKID) }

// CertificateLookup resolves sender certificates for verifying signature-protected messages.
// The issuer is derived from the recipient header field. The senderKID is optional and may
// be nil if the client did not include it (RFC 9810 §5.1.1).
type CertificateLookup interface {
	LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error)
}

// CertificateLookupFunc adapts a function to the CertificateLookup interface.
type CertificateLookupFunc func(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error)

func (f CertificateLookupFunc) LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	return f(issuer, subject, senderKID)
}

type serverConfig struct {
	signerKey   crypto.Signer
	signerCert  *x509.Certificate
	signerChain []*x509.Certificate
	secretLookup      SecretLookup
	certificateLookup CertificateLookup
	extraCerts  []*x509.Certificate
	sender      pkix.Name
	confirmWait     time.Duration
	implicitConfirm bool
	maxTransactions              int
	maxTransactionsPerCredential int
}

// WithSigner configures signature-based response protection.
func WithSigner(key crypto.Signer, cert *x509.Certificate, chain ...*x509.Certificate) Option {
	return func(c *serverConfig) {
		c.signerKey = key
		c.signerCert = cert
		c.signerChain = chain
	}
}

// WithSecretLookup configures lookup of shared secrets for MAC-protected requests.
func WithSecretLookup(lookup SecretLookup) Option {
	return func(c *serverConfig) {
		c.secretLookup = lookup
	}
}

// WithCertificateLookup configures lookup of sender certificates for signature-protected requests.
func WithCertificateLookup(lookup CertificateLookup) Option {
	return func(c *serverConfig) {
		c.certificateLookup = lookup
	}
}

// WithExtraCerts provides additional certificates to include in responses.
func WithExtraCerts(certs []*x509.Certificate) Option {
	return func(c *serverConfig) {
		c.extraCerts = certs
	}
}

// WithSender sets the server's identity used in response headers.
func WithSender(name pkix.Name) Option {
	return func(c *serverConfig) {
		c.sender = name
	}
}

// WithConfirmWaitTime sets the confirmWaitTime included in certificate responses.
// RFC 9810 §5.1.1.2.
func WithConfirmWaitTime(d time.Duration) Option {
	return func(c *serverConfig) {
		c.confirmWait = d
	}
}

// WithImplicitConfirm configures the server to always include id-it-implicitConfirm
// in successful certificate responses, skipping the certConf/pkiConf exchange.
// RFC 9810 §5.1.1.1.
func WithImplicitConfirm() Option {
	return func(c *serverConfig) {
		c.implicitConfirm = true
	}
}


// WithMaxTransactions sets the maximum number of concurrent transactions.
// Default is 10000.
func WithMaxTransactions(n int) Option {
	return func(c *serverConfig) {
		c.maxTransactions = n
	}
}

// WithMaxTransactionsPerCredential sets the maximum number of concurrent
// transactions per credential. Default is 100.
func WithMaxTransactionsPerCredential(n int) Option {
	return func(c *serverConfig) {
		c.maxTransactionsPerCredential = n
	}
}