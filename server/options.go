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
//
// The sender parameter is the DN from the PKIHeader sender field. It may be
// a NULL-DN (len(sender.Names) == 0) when the sender identity is unknown,
// e.g., during initial enrollment (RFC 9810 §5.1.1).
//
// The senderKID parameter is the reference number that identifies the shared
// secret (RFC 4210 §5.1.3.1). When sender is a NULL-DN, senderKID MUST be
// present (non-nil) and is the sole means of identifying the shared secret.
//
// Implementations may use either or both fields to locate the shared secret.
type SecretLookup interface {
	LookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error)
}

// SecretLookupFunc adapts a function to the SecretLookup interface.
type SecretLookupFunc func(sender pkix.Name, senderKID []byte) ([]byte, error)

func (f SecretLookupFunc) LookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error) {
	return f(sender, senderKID)
}

// CertificateLookup resolves sender certificates for verifying signature-protected messages.
//
// The issuer parameter is the DN from the PKIHeader recipient field (the CA's identity).
// It may be a NULL-DN (len(issuer.Names) == 0) if the client did not set a recipient.
//
// The subject parameter is the DN from the PKIHeader sender field (the end entity's identity).
// It may be a NULL-DN (len(subject.Names) == 0) when the sender identity is not yet known,
// e.g., during initial enrollment (RFC 9810 §5.1.1).
//
// The senderKID parameter is the key identifier from the PKIHeader senderKID field. It is
// OPTIONAL and may be nil if the client did not include it (RFC 9810 §5.1.1).
//
// Implementations may use any combination of these fields to locate the certificate.
type CertificateLookup interface {
	LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error)
}

// CertificateLookupFunc adapts a function to the CertificateLookup interface.
type CertificateLookupFunc func(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error)

func (f CertificateLookupFunc) LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	return f(issuer, subject, senderKID)
}

type serverConfig struct {
	signerKey                    crypto.Signer
	signerCert                   *x509.Certificate
	signerChain                  []*x509.Certificate
	secretLookup                 SecretLookup
	certificateLookup            CertificateLookup
	extraCerts                   []*x509.Certificate
	sender                       pkix.Name
	confirmWait                  time.Duration
	implicitConfirm              bool
	maxTransactions              int
	maxTransactionsPerCredential int
	confirmer                    CertificateConfirmer // set automatically by NewCAServer
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

// WithConfirmWaitTime sets the confirmWaitTime included in certificate responses
// and controls when [Server.CleanupExpired] considers transactions stale.
// The default is 10 seconds. RFC 9810 §5.1.1.2.
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
