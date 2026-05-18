// Package mockserver provides a minimal CMP CA for testing.
package mockserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- used for SKI computation (opaque identifier)
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/tsaarni/go-pkicmp/server"
)

// CA implements server.CA for testing.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	log  *slog.Logger

	mu          sync.Mutex
	issuedCerts []*x509.Certificate
	secrets     map[string][]byte // senderKID -> secret
}

// Option configures the CA.
type Option func(*CA)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *CA) { c.log = l }
}

// WithSecret registers a shared secret for MAC-protected requests.
func WithSecret(senderKID, secret []byte) Option {
	return func(c *CA) {
		if c.secrets == nil {
			c.secrets = make(map[string][]byte)
		}
		c.secrets[string(senderKID)] = secret
	}
}

// New creates a CA with a self-signed certificate.
func New(opts ...Option) (*CA, error) {
	key, cert, err := generateCA()
	if err != nil {
		return nil, err
	}
	c := &CA{key: key, cert: cert, log: slog.Default()}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Key returns the CA private key.
func (c *CA) Key() *ecdsa.PrivateKey { return c.key }

// Cert returns the CA certificate.
func (c *CA) Cert() *x509.Certificate { return c.cert }

// IssueCertificate implements server.CA.
func (c *CA) IssueCertificate(_ context.Context, reqType server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	// Set certificate parameters.
	serial, err := server.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.Issuer = c.cert.Subject
	tmpl.NotBefore = time.Now().Add(-1 * time.Minute)
	tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature

	c.log.Info("issuing certificate",
		"type", reqType,
		"subject", tmpl.Subject.String(),
		"serial", serial.String(),
	)

	// Sign the certificate.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, tmpl.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	// Store for later lookup.
	c.mu.Lock()
	c.issuedCerts = append(c.issuedCerts, cert)
	c.mu.Unlock()

	return &server.Response{Certificate: cert}, nil
}

// LookupSecret implements server.CA.
func (c *CA) LookupSecret(senderKID []byte) ([]byte, error) {
	if c.secrets == nil {
		return nil, fmt.Errorf("no secrets configured")
	}
	secret, ok := c.secrets[string(senderKID)]
	if !ok {
		return nil, fmt.Errorf("unknown senderKID")
	}
	return secret, nil
}

// LookupCertificate implements server.CA.
func (c *CA) LookupCertificate(_ pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(senderKID) == 0 {
		return nil, fmt.Errorf("senderKID required")
	}
	for _, cert := range c.issuedCerts {
		if bytes.Equal(cert.SubjectKeyId, senderKID) {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("certificate not found")
}

// NewServer creates a CMP server using this CA.
func (c *CA) NewServer(opts ...server.Option) *server.Server {
	opts = append([]server.Option{server.WithImplicitConfirm()}, opts...)
	return server.NewCAServer(c, c.key, c.cert, opts...)
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ski := sha1.Sum(pubDER) // #nosec G401 -- SHA-1 hash of SPKI for SKI (opaque identifier, collision resistance not required)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski[:],
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
