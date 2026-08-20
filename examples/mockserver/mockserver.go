// Package mockserver demonstrates how to implement the [server.CA] interface
// to build a CMP certificate authority server.
//
// Read [CA.IssueCertificate], [CA.LookupSecret], and [CA.LookupCertificate]
// to see the three methods a CA backend must provide, then look at cmd/main.go
// to see how they are wired into a running HTTP server.
package mockserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/server"
)

// oidKeyUsage identifies the RFC 5280 §4.2.1.3 keyUsage extension.
var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// MockCA implements [server.CA], [server.SecretLookup], and [server.CertificateLookup].
type MockCA struct {
	key  *ecdsa.PrivateKey // CA private key used to sign issued certificates
	cert *x509.Certificate // CA certificate returned in caPubs on IR responses

	mu          sync.Mutex          // guards issuedCerts; the HTTP server handles requests concurrently
	issuedCerts []*x509.Certificate // certificates issued so far; used by LookupCertificate
	secrets     map[string][]byte   // senderKID -> IAK, used by LookupSecret for MAC-protected requests
	nextIssueID atomic.Uint64       // monotonic counter; used as IssueRef

	Log *slog.Logger
}

// New creates a CA with a self-signed certificate.
//
// secrets maps senderKID reference strings to Initial Authentication Keys (IAKs)
// for MAC-based enrollment (RFC 4210 §5.1.3.1). Pass nil if only signature-based
// protection is needed.
//
// log is the logger to use for CA operations. If nil, slog.Default() is used.
func New(secrets map[string][]byte, log *slog.Logger) (*MockCA, error) {
	key, cert, err := generateSelfSignedCA()
	if err != nil {
		return nil, err
	}
	return &MockCA{
		key:     key,
		cert:    cert,
		Log:     log,
		secrets: secrets,
	}, nil
}

// Key returns the CA private key.
func (c *MockCA) Key() *ecdsa.PrivateKey { return c.key }

// Cert returns the CA certificate.
func (c *MockCA) Cert() *x509.Certificate { return c.cert }

// IssueCertificate implements server.CA.
func (c *MockCA) IssueCertificate(_ context.Context, reqType server.RequestType, tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
	// Log who is requesting a certificate and how their request was authenticated.
	// SenderIdentity is populated by the server after verifying the request's
	// protection: MACVerified=true for shared-secret (MAC) requests, or
	// Certificate is set for signature-protected requests.
	if sender.MACVerified {
		c.Log.Info("certificate request received",
			"type", reqType,
			"protection", "MAC",
			"senderKID", string(sender.SenderKID),
		)
	} else {
		c.Log.Info("certificate request received",
			"type", reqType,
			"protection", "signature",
			"sender", sender.Sender.String(),
		)
	}

	// Set certificate parameters.
	serial, err := server.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.Issuer = c.cert.Subject
	tmpl.NotBefore = time.Now().Add(-1 * time.Minute)
	tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)

	// tmpl.ExtraExtensions holds what the requester asked for, and
	// x509.CreateCertificate lets an extension there override the matching typed
	// field. Without dropping it first, a requested keyUsage would silently
	// replace the assignment below and the requester would choose its own key
	// usage. Other requested extensions are left for this example to pass through.
	tmpl.ExtraExtensions = slices.DeleteFunc(tmpl.ExtraExtensions, func(e pkix.Extension) bool {
		return e.Id.Equal(oidKeyUsage)
	})
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature

	c.Log.Info("issuing certificate",
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

	// IssueRef is an opaque value passed back to ConfirmCertificate.  The
	// server treats it as interface{} and never inspects it, so the CA is
	// free to store anything convenient.
	resp := &server.Response{Certificate: cert, IssueRef: c.nextIssueID.Add(1)}

	// Include the CA certificate in caPubs for IR responses only.
	// RFC 9483 §4.1.1 allows caPubs in IR responses to bootstrap trust.
	// RFC 9483 §4.1.3 requires caPubs to be absent in KUR responses.
	if reqType == server.RequestIR {
		resp.CACerts = []*x509.Certificate{c.cert}
		c.Log.Info("including CA certificate in caPubs (IR bootstrap)")
	}

	return resp, nil
}

// LookupSecret implements server.SecretLookup.
// The server calls this before verifying MAC protection so that each client
// can carry its own pre-shared secret (Initial Authentication Key, IAK).
// This implementation keys on senderKID (reference number) per RFC 4210 §5.1.3.1.
// The sender DN is ignored.
func (c *MockCA) LookupSecret(_ pkix.Name, senderKID []byte) ([]byte, error) {
	c.Log.Info("looking up shared secret for MAC-protected request",
		"senderKID", string(senderKID),
	)
	if c.secrets == nil {
		c.Log.Warn("no secrets configured; rejecting MAC-protected request")
		return nil, fmt.Errorf("no secrets configured")
	}
	secret, ok := c.secrets[string(senderKID)]
	if !ok {
		c.Log.Warn("unknown senderKID; rejecting MAC-protected request",
			"senderKID", string(senderKID),
		)
		return nil, fmt.Errorf("unknown senderKID")
	}
	return secret, nil
}

// LookupCertificate implements server.CertificateLookup.
// The server calls this before verifying signature protection on follow-up
// messages (KUR, certConf) so it can locate the previously issued certificate
// that should be used to verify the signature.
func (c *MockCA) LookupCertificate(_ pkix.Name, _ pkix.Name, senderKID []byte) (*x509.Certificate, error) {
	c.Log.Info("looking up certificate for signature-protected request",
		"senderKID", fmt.Sprintf("%x", senderKID),
	)
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(senderKID) == 0 {
		c.Log.Warn("senderKID missing in signature-protected request")
		return nil, fmt.Errorf("senderKID required")
	}
	for _, cert := range c.issuedCerts {
		if bytes.Equal(cert.SubjectKeyId, senderKID) {
			c.Log.Info("found certificate",
				"subject", cert.Subject.String(),
				"serial", cert.SerialNumber.String(),
			)
			return cert, nil
		}
	}
	c.Log.Warn("certificate not found for senderKID",
		"senderKID", fmt.Sprintf("%x", senderKID),
	)
	return nil, fmt.Errorf("certificate not found")
}

// ConfirmCertificate implements [server.CertificateConfirmer].
// The server calls this after receiving certConf from the client, or when a
// transaction expires without confirmation. issueRef is whatever value the CA
// stored in [Response.IssueRef] during issuance — the server passes it back
// unchanged so the CA can update its records without an extra certificate
// lookup.
//
// status is one of:
//   - [server.ConfirmAccepted]: client accepted the certificate via certConf
//   - [server.ConfirmRejected]: client rejected the certificate via certConf
//   - [server.ConfirmImplicit]: implicit confirm was granted; no certConf round-trip
//   - [server.ConfirmExpired]: transaction timed out before certConf was received
func (c *MockCA) ConfirmCertificate(_ context.Context, cert *x509.Certificate, status server.ConfirmStatus, issueRef any) error {
	c.Log.Info("certificate confirmation received",
		"status", status.String(),
		"subject", cert.Subject.String(),
		"issueRef", issueRef,
	)
	return nil
}

// generateSelfSignedCA creates a self-signed CA key and certificate.
// This is standard Go crypto boilerplate, not CMP-specific.
// In production you would load the CA key and certificate from secure storage
// (HSM, secret manager, or PEM files) rather than generating them at startup.
func generateSelfSignedCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	h := sha256.Sum256(pubDER)
	ski := h[:20] // first 20 bytes of SHA-256 used as SKI (opaque identifier per RFC 5280 §4.2.1.2)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		// digitalSignature is required because this same certificate is the CMP
		// protection certificate passed to server.WithSigner (RFC 9483 §3.5).
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski,
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
