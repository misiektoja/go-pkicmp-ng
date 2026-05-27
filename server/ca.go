package server

import (
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- used for SKI computation (opaque identifier)
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// CA is the interface a certificate authority must implement.
type CA interface {
	// IssueCertificate signs a certificate request. The template has subject,
	// public key, extensions, and SKI populated from the CMP request.
	// SerialNumber is nil - the CA must set it.
	//
	// The CA may modify the template before signing (e.g., enforce policy on
	// validity period, add extensions). Return Response.Waiting to trigger
	// the polling flow for async issuance.
	IssueCertificate(ctx context.Context, reqType RequestType, template *x509.Certificate, sender *SenderIdentity) (*Response, error)
}

// PendingChecker is an optional interface for CAs that support async issuance.
// Implement this if IssueCertificate may return Response.Waiting.
type PendingChecker interface {
	// CheckPending checks the status of a pending certificate request.
	// pollRef is the value returned in WaitingResponse.PollRef.
	CheckPending(ctx context.Context, pollRef string, sender *SenderIdentity) (*Response, error)
}

// ConfirmStatus indicates the outcome of a certificate confirmation.
type ConfirmStatus int

const (
	// ConfirmAccepted means the client sent a certConf message accepting the certificate.
	ConfirmAccepted ConfirmStatus = iota
	// ConfirmRejected means the client sent a certConf message rejecting the certificate.
	ConfirmRejected
	// ConfirmImplicit means the server granted implicit confirm (id-it-implicitConfirm).
	// The certificate is considered accepted without a certConf round-trip.
	ConfirmImplicit
	// ConfirmExpired means the transaction timed out without receiving certConf.
	// The CA may want to revoke the certificate.
	ConfirmExpired
)

// String returns a human-readable name for the confirmation status.
func (s ConfirmStatus) String() string {
	switch s {
	case ConfirmAccepted:
		return "accepted"
	case ConfirmRejected:
		return "rejected"
	case ConfirmImplicit:
		return "implicit"
	case ConfirmExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// CertificateConfirmer is an optional interface a CA can implement to receive
// certificate confirmation notifications.
type CertificateConfirmer interface {
	// ConfirmCertificate is called when a certificate's confirmation status
	// is determined.
	//
	// The issueRef parameter is the [Response.IssueRef] value set by the CA
	// in [CA.IssueCertificate], allowing the CA to correlate the confirmation
	// with the original issuance without looking up by certificate fields.
	ConfirmCertificate(ctx context.Context, cert *x509.Certificate, status ConfirmStatus, issueRef any) error
}

// pollRefKey is the context key for passing pollRef to handlers.
type pollRefKey struct{}

// PollRefFromContext extracts the pollRef from context, if present.
// Used by handlers to detect poll requests.
func PollRefFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(pollRefKey{}).(string)
	return v, ok
}

// contextWithPollRef adds pollRef to context.
func contextWithPollRef(ctx context.Context, pollRef string) context.Context {
	return context.WithValue(ctx, pollRefKey{}, pollRef)
}

// caHandler implements Handler by delegating to a CA.
type caHandler struct {
	ca CA
}

// NewCAHandler creates a Handler that delegates certificate issuance to a CA.
// It handles CRMF/P10CR parsing, template building, and the CMP ceremony.
//
// Use with middleware for policy enforcement:
//
//	srv := server.New(
//	    server.Chain(server.NewCAHandler(ca), server.LightweightPolicy()),
//	    server.WithSigner(caKey, caCert),
//	    server.WithSecretLookup(secretLookup),
//	    server.WithCertificateLookup(certLookup),
//	)
func NewCAHandler(ca CA) Handler {
	return &caHandler{ca: ca}
}

func (h *caHandler) HandleCMP(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		return h.handleCertRequest(ctx, msg, sender)
	case pkicmp.BodyTypeCertConf:
		return h.handleCertConf(ctx, msg)
	case pkicmp.BodyTypePollReq:
		return h.handlePollReq(ctx, msg, sender)
	default:
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
	}
}

func (h *caHandler) handleCertRequest(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
	var subject pkix.Name
	var pubKey any
	var extensions []pkix.Extension

	switch msg.Body.Type {
	case pkicmp.BodyTypeP10CR:
		csr, err := msg.Body.P10CR()
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat}
		}
		subject, pubKey, extensions = csr.Subject, csr.PublicKey, csr.Extensions
	default:
		crmf, err := parseCRMFMsg(msg)
		if err != nil {
			return nil, err
		}
		subject, pubKey, extensions = crmf.subject, crmf.publicKey, crmf.extensions
	}

	// Compute SubjectKeyIdentifier from public key per RFC 5280 §4.2.1.2.
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadAlg, StatusText: err.Error()}
	}
	ski := sha1.Sum(pubDER) // #nosec G401 -- SHA-1 hash of SPKI for SKI (opaque identifier, collision resistance not required)

	// Build template with data from the request only. CA sets serial, validity, key usage, etc.
	template := &x509.Certificate{
		Subject:         subject,
		PublicKey:       pubKey,
		SubjectKeyId:    ski[:],
		ExtraExtensions: extensions,
	}

	reqType := bodyTypeToRequestType(msg.Body.Type)
	return h.ca.IssueCertificate(ctx, reqType, template, sender)
}

func (h *caHandler) handleCertConf(ctx context.Context, msg *pkicmp.PKIMessage) (*Response, error) {
	confirmer, ok := h.ca.(CertificateConfirmer)
	if !ok {
		return nil, nil
	}

	conf, err := msg.Body.CertConf()
	if err != nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat}
	}

	// Get the issued certificate from context (set by Server.handleCertConf).
	cert := IssuedCertFromContext(ctx)
	if cert == nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "no issued certificate"}
	}

	issueRef := IssueRefFromContext(ctx)

	for _, cs := range *conf {
		status := ConfirmAccepted
		if cs.StatusInfo != nil && cs.StatusInfo.Status == pkicmp.StatusRejection {
			status = ConfirmRejected
		}
		if err := confirmer.ConfirmCertificate(ctx, cert, status, issueRef); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (h *caHandler) handlePollReq(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
	checker, ok := h.ca.(PendingChecker)
	if !ok {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "polling not supported"}
	}

	pollRef, ok := PollRefFromContext(ctx)
	if !ok {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "no pending certificate"}
	}

	return checker.CheckPending(ctx, pollRef, sender)
}

func bodyTypeToRequestType(t pkicmp.BodyType) RequestType {
	switch t {
	case pkicmp.BodyTypeIR:
		return RequestIR
	case pkicmp.BodyTypeCR:
		return RequestCR
	case pkicmp.BodyTypeKUR:
		return RequestKUR
	case pkicmp.BodyTypeP10CR:
		return RequestP10CR
	default:
		return RequestIR
	}
}

// NewCAServer creates a complete CMP server from a CA implementation.
// The CA is responsible only for certificate issuance. Configure request
// verification separately with [WithSecretLookup] and/or
// [WithCertificateLookup]. Use middleware to add policy enforcement
// (e.g., [LightweightPolicy]).
// Use [WithSigner] and [WithExtraCerts] options to configure the signing
// credentials for CMP response protection.
func NewCAServer(ca CA, mw []Middleware, opts ...Option) *Server {
	// Detect if the CA implements CertificateConfirmer so the server can
	// call it on implicit confirm (not just explicit certConf).
	if confirmer, ok := ca.(CertificateConfirmer); ok {
		opts = append([]Option{func(c *serverConfig) { c.confirmer = confirmer }}, opts...)
	}
	return New(
		Chain(NewCAHandler(ca), mw...),
		opts...,
	)
}

// GenerateSerial generates a random 128-bit serial number.
// Convenience function for CA implementations.
func GenerateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
