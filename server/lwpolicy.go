package server

import (
	"context"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// LightweightPolicy returns a handler wrapper that enforces RFC 9483 Lightweight CMP Profile requirements.
// This is the default policy used by the server. Users can replace it with their own policy wrappers.
func LightweightPolicy() func(Handler) Handler {
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
			// RFC 9483 §3.1 wants a MAC-protected message to name the shared
			// secret in the sender commonName, but RFC 4210 §5.1.1 requires the
			// opposite of an end entity that does not yet know its own name: a
			// NULL-DN sender with the reference number in senderKID, which is
			// what a bootstrapping enrollment normally is. Either form
			// identifies the secret, so only the absence of both is rejected
			// here. WithStrictProfileValidation applies the profile rule.
			if sender.MACVerified && len(msg.Header.Sender.DirectoryName) == 0 && len(msg.Header.SenderKID) == 0 {
				return nil, &Error{
					Status:      pkicmp.StatusRejection,
					FailureInfo: pkicmp.FailBadMessageCheck,
					StatusText:  "MAC protection requires a sender name or senderKID",
				}
			}

			// The RFC 9483 §3.3 rules on extraCerts, that it is present for
			// signature-based protection and that the CMP protection certificate
			// comes first, are enforced only under WithStrictProfileValidation.
			// They exist so a recipient can resolve and validate the signer from
			// the message, and this server never does that: it authenticates
			// through CertificateLookup against its own store. Enforcing them by
			// default would reject deployed clients over a field the server
			// ignores. Outgoing responses always follow §3.3.

			// Only validate cert requests further.
			if !isCertRequest(msg.Body.Type) {
				return next.HandleCMP(ctx, msg, sender)
			}

			// RFC 9483 §4.1.3: KUR MUST be signature-protected.
			if msg.Body.Type == pkicmp.BodyTypeKUR && sender.MACVerified {
				return nil, &Error{
					Status:      pkicmp.StatusRejection,
					FailureInfo: pkicmp.FailWrongIntegrity,
					StatusText:  "KUR requires signature protection",
				}
			}

			// Validate based on request type.
			switch msg.Body.Type {
			case pkicmp.BodyTypeP10CR:
				if err := validateP10CR(msg); err != nil {
					return nil, err
				}
			case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR:
				if err := validateCRMF(msg); err != nil {
					return nil, err
				}
			}

			return next.HandleCMP(ctx, msg, sender)
		})
	}
}

func isCertRequest(t pkicmp.BodyType) bool {
	switch t {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		return true
	}
	return false
}

func validateP10CR(msg *pkicmp.PKIMessage) error {
	csr, err := msg.Body.P10CR()
	if err != nil {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat}
	}
	// RFC 4211 §4: the CSR self-signature proves possession of the key.
	if err := enforceProofOfPossession(msg); err != nil {
		return err
	}
	// RFC 9483 §4.1.1: Subject required.
	if len(csr.Subject.String()) == 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadCertTemplate, StatusText: "subject required"}
	}
	// RFC 5280 §4.2.1.9 path-length rules, plus the policy decision to refuse a
	// request for a CA certificate.
	return checkBasicConstraints(csr.Extensions)
}

func validateCRMF(msg *pkicmp.PKIMessage) error {
	crmf, err := parseCRMFMsg(msg)
	if err != nil {
		return err
	}

	// RFC 9483 §4.1.3: certReqId MUST be 0.
	if crmf.certReqID != 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "certReqId must be 0"}
	}

	// RFC 4211 §4 and RFC 9483 §5.1.1: the request must prove possession of the
	// requested key.
	if err := enforceProofOfPossession(msg); err != nil {
		return err
	}

	// RFC 9483 §4.1.1: Subject required.
	if len(crmf.subject.String()) == 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadCertTemplate, StatusText: "subject required"}
	}

	// RFC 5280 §4.2.1.9 path-length rules, plus the policy decision to refuse a
	// request for a CA certificate.
	return checkBasicConstraints(crmf.extensions)
}
