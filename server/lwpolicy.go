package server

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// LightweightPolicy returns middleware that enforces RFC 9483 Lightweight CMP Profile requirements.
// This is the default policy used by the server. Users can replace it with their own middleware.
func LightweightPolicy() Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) (*Response, error) {
			// RFC 9483 §3.1: MAC-protected messages MUST use directoryName in the sender field.
			if sender.MACVerified && len(msg.Header.Sender.DirectoryName) == 0 {
				return nil, &Error{
					Status:      pkicmp.StatusRejection,
					FailureInfo: pkicmp.FailBadMessageCheck,
					StatusText:  "MAC protection requires directoryName sender",
				}
			}

			// RFC 9483 §3.3: Signature-protected messages MUST include extraCerts.
			if !sender.MACVerified && len(msg.ExtraCerts) == 0 {
				return nil, &Error{
					Status:      pkicmp.StatusRejection,
					FailureInfo: pkicmp.FailBadMessageCheck,
					StatusText:  "signature protection without extraCerts",
				}
			}

			// RFC 9483 §3.5: For initial requests, extraCerts MUST contain the
			// complete certificate chain (signer cert + issuing CA certs).
			if !sender.MACVerified && isInitialRequest(msg.Body.Type) {
				if err := validateExtraCertsChain(msg.ExtraCerts); err != nil {
					return nil, &Error{
						Status:      pkicmp.StatusRejection,
						FailureInfo: pkicmp.FailBadMessageCheck,
						StatusText:  "incomplete certificate chain in extraCerts",
					}
				}
			}

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
	// Verify CSR signature.
	if err := csr.CheckSignature(); err != nil {
		if errors.Is(err, x509.ErrUnsupportedAlgorithm) {
			return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadAlg, StatusText: "unsupported signature algorithm"}
		}
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadPOP, StatusText: err.Error()}
	}
	// RFC 9483 §4.1.1: Subject required.
	if len(csr.Subject.String()) == 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadCertTemplate, StatusText: "subject required"}
	}
	// RFC 5280 §4.2.1.9: Validate BasicConstraints path-length.
	if err := validateBasicConstraints(csr.Extensions); err != nil {
		return err
	}
	// Policy: Reject requests for CA certificates.
		if hasCABasicConstraints(csr.Extensions) {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "CA certificates not allowed"}
	}
	return nil
}

// validateBasicConstraints checks RFC 5280 §4.2.1.9 constraints on path-length.
func validateBasicConstraints(extensions []pkix.Extension) error {
	oidBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}
	for _, ext := range extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional"`
			}
			if rest, err := asn1.Unmarshal(ext.Value, &bc); err == nil && len(rest) == 0 {
				if bc.MaxPathLen < 0 || (!bc.IsCA && bc.MaxPathLen != 0) {
					return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadCertTemplate, StatusText: "invalid path-length in BasicConstraints"}
				}
			}
		}
	}
	return nil
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

	// RFC 4211 §4: Verify POP.
	if err := verifyPOPMsg(msg); err != nil {
		failInfo := pkicmp.FailBadPOP
		// RFC 9810 §5.2.8.1: An end entity MUST NOT use raVerified.
		var parseErr *pkicmp.ParseError
		if errors.As(err, &parseErr) && parseErr.Detail == "raVerified POP not supported" {
			failInfo = pkicmp.FailNotAuthorized
		}
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: failInfo, StatusText: err.Error()}
	}

	// RFC 9483 §5.1.1: POP required for signature-capable keys.
	if crmf.popRequired && crmf.popMissing {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadPOP, StatusText: "POP required for signature key"}
	}

	// RFC 9483 §4.1.1: Subject required.
	if len(crmf.subject.String()) == 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadCertTemplate, StatusText: "subject required"}
	}

	// RFC 5280 §4.2.1.9: Validate BasicConstraints path-length.
	if err := validateBasicConstraints(crmf.extensions); err != nil {
		return err
	}

	// Policy: Reject requests for CA certificates.
	if hasCABasicConstraints(crmf.extensions) {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized, StatusText: "CA certificates not allowed"}
	}

	return nil
}
