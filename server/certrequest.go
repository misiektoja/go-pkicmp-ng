package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

type parsedCRMF struct {
	certReqID   int64
	subject     pkix.Name
	publicKey   crypto.PublicKey
	extensions  []pkix.Extension
	popMissing  bool // POP not present in request
	popRequired bool // Key type requires POP (signature-capable)
}

// parseCRMFMsg extracts fields from a CRMF request body.
func parseCRMFMsg(msg *pkicmp.PKIMessage) (*parsedCRMF, error) {
	var msgs *pkicmp.CertReqMessages
	var err error
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR:
		msgs, err = msg.Body.IR()
	case pkicmp.BodyTypeCR:
		msgs, err = msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		msgs, err = msg.Body.KUR()
	default:
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest}
	}
	if err != nil {
		return nil, err
	}
	if len(*msgs) == 0 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat, StatusText: "empty CertReqMessages"}
	}
	if len(*msgs) > 1 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "multiple CertReqMsg not supported"}
	}

	reqMsg := (*msgs)[0]
	result := &parsedCRMF{certReqID: reqMsg.CertReq.CertReqID}

	// Extract subject.
	if len(reqMsg.CertReq.CertTemplate.Subject.DirectoryName) > 0 {
		var name pkix.Name
		name.FillFromRDNSequence(&reqMsg.CertReq.CertTemplate.Subject.DirectoryName)
		result.subject = name
	}

	// Extract public key.
	if len(reqMsg.CertReq.CertTemplate.PublicKey) > 0 {
		pub, err := x509.ParsePKIXPublicKey(reqMsg.CertReq.CertTemplate.PublicKey)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadAlg, StatusText: err.Error()}
		}
		result.publicKey = pub

		// Check if key type requires POP (signature-capable keys).
		result.popRequired = isSignatureCapableKey(pub)
	}

	// Check if POP is missing.
	result.popMissing = reqMsg.Popo == nil || reqMsg.Popo.Signature == nil

	// Extract extensions.
	if len(reqMsg.CertReq.CertTemplate.Extensions) > 0 {
		var exts []pkix.Extension
		rest := reqMsg.CertReq.CertTemplate.Extensions
		// Parse DER SEQUENCE OF Extension using encoding/asn1.
		if _, err := asn1.Unmarshal(rest, &exts); err != nil {
			return nil, err
		}
		result.extensions = exts
	}

	return result, nil
}

// verifyPOPMsg verifies the Proof of Possession for CRMF requests.
// RFC 4211 §4: Delegates to pkicmp.VerifyPOP.
func verifyPOPMsg(msg *pkicmp.PKIMessage) error {
	var msgs *pkicmp.CertReqMessages
	var err error
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR:
		msgs, err = msg.Body.IR()
	case pkicmp.BodyTypeCR:
		msgs, err = msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		msgs, err = msg.Body.KUR()
	default:
		return nil
	}
	if err != nil || len(*msgs) == 0 {
		return err
	}

	return pkicmp.VerifyPOP(&(*msgs)[0])
}

// isSignatureCapableKey returns true if the key can be used for signing.
// RSA, ECDSA, and EdDSA keys are signature-capable.
func isSignatureCapableKey(pub crypto.PublicKey) bool {
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

// hasCABasicConstraints checks if extensions contain BasicConstraints with cA=true.
// Handlers can use this to reject CA certificate requests as a policy decision.
func hasCABasicConstraints(extensions []pkix.Extension) bool {
	// OID for BasicConstraints: 2.5.29.19
	oidBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}

	for _, ext := range extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
				return true
			}
		}
	}
	return false
}

