package pkicmp

import (
	"crypto/x509"
	"fmt"
)

// VerifyPOP verifies the Proof of Possession signature on a CertReqMsg.
// RFC 4211 §4: Only signature POP is supported; raVerified is rejected.
// Returns nil if POP is valid or not present.
func VerifyPOP(reqMsg *CertReqMsg) error {
	if reqMsg.Popo == nil {
		return nil // No POP present — allowed for some profiles.
	}
	if reqMsg.Popo.RAVerified {
		return &ParseError{Detail: "raVerified POP not supported"}
	}
	if reqMsg.Popo.Signature == nil {
		return nil // Other POP types not verified here.
	}

	// Get public key from cert template.
	if len(reqMsg.CertReq.CertTemplate.PublicKey) == 0 {
		return &ParseError{Detail: "no public key in template for POP verification"}
	}
	pub, err := x509.ParsePKIXPublicKey(reqMsg.CertReq.CertTemplate.PublicKey)
	if err != nil {
		return fmt.Errorf("pkicmp: parse public key for POP: %w", err)
	}

	// Use the raw DER captured during parsing.
	certReqDER := reqMsg.CertReq.Raw
	if len(certReqDER) == 0 {
		return &ParseError{Detail: "no raw CertRequest DER available for POP verification"}
	}

	// Verify signature using the algorithm from popoSigningKey.
	sigAlg, err := sigAlgFromOID(reqMsg.Popo.Signature.Algorithm.Algorithm)
	if err != nil {
		return err
	}

	// Create a minimal x509.Certificate to use CheckSignature.
	verifier := &x509.Certificate{PublicKey: pub}
	return verifier.CheckSignature(sigAlg, certReqDER, reqMsg.Popo.Signature.Signature)
}
