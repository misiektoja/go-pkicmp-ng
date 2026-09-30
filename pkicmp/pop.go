package pkicmp

import (
	"crypto/x509"
	"errors"
	"fmt"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

// POPOptions configures [VerifyPOPWithOptions].
type POPOptions struct {
	// AllowSHA1Signatures accepts a signature proof made with
	// sha1WithRSAEncryption or ecdsa-with-SHA1, which RFC 9481 §7.1 deprecates.
	AllowSHA1Signatures bool
}

// VerifyPOP verifies the Proof of Possession signature on a CertReqMsg.
// RFC 4211 §4: Only signature POP is supported; raVerified is rejected.
// Returns nil if POP is valid or not present.
func VerifyPOP(reqMsg *CertReqMsg) error {
	return VerifyPOPWithOptions(reqMsg, POPOptions{})
}

// VerifyPOPWithOptions verifies the Proof of Possession signature on a CertReqMsg as [VerifyPOP] does, applying opts.
func VerifyPOPWithOptions(reqMsg *CertReqMsg, opts POPOptions) error {
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
	pub, err := compositex509.ParsePKIXPublicKey(reqMsg.CertReq.CertTemplate.PublicKey)
	if err != nil {
		return fmt.Errorf("pkicmp: parse public key for POP: %w", err)
	}

	// Use the raw DER captured during parsing.
	certReqDER := reqMsg.CertReq.Raw
	if len(certReqDER) == 0 {
		return &ParseError{Detail: "no raw CertRequest DER available for POP verification"}
	}

	composite, ok, err := compositeSignatureAlgorithm(reqMsg.Popo.Signature.Algorithm)
	if err != nil {
		return err
	}
	key, isComposite := pub.(*compositemldsa.PublicKey)
	if ok || isComposite {
		// A composite algorithm fixes both component keys, so it must match the requested key exactly.
		if !ok || !isComposite || key.Algorithm() != composite {
			return errors.New("pkicmp: POP algorithm does not match the requested public key")
		}
		return compositemldsa.Verify(key, certReqDER, reqMsg.Popo.Signature.Signature, nil)
	}

	// Verify signature using the algorithm from popoSigningKey.
	sigAlg, err := signatureAlgorithm(reqMsg.Popo.Signature.Algorithm, opts.AllowSHA1Signatures)
	if err != nil {
		return err
	}

	// Create a minimal x509.Certificate to use CheckSignature.
	verifier := &x509.Certificate{PublicKey: pub}
	return verifier.CheckSignature(sigAlg, certReqDER, reqMsg.Popo.Signature.Signature)
}
