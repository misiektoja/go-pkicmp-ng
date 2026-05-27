package server

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// verifyProtection verifies message protection and returns the sender identity.
func (s *Server) verifyProtection(msg *pkicmp.PKIMessage) (*SenderIdentity, error) {
	if msg.Header.ProtectionAlg == nil || len(msg.Protection) == 0 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "message not protected"}
	}

	alg := msg.Header.ProtectionAlg.Algorithm

	// MAC-protected message.
	if isMACAlgorithm(alg) {
		if s.cfg.secretLookup == nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC protection not configured"}
		}

		// Resolve sender DN from header (may be NULL-DN for initial enrollment).
		var senderName pkix.Name
		if len(msg.Header.Sender.DirectoryName) > 0 {
			senderName.FillFromRDNSequence(&msg.Header.Sender.DirectoryName)
		}

		secret, err := s.cfg.secretLookup.LookupSecret(senderName, msg.Header.SenderKID)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "unknown sender"}
		}
		vr, err := msg.Verify(pkicmp.VerifyOptions{SharedSecret: secret})
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC verification failed"}
		}
		return &SenderIdentity{Sender: senderName, SenderKID: msg.Header.SenderKID, MACVerified: true, secret: secret, protectionParams: vr.ProtectionParams}, nil
	}

	// Signature-protected message.
	if s.cfg.certificateLookup == nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSignerNotTrusted, StatusText: "signature protection not configured"}
	}

	// Resolve sender DN from header.
	var senderName pkix.Name
	if len(msg.Header.Sender.DirectoryName) > 0 {
		senderName.FillFromRDNSequence(&msg.Header.Sender.DirectoryName)
	}

	// Resolve issuer from recipient header field.
	var issuerName pkix.Name
	if len(msg.Header.Recipient.DirectoryName) > 0 {
		issuerName.FillFromRDNSequence(&msg.Header.Recipient.DirectoryName)
	}

	// Look up the sender's certificate from the server's database.
	// RFC 9810 §5.1.1: senderKID SHOULD be used but is not mandatory.
	signerCert, err := s.cfg.certificateLookup.LookupCertificate(issuerName, senderName, msg.Header.SenderKID)
	if err != nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSignerNotTrusted, StatusText: "unknown sender"}
	}

	// Verify signature directly against the looked-up certificate.
	// No chain validation needed — the server trusts this certificate
	// because it came from its own database.
	_, err = msg.Verify(pkicmp.VerifyOptions{TrustedCert: signerCert})
	if err != nil {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSignerNotTrusted, StatusText: "signature verification failed"}
	}

	return &SenderIdentity{Certificate: signerCert, Sender: senderName}, nil
}

// isMACAlgorithm returns true if the OID is a supported MAC protection algorithm.
func isMACAlgorithm(oid asn1.ObjectIdentifier) bool {
	// OIDPasswordBasedMac = 1.2.840.113533.7.66.13
	// OIDPBMAC1 = 1.2.840.113549.1.5.14
	return oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}) ||
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14})
}

// protectResponseWithOptions applies protection using stored MAC options when available.
// protectionParams carries the decoded protection parameters for echo-back (RFC 9810 §5.1.3).
func (s *Server) protectResponseWithOptions(resp *pkicmp.PKIMessage, sender *SenderIdentity, protectionParams pkicmp.MACCredentialOption) error {
	// MAC-protected request → MAC-protect response with same secret.
	if sender != nil && sender.MACVerified && len(sender.secret) > 0 {
		var opts []pkicmp.MACCredentialOption
		if protectionParams != nil {
			opts = append(opts, protectionParams)
		}
		creds, err := pkicmp.NewMACCredentials(sender.secret, opts...)
		if err != nil {
			return err
		}
		return creds.Protect(resp)
	}

	// Signature protection.
	if s.cfg.signerKey != nil && s.cfg.signerCert != nil {
		creds, err := pkicmp.NewSignatureCredentials(s.cfg.signerKey, s.cfg.signerCert, s.cfg.signerChain...)
		if err != nil {
			return err
		}
		return creds.Protect(resp)
	}

	return nil
}
