package server

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/tsaarni/go-pkicmp/pkicmp"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// verifyProtection verifies message protection and returns the sender identity.
func (s *Server) verifyProtection(msg *pkicmp.PKIMessage) (*SenderIdentity, error) {
	if msg.Header.ProtectionAlg == nil || len(msg.Protection) == 0 {
		return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "message not protected"}
	}

	alg := msg.Header.ProtectionAlg.Algorithm

	// MAC-protected message.
	if alg.Equal(pkicmp.OIDPasswordBasedMac) || alg.Equal(pkicmp.OIDPBMAC1) {
		if s.cfg.secretLookup == nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC protection not configured"}
		}
		secret, err := s.cfg.secretLookup.LookupSecret(msg.Header.SenderKID)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "unknown sender"}
		}
		creds, err := pkicmp.NewMACCredentials(secret)
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "invalid secret"}
		}
		_, err = msg.Verify(pkicmp.VerifyOptions{Credentials: creds})
		if err != nil {
			return nil, &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "MAC verification failed"}
		}
		return &SenderIdentity{SenderKID: msg.Header.SenderKID, MACVerified: true}, nil
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

	// Look up the sender's certificate from the server's database.
	// RFC 9810 §5.1.1: senderKID SHOULD be used but is not mandatory.
	signerCert, err := s.cfg.certificateLookup.LookupCertificate(senderName, msg.Header.SenderKID)
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

	return &SenderIdentity{Certificate: signerCert}, nil
}

// protectResponseWithOptions applies protection using stored MAC options when available.
func (s *Server) protectResponseWithOptions(resp *pkicmp.PKIMessage, sender *SenderIdentity, macOpts *pkicmp.MACOptions) error {
	// MAC-protected request → MAC-protect response with same secret.
	if sender != nil && sender.MACVerified && s.cfg.secretLookup != nil {
		secret, err := s.cfg.secretLookup.LookupSecret(sender.SenderKID)
		if err == nil && len(secret) > 0 {
			if macOpts != nil {
				// Echo back the client's MAC parameters (fresh salt is generated).
				if macOpts.Algorithm.Equal(pkicmp.OIDPBMAC1) {
					// RFC 9481 §6.1.2: PBMAC1 protection.
					return resp.ProtectWithPBMAC1Options(pkicmp.PBMAC1Options{
						Secret:         secret,
						IterationCount: macOpts.IterationCount,
						KeyLength:      macOpts.KeyLength,
						PRF:            macOpts.OWF,
						MAC:            macOpts.MAC,
					})
				}
				opts := *macOpts
				opts.Secret = secret
				return resp.ProtectWithMACOptions(opts)
			}
			// extractMACOptions must succeed for any message that passed MAC verification.
			return fmt.Errorf("internal error: MAC-verified message has no parseable MAC parameters")
		}
	}

	// Signature protection.
	if s.cfg.signerKey != nil && s.cfg.signerCert != nil {
		return resp.ProtectWithSignature(s.cfg.signerKey, s.cfg.signerCert, s.cfg.signerChain...)
	}

	return nil
}

// extractMACOptions extracts PBM/PBMAC1 parameters from a MAC-protected request message.
// Returns nil if the message is not MAC-protected or parameters cannot be parsed.
func extractMACOptions(msg *pkicmp.PKIMessage) *pkicmp.MACOptions {
	if msg.Header.ProtectionAlg == nil {
		return nil
	}
	if len(msg.Header.ProtectionAlg.Parameters) == 0 {
		return nil
	}

	alg := msg.Header.ProtectionAlg.Algorithm

	// RFC 8018 §7.1: PBMAC1 parameters.
	if alg.Equal(pkicmp.OIDPBMAC1) {
		return extractPBMAC1Options(msg.Header.ProtectionAlg.Parameters)
	}

	if !alg.Equal(pkicmp.OIDPasswordBasedMac) {
		return nil
	}

	// Parse PBMParameter from the protectionAlg parameters.
	s := cryptobyte.String(msg.Header.ProtectionAlg.Parameters)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil
	}
	// Skip salt (OCTET STRING).
	var salt []byte
	if !seq.ReadASN1Bytes(&salt, cbasn1.OCTET_STRING) {
		return nil
	}
	// Read OWF AlgorithmIdentifier.
	var owfSeq cryptobyte.String
	if !seq.ReadASN1(&owfSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var owfOID asn1.ObjectIdentifier
	if !owfSeq.ReadASN1ObjectIdentifier(&owfOID) {
		return nil
	}
	// Capture any remaining parameters (e.g., NULL).
	var owfParams []byte
	if !owfSeq.Empty() {
		var params cryptobyte.String
		var tag cbasn1.Tag
		if owfSeq.ReadAnyASN1Element(&params, &tag) {
			owfParams = params
		}
	}
	// Read iterationCount.
	var iterCount int64
	if !seq.ReadASN1Integer(&iterCount) {
		return nil
	}
	// Read MAC AlgorithmIdentifier.
	var macSeq cryptobyte.String
	if !seq.ReadASN1(&macSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var macOID asn1.ObjectIdentifier
	if !macSeq.ReadASN1ObjectIdentifier(&macOID) {
		return nil
	}
	// Capture any remaining parameters (e.g., NULL).
	var macParams []byte
	if !macSeq.Empty() {
		var params cryptobyte.String
		var tag cbasn1.Tag
		if macSeq.ReadAnyASN1Element(&params, &tag) {
			macParams = params
		}
	}

	return &pkicmp.MACOptions{
		Algorithm:      pkicmp.OIDPasswordBasedMac,
		IterationCount: int(iterCount),
		OWF:            owfOID,
		MAC:            macOID,
		OWFParameters:  owfParams,
		MACParameters:  macParams,
	}
}

// extractPBMAC1Options parses PBMAC1-params (RFC 8018 §A.4) from protectionAlg parameters.
// PBMAC1-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier, messageAuthScheme AlgorithmIdentifier }
func extractPBMAC1Options(params []byte) *pkicmp.MACOptions {
	s := cryptobyte.String(params)
	var outer cryptobyte.String
	if !s.ReadASN1(&outer, cbasn1.SEQUENCE) {
		return nil
	}

	// keyDerivationFunc AlgorithmIdentifier (OID = id-PBKDF2).
	var kdfSeq cryptobyte.String
	if !outer.ReadASN1(&kdfSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var kdfOID asn1.ObjectIdentifier
	if !kdfSeq.ReadASN1ObjectIdentifier(&kdfOID) {
		return nil
	}
	if !kdfOID.Equal(pkicmp.OIDPBKDF2) {
		return nil
	}

	// PBKDF2-params: SEQUENCE { salt, iterationCount, [keyLength], [prf] }
	var pbkdf2Params cryptobyte.String
	if !kdfSeq.ReadASN1(&pbkdf2Params, cbasn1.SEQUENCE) {
		return nil
	}
	// Skip salt (OCTET STRING).
	var salt []byte
	if !pbkdf2Params.ReadASN1Bytes(&salt, cbasn1.OCTET_STRING) {
		return nil
	}
	// Read iterationCount.
	var iterCount int64
	if !pbkdf2Params.ReadASN1Integer(&iterCount) {
		return nil
	}
	// Skip optional keyLength (INTEGER) if present, then read prf.
	// RFC 8018 §A.2: keyLength is OPTIONAL INTEGER, prf is OPTIONAL SEQUENCE.
	var keyLength int64
	prfOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9} // default: hmacWithSHA256
	if !pbkdf2Params.Empty() {
		var peek cryptobyte.String
		var tag cbasn1.Tag
		if !pbkdf2Params.ReadAnyASN1Element(&peek, &tag) {
			return nil
		}
		if tag == cbasn1.INTEGER {
			// Was keyLength; parse its value.
			inner := cryptobyte.String(peek)
			if !inner.ReadASN1Integer(&keyLength) {
				return nil
			}
			// Read prf if present.
			if !pbkdf2Params.Empty() {
				var prfSeq cryptobyte.String
				if pbkdf2Params.ReadASN1(&prfSeq, cbasn1.SEQUENCE) {
					prfSeq.ReadASN1ObjectIdentifier(&prfOID)
				}
			}
		} else if tag == cbasn1.SEQUENCE {
			// Was prf directly (no keyLength).
			inner := cryptobyte.String(peek)
			var prfSeq cryptobyte.String
			if inner.ReadASN1(&prfSeq, cbasn1.SEQUENCE) {
				prfSeq.ReadASN1ObjectIdentifier(&prfOID)
			}
		}
	}

	// messageAuthScheme AlgorithmIdentifier.
	var macSeq cryptobyte.String
	if !outer.ReadASN1(&macSeq, cbasn1.SEQUENCE) {
		return nil
	}
	var macOID asn1.ObjectIdentifier
	if !macSeq.ReadASN1ObjectIdentifier(&macOID) {
		return nil
	}

	return &pkicmp.MACOptions{
		Algorithm:      pkicmp.OIDPBMAC1,
		IterationCount: int(iterCount),
		KeyLength:      int(keyLength),
		OWF:            prfOID, // Reuse OWF field for PRF OID.
		MAC:            macOID,
	}
}
