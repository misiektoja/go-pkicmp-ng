package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// issuedInfoContextKey passes issuance details to the handler during certConf.
type issuedInfoContextKey struct{}

// issuedInfo bundles the issued certificate and the CA's opaque IssueRef.
type issuedInfo struct {
	cert     *x509.Certificate
	issueRef any
}

// IssuedCertFromContext retrieves the issued certificate stored by the server
// during certConf processing. Handlers can use this for certHash verification.
func IssuedCertFromContext(ctx context.Context) *x509.Certificate {
	info, _ := ctx.Value(issuedInfoContextKey{}).(issuedInfo)
	return info.cert
}

// IssueRefFromContext retrieves the opaque IssueRef stored by the server
// during certConf processing. This is the value the CA set in
// [Response.IssueRef] when it issued the certificate.
func IssueRefFromContext(ctx context.Context) any {
	info, _ := ctx.Value(issuedInfoContextKey{}).(issuedInfo)
	return info.issueRef
}

// handleCertConf processes certConf messages (RFC 9810 §5.3.18).
func (s *Server) handleCertConf(ctx context.Context, msg *pkicmp.PKIMessage, sender *SenderIdentity) *pkicmp.PKIMessage {
	conf, err := msg.Body.CertConf()
	if err != nil {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	// RFC 9483 §4.1: Reject contradictory CertStatus entries where status is
	// accepted but failInfo bits are set.
	for _, cs := range *conf {
		if cs.StatusInfo != nil && cs.StatusInfo.Status == pkicmp.StatusAccepted && cs.StatusInfo.FailInfo != 0 {
			return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadRequest,
				StatusString: pkicmp.PKIFreeText{"accepted status with failInfo set"},
			})
		}
	}

	// Look up the issued cert entry using composite key — automatically rejects different credentials.
	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID
	entry, exists := s.getIssued(credID, txnID)
	if !exists {
		// No pending transaction — reject.
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"unknown transaction"},
		})
	}

	// Verify certHash matches the issued certificate (RFC 9810 §5.3.18).
	if len(*conf) > 0 {
		expectedHash, err := computeCertHash(entry.cert)
		if err != nil {
			return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadAlg,
				StatusString: pkicmp.PKIFreeText{"cannot compute certHash"},
			})
		}
		if !bytes.Equal((*conf)[0].CertHash, expectedHash) {
			return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadCertId,
				StatusString: pkicmp.PKIFreeText{"certHash mismatch"},
			})
		}
	}

	// RFC 9483 §3.5: recipNonce MUST equal the senderNonce of the previous message.
	if len(msg.Header.RecipNonce) == 0 {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"missing recipNonce"},
		})
	}
	if !bytes.Equal(msg.Header.RecipNonce, entry.issuedSenderNonce) {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"recipNonce mismatch"},
		})
	}

	// RFC 9483 §3.5: senderNonce MUST be fresh (different from previous messages).
	if bytes.Equal(msg.Header.SenderNonce, entry.issuedSenderNonce) {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadSenderNonce,
			StatusString: pkicmp.PKIFreeText{"senderNonce reused"},
		})
	}
	// Also reject if the client reuses their original senderNonce from the cert request.
	if len(entry.clientSenderNonce) > 0 && bytes.Equal(msg.Header.SenderNonce, entry.clientSenderNonce) {
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadSenderNonce,
			StatusString: pkicmp.PKIFreeText{"senderNonce reused"},
		})
	}

	// certConf MUST NOT be signed with the newly issued certificate (security best practice).
	if sender != nil && sender.Certificate != nil && entry.cert != nil {
		if publicKeysEqual(sender.Certificate.PublicKey, entry.cert.PublicKey) {
			return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadMessageCheck,
				StatusString: pkicmp.PKIFreeText{"certConf signed with newly issued certificate"},
			})
		}
	}

	// Clean up stored cert and transaction.
	s.delete(credID, txnID)

	// Notify handler about the confirmation, passing issuance details via context.
	ctx = context.WithValue(ctx, issuedInfoContextKey{}, issuedInfo{cert: entry.cert, issueRef: entry.issueRef})
	_, _ = s.handler.HandleCMP(ctx, msg, sender)

	return s.buildResponseWithEchoProtection(msg, pkicmp.NewPKIConfBody(), sender, entry.protectionParams)
}

// computeCertHash computes the certificate hash using the hash algorithm
// matching the certificate's signature algorithm (RFC 9810 §5.3.18).
func computeCertHash(cert *x509.Certificate) ([]byte, error) {
	hash := hashFromCertSigAlg(cert.SignatureAlgorithm)
	if hash == 0 {
		return nil, nil // Unsupported algorithm, skip validation.
	}
	h := hash.New()
	h.Write(cert.Raw)
	return h.Sum(nil), nil
}

// hashFromCertSigAlg maps x509.SignatureAlgorithm to crypto.Hash.
func hashFromCertSigAlg(sigAlg x509.SignatureAlgorithm) crypto.Hash {
	switch sigAlg {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512
	case x509.PureEd25519:
		return crypto.SHA512 // RFC 9481 §3.3: EdDSA uses SHA-512 for certHash.
	default:
		return 0
	}
}

// publicKeysEqual compares two public keys by their PKIX-encoded form.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aDER, bDER)
}
