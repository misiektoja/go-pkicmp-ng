package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
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
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	// RFC 9483 §4.1: Reject contradictory CertStatus entries where status is
	// accepted but failInfo bits are set.
	for _, cs := range *conf {
		if cs.StatusInfo != nil && cs.StatusInfo.Status == pkicmp.StatusAccepted && cs.StatusInfo.FailInfo != 0 {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadRequest,
				StatusString: pkicmp.PKIFreeText{"accepted status with failInfo set"},
			})
		}
	}

	// Look up the issued cert entry using composite key — automatically rejects different credentials.
	credID, err := sender.credentialID()
	if err != nil {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck,
		})
	}
	txnID := msg.Header.TransactionID
	entry, exists := s.getIssued(credID, txnID)
	if !exists {
		// No pending transaction — reject.
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{"unknown transaction"},
		})
	}

	// Verify certHash matches the issued certificate (RFC 9810 §5.3.18).
	if len(*conf) > 0 {
		expectedHash, err := pkicmp.CertHash(entry.cert)
		if err != nil {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadAlg,
				StatusString: pkicmp.PKIFreeText{"cannot compute certHash"},
			})
		}
		if !bytes.Equal((*conf)[0].CertHash, expectedHash) {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadCertId,
				StatusString: pkicmp.PKIFreeText{"certHash mismatch"},
			})
		}
	}

	// RFC 9483 §3.5: recipNonce MUST equal the senderNonce of the previous message.
	if len(msg.Header.RecipNonce) == 0 {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"missing recipNonce"},
		})
	}
	if !bytes.Equal(msg.Header.RecipNonce, entry.issuedSenderNonce) {
		return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRecipientNonce,
			StatusString: pkicmp.PKIFreeText{"recipNonce mismatch"},
		})
	}

	// A repeated senderNonce is only rejected under WithStrictProfileValidation.
	// RFC 9483 §3.1 tells the sender to generate a fresh nonce, but the
	// receiver-side checks §3.5 requires are just that senderNonce is present
	// and long enough and that recipNonce matches, both enforced above.
	// Rejecting a repeat by default would discard an already-issued certificate
	// over a peer-side generation defect that deployed clients exhibit.
	if s.cfg.strictProfile {
		repeatsServerNonce := bytes.Equal(msg.Header.SenderNonce, entry.issuedSenderNonce)
		repeatsOwnNonce := len(entry.clientSenderNonce) > 0 && bytes.Equal(msg.Header.SenderNonce, entry.clientSenderNonce)
		if repeatsServerNonce || repeatsOwnNonce {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadSenderNonce,
				StatusString: pkicmp.PKIFreeText{"senderNonce reused"},
			})
		}
	}

	// certConf MUST NOT be signed with the newly issued certificate (security best practice).
	if sender != nil && sender.Certificate != nil && entry.cert != nil {
		if publicKeysEqual(sender.Certificate.PublicKey, entry.cert.PublicKey) {
			return s.buildErrorResponse(msg, sender, pkicmp.PKIStatusInfo{
				Status:       pkicmp.StatusRejection,
				FailInfo:     pkicmp.FailBadMessageCheck,
				StatusString: pkicmp.PKIFreeText{"certConf signed with newly issued certificate"},
			})
		}
	}

	// Notify handler about the confirmation, passing issuance details via context.
	ctx = context.WithValue(ctx, issuedInfoContextKey{}, issuedInfo{cert: entry.cert, issueRef: entry.issueRef})
	if _, err := s.handler.HandleCMP(ctx, msg, sender); err != nil {
		// RFC 9483 §3.6.2: an error condition on a certConf MUST be reported
		// downstream. Keep the transaction so the client can retry and so the
		// CA still gets ConfirmExpired if no retry succeeds.
		return s.buildResponseWithEchoProtection(msg, pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{
			PKIStatusInfo: errorToStatusInfo(err),
		}), sender, entry.protectionParams)
	}

	// Confirmation recorded — release the transaction.
	s.delete(credID, txnID)

	return s.buildResponseWithEchoProtection(msg, pkicmp.NewPKIConfBody(), sender, entry.protectionParams)
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
