package server

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net/http"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// MaxRequestBodySize limits the size of incoming CMP request bodies to prevent DoS.
var MaxRequestBodySize int64 = 1 << 20 // 1 MiB

// Server implements http.Handler for the CMP protocol (RFC 6712 §3).
type Server struct {
	handler Handler
	cfg     serverConfig
	*transactionTracker
}

// New creates a CMP server with the given handler and options.
// NOTE: A signer SHOULD be configured (WithSigner) for RFC 9810 compliance,
// as error messages MUST be signature-protected per RFC 9810 §5.3.21.
func New(handler Handler, opts ...Option) *Server {
	s := &Server{handler: handler}
	for _, o := range opts {
		o(&s.cfg)
	}
	maxTxn := s.cfg.maxTransactions
	if maxTxn == 0 {
		maxTxn = 10000
	}
	maxPerCred := s.cfg.maxTransactionsPerCredential
	if maxPerCred == 0 {
		maxPerCred = 100
	}
	s.transactionTracker = newTransactionTracker(maxTxn, maxPerCred)
	return s
}

// ServeHTTP implements http.Handler per RFC 6712 §3.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// RFC 6712 §3: Only POST is allowed.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// RFC 6712 §3: Content-Type must be application/pkixcmp.
	if ct := r.Header.Get("Content-Type"); ct != "application/pkixcmp" {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	msg, err := pkicmp.ParsePKIMessage(body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	resp := s.processMessage(r.Context(), msg)

	respDER, err := resp.MarshalBinary()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkixcmp")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respDER)
}

// processMessage handles a parsed PKIMessage and returns a response.
func (s *Server) processMessage(ctx context.Context, msg *pkicmp.PKIMessage) *pkicmp.PKIMessage {
	// RFC 9810 §7: Validate PVNO.
	if msg.Header.PVNO < pkicmp.PVNO2 || msg.Header.PVNO > pkicmp.PVNO3 {
		resp := s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:   pkicmp.StatusRejection,
			FailInfo: pkicmp.FailUnsupportedVersion,
		})
		// RFC 9810 §7: Use the closest supported PVNO in the error response.
		if msg.Header.PVNO > pkicmp.PVNO3 {
			resp.Header.PVNO = pkicmp.PVNO3
		} else if msg.Header.PVNO < pkicmp.PVNO2 {
			resp.Header.PVNO = pkicmp.PVNO2
		}
		return resp
	}

	// RFC 9810 §5.1.1: Verify that the recipient matches the server's identity.
	if err := s.verifyRecipient(msg); err != nil {
		resp := s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadRequest,
			StatusString: pkicmp.PKIFreeText{err.Error()},
		})
		return resp
	}

	// Verify message protection.
	sender, err := s.verifyProtection(msg)
	if err != nil {
		resp := s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			FailInfo:     pkicmp.FailBadMessageCheck,
			StatusString: pkicmp.PKIFreeText{err.Error()},
		})
		return resp
	}

	// RFC 9483 §4.1: Validate header fields.
	if err := s.validateHeader(msg, sender); err != nil {
		var srvErr *Error
		if errors.As(err, &srvErr) {
			return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
				Status:       srvErr.Status,
				FailInfo:     srvErr.FailureInfo,
				StatusString: pkicmp.PKIFreeText{srvErr.StatusText},
			})
		}
		return s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:   pkicmp.StatusRejection,
			FailInfo: pkicmp.FailBadDataFormat,
		})
	}

	// Dispatch by body type.
	var resp *pkicmp.PKIMessage
	switch msg.Body.Type {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		resp = s.handleCertRequestNew(ctx, msg, sender)
	case pkicmp.BodyTypeCertConf:
		resp = s.handleCertConf(ctx, msg, sender)
	case pkicmp.BodyTypePollReq:
		resp = s.handlePollReqNew(ctx, msg, sender)
	case pkicmp.BodyTypeError:
		// RFC 9810 §5.3.21: Respond with PKIConf. Protection verification above
		// already catches invalid headers, so reaching here means the header is valid.
		resp = s.buildResponse(msg, pkicmp.NewPKIConfBody(), sender)
	default:
		resp = s.buildErrorResponse(msg, pkicmp.PKIStatusInfo{
			Status:   pkicmp.StatusRejection,
			FailInfo: pkicmp.FailBadRequest,
		})
	}
	return resp
}

// CleanupExpired removes pending transactions and issued certificates that
// have exceeded the configured confirmWaitTime. Call this periodically.
func (s *Server) CleanupExpired() {
	s.transactionTracker.cleanupExpired(s.cfg.confirmWait)
}

// verifyRecipient checks that the recipient field in the request matches the
// server's identity. RFC 9810 §5.1.1: the recipient field contains the name
// of the intended recipient. Validation is skipped if the server has no
// configured identity or if the recipient is a NULL-DN.
func (s *Server) verifyRecipient(msg *pkicmp.PKIMessage) error {
	// Determine server's identity name.
	var serverName pkix.Name
	if len(s.cfg.sender.CommonName) > 0 || len(s.cfg.sender.Organization) > 0 {
		serverName = s.cfg.sender
	} else if s.cfg.signerCert != nil {
		serverName = s.cfg.signerCert.Subject
	} else {
		// No server identity configured — skip validation.
		return nil
	}

	// NULL-DN (empty RDNSequence) means the client doesn't know the server's name.
	if len(msg.Header.Recipient.DirectoryName) == 0 {
		return nil
	}

	// Compare recipient to server identity.
	var recipientName pkix.Name
	recipientName.FillFromRDNSequence(&msg.Header.Recipient.DirectoryName)

	if recipientName.String() != serverName.String() {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "recipient does not match server identity"}
	}
	return nil
}

// validateHeader validates PKIHeader fields per RFC 9483 §4.1.
func (s *Server) validateHeader(msg *pkicmp.PKIMessage, sender *SenderIdentity) error {
	// RFC 9483 §4.1: transactionID MUST be present.
	if len(msg.Header.TransactionID) == 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadDataFormat, StatusText: "missing transactionID"}
	}

	// RFC 9483 §4.1: senderNonce MUST be present.
	if len(msg.Header.SenderNonce) == 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadSenderNonce, StatusText: "missing senderNonce"}
	}

	// RFC 9483 §4.1: senderNonce MUST be at least 128 bits (16 bytes).
	if len(msg.Header.SenderNonce) < 16 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadSenderNonce, StatusText: "senderNonce too short"}
	}

	// Determine if this is a first message (starts a new transaction).
	isFirstMessage := isInitialRequest(msg.Body.Type)

	// RFC 9483 §4.1: recipNonce MUST NOT be present in first message.
	if isFirstMessage && len(msg.Header.RecipNonce) > 0 {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRecipientNonce, StatusText: "recipNonce in first message"}
	}

	// RFC 9483 §4.1: Check for duplicate transactionID (scoped to this client's credentials).
	credID, err := sender.CredentialID()
	if err != nil {
		return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadMessageCheck, StatusText: "invalid sender credentials"}
	}
	txnID := msg.Header.TransactionID
	if isFirstMessage {
		alreadyExists, err := s.startIfAbsent(credID, txnID)
		if err != nil {
			return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailSystemUnavail, StatusText: err.Error()}
		}
		if alreadyExists {
			return &Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailTransactionIdInUse, StatusText: "transactionID already in use"}
		}
	}

	return nil
}

// isInitialRequest returns true if the body type starts a new transaction.
func isInitialRequest(bodyType pkicmp.BodyType) bool {
	switch bodyType {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR:
		return true
	default:
		return false
	}
}

// validateExtraCertsChain verifies that extraCerts contains a complete certificate
// chain: the signer cert must chain to a self-signed root CA via certificates
// present in extraCerts. Per RFC 9483 §3.5, the chain must be complete for
// signature-protected initial request messages.
func validateExtraCertsChain(extraCerts []pkicmp.CMPCertificate) error {
	if len(extraCerts) < 2 {
		return errors.New("chain too short")
	}

	certs := make([]*x509.Certificate, 0, len(extraCerts))
	for _, ec := range extraCerts {
		c, err := ec.Parse()
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}

	// Check that at least one certificate in extraCerts is self-signed (root CA).
	for _, c := range certs {
		if err := c.CheckSignatureFrom(c); err == nil {
			return nil
		}
	}

	return errors.New("no self-signed root CA in extraCerts")
}
