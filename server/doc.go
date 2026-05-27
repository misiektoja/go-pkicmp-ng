// Package server implements a CMP server framework that can be embedded in a
// CA to add CMP support. It handles all protocol mechanics automatically:
// HTTP transport, message parsing, protection verification, response construction,
// nonce and transaction management, and the certConf round-trip.
//
// # Abstraction levels
//
// The package offers two levels of control:
//
//   - [CA] interface: implement certificate issuance; the framework handles the rest.
//   - [Handler] interface: receive the raw [pkicmp.PKIMessage] for full control
//     (RA proxying, custom routing, non-standard flows).
//
// Most callers should use [CA] via [NewCAServer].
//
// # CA interface
//
// Implement [CA.IssueCertificate]:
//
//	IssueCertificate(ctx context.Context, reqType RequestType,
//	    template *x509.Certificate, sender *SenderIdentity) (*Response, error)
//
// The template arrives with subject, public key, extensions, and SKI already
// populated from the CMP request. The CA has full control before signing:
// it must set SerialNumber and validity, and may enforce policy, override
// the subject, add or strip extensions, or reject the request outright.
//
// # Basic example
//
//	type myCA struct {
//	    key  crypto.Signer
//	    cert *x509.Certificate
//	}
//
//	func (c *myCA) IssueCertificate(ctx context.Context, reqType server.RequestType,
//	    tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
//
//	    tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
//	    tmpl.NotBefore = time.Now()
//	    tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)
//	    tmpl.KeyUsage = x509.KeyUsageDigitalSignature
//
//	    der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, tmpl.PublicKey, c.key)
//	    if err != nil {
//	        return nil, err
//	    }
//	    cert, _ := x509.ParseCertificate(der)
//	    return &server.Response{Certificate: cert}, nil
//	}
//
// Pass the CA implementation and credential lookups to [NewCAServer] along with
// the signing key, CA certificate, and middleware (or chain of middlewares).
//
//	srv := server.NewCAServer(ca,
//	    server.LightweightPolicy(),
//	    server.WithSigner(caKey, caCert),
//	    server.WithExtraCerts([]*x509.Certificate{caCert}),
//	    server.WithSecretLookup(server.SecretLookupFunc(lookupSecret)),
//	    server.WithCertificateLookup(server.CertificateLookupFunc(lookupCertificate)),
//	)
//	http.ListenAndServe(":8080", srv)
//
// [SecretLookup] and [CertificateLookup] supply credentials for MAC- and
// signature-protected messages respectively. See the Authentication section.
//
// # Optional interfaces
//
// CAs may implement additional optional interfaces:
//
//   - [PendingChecker]: asynchronous issuance with polling.
//   - [CertificateConfirmer]: notification when a client accepts or rejects a certificate.
//
// # Asynchronous issuance (polling)
//
// When a CA cannot issue immediately (pending approval, HSM queue), implement
// [PendingChecker]:
//
//	type PendingChecker interface {
//	    CheckPending(ctx context.Context, pollRef string, sender *SenderIdentity) (*Response, error)
//	}
//
// Flow:
//
//  1. Client sends IR/CR/KUR.
//  2. [CA.IssueCertificate] returns a [WaitingResponse]:
//     return &Response{Waiting: &WaitingResponse{CheckAfter: 30*time.Second, PollRef: "job-123"}}, nil
//  3. Server stores the pollRef and replies with a "waiting" status.
//  4. Client polls after [WaitingResponse.CheckAfter].
//  5. Server calls [PendingChecker.CheckPending] with the stored pollRef.
//  6. CA returns either the issued certificate or another [WaitingResponse].
//
// The pollRef is an opaque string the CA uses to correlate with its backend
// (a database ID, job reference, or any identifier). It works across server
// replicas when the CA uses shared storage.
//
// # Certificate confirmation
//
// Implement [CertificateConfirmer] to be notified when a client accepts or
// rejects a certificate ([ConfirmAccepted], [ConfirmRejected]), when implicit
// confirm is granted ([ConfirmImplicit]), or when the transaction expires
// ([ConfirmExpired]). The ref parameter echoes [Response.IssueRef] set during
// [CA.IssueCertificate] for correlation.
//
// # Authentication
//
// The server verifies every message's protection before passing it to the CA or
// Handler. The package does not provide a credential store; it defines the
// [SecretLookup] and [CertificateLookup] interfaces. Provide implementations
// via [WithSecretLookup] and [WithCertificateLookup].
//
// For MAC-protected messages, the server passes the sender DN and senderKID to
// [SecretLookup.LookupSecret]. RFC 9810 §5.1.1 covers two cases:
//
//   - Known sender: sender field carries the name, senderKID SHOULD be set.
//     Either or both may be used to locate the shared secret.
//   - Unknown sender (initial enrollment): sender MUST be a NULL-DN and senderKID
//     MUST carry the reference number identifying the shared secret (RFC 4210 §5.1.3.1).
//
// These fields are analogous to a username; the shared secret is the password.
// If two clients share the same identifier they become indistinguishable (shared
// transactions, possible certificate hijacking). The provisioning system must
// enforce uniqueness:
//
//	func Register(senderKID, secret []byte) error {
//	    if exists(senderKID) {
//	        return errors.New("senderKID already registered")
//	    }
//	    store[senderKID] = secret
//	}
//
//	func LookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error) {
//	    return store[senderKID]
//	}
//
// For signature-protected messages (e.g., KUR), the client's identity is its
// certificate. The sender DN in the header is used only as a lookup key — the
// server does not trust it. The flow is:
//
//  1. Server uses the sender DN to look up a candidate certificate from its store.
//  2. Server verifies the message signature against that certificate's public key.
//  3. If the client lied about the DN, the lookup fails or the signature does not verify.
//
// Trust comes from the certificate being in the server's store and the signature
// proving the client holds the corresponding private key.
//
//	func LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
//	    return certStore[issuer, subject]
//	}
//
// # Middleware
//
// [NewCAServer] requires a handler wrapper that implements authorization and
// request validation. The server handles authentication (verifying protection)
// but delegates authorization and other cross-cutting concerns (like audit logging,
// metrics tracking, or rate limiting) to wrappers. Without validation wrappers,
// any authenticated client could request any certificate.
//
// [LightweightPolicy] enforces the RFC 9483 Lightweight CMP Profile:
//
//   - Verifies Proof-of-Possession (POP) on CRMF requests.
//   - Requires KUR to use signature protection (not MAC).
//   - Validates that extraCerts contains a complete chain for signature-protected requests.
//   - Enforces subject presence in certificate templates.
//   - Rejects requests for CA certificates.
//   - Validates BasicConstraints path-length.
// Add custom authorization policy and logging using [MiddlewareChain].
// In this setup, `myPolicy()` runs before `LightweightPolicy()` to quickly reject
// unauthorized requests before performing verification against lightweight policy:
//
//	srv := server.NewCAServer(ca,
//	    server.MiddlewareChain(auditLog(logger), myPolicy(), server.LightweightPolicy()),
//	    server.WithSigner(caKey, caCert),
//	    server.WithExtraCerts([]*x509.Certificate{caCert}),
//	    server.WithSecretLookup(server.SecretLookupFunc(lookupSecret)),
//	    server.WithCertificateLookup(server.CertificateLookupFunc(lookupCertificate)),
//	)
//
// A middleware wraps a [Handler] to reject, inspect, or pass through requests:
//
//	func myPolicy() func(server.Handler) server.Handler {
//	    return func(next server.Handler) server.Handler {
//	        return server.HandlerFunc(func(ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity) (*server.Response, error) {
//	            if !isAllowed(sender) {
//	                return nil, &server.Error{
//	                    Status:      pkicmp.StatusRejection,
//	                    FailureInfo: pkicmp.FailNotAuthorized,
//	                    StatusText:  "not authorized",
//	                }
//	            }
//	            return next.HandleCMP(ctx, msg, sender)
//	        })
//	    }
//	}
//
//	func auditLog(logger *slog.Logger) func(server.Handler) server.Handler {
//	    return func(next server.Handler) server.Handler {
//	        return server.HandlerFunc(func(ctx context.Context, msg *pkicmp.PKIMessage, sender *server.SenderIdentity) (*server.Response, error) {
//	            logger.Info("CMP request received", "type", msg.Body.Type, "sender", sender.Sender)
//	            resp, err := next.HandleCMP(ctx, msg, sender)
//	            if err != nil {
//	                logger.Error("CMP request failed", "err", err)
//	            } else {
//	                logger.Info("CMP request succeeded")
//	            }
//	            return resp, err
//	        })
//	    }
//	}
//
// # Multiple CAs
//
// Each [Server] serves a single CA. To support multiple CAs, create separate
// Server instances and route by URL path. RFC 9483 §6.1 defines the well-known
// URI structure: /.well-known/cmp/p/<name>
//
//	mux := http.NewServeMux()
//	mux.Handle("/.well-known/cmp/p/ca1", server.NewCAServer(ca1,
//	    server.LightweightPolicy(),
//	    server.WithSigner(ca1Key, ca1Cert),
//	    server.WithExtraCerts([]*x509.Certificate{ca1Cert}),
//	    server.WithSecretLookup(ca1SecretLookup),
//	    server.WithCertificateLookup(ca1CertLookup),
//	))
//	mux.Handle("/.well-known/cmp/p/ca2", server.NewCAServer(ca2,
//	    server.LightweightPolicy(),
//	    server.WithSigner(ca2Key, ca2Cert),
//	    server.WithExtraCerts([]*x509.Certificate{ca2Cert}),
//	    server.WithSecretLookup(ca2SecretLookup),
//	    server.WithCertificateLookup(ca2CertLookup),
//	))
//	http.ListenAndServe(":8080", mux)
//
// # Transaction management
//
// The server tracks multi-message exchanges (IR→IP->CertConf->PKIConf and polling
// flows). Transactions are keyed by a composite of the client's cryptographically
// verified credentials and the client-supplied transactionID, preventing
// cross-client hijacking (RFC 9810 §5.1.1).
//
// To prevent resource exhaustion, the server enforces transaction caps:
//
//   - [WithMaxTransactions]: global cap on concurrent transactions (default 10000).
//   - [WithMaxTransactionsPerCredential]: per-client cap (default 100).
//
// When limits are exceeded, new requests are rejected with failInfo systemUnavail.
//
// [WithImplicitConfirm] eliminates the certConf round-trip when both server and
// client agree.
//
// Call [Server.CleanupExpired] periodically to remove completed and stale
// transactions:
//
//	go func() {
//	    for range time.Tick(time.Minute) {
//	        srv.CleanupExpired()
//	    }
//	}()
//
// Entries expire based on last activity time; the expiry duration is controlled
// by [WithConfirmWaitTime] (default 10 seconds).
package server
