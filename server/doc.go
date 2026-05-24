// Package server implements a CMP protocol server that can be embedded in a
// CA or RA to add CMP support. It handles all protocol mechanics —
// HTTP transport, message parsing, protection verification, response
// construction, nonce/transaction management, and the certConf round-trip.
//
// # Server Levels
//
// The package provides two abstraction levels:
//
//   - [Handler] interface: Low-level, full control over CMP message handling.
//   - [CA] interface: High-level, just implement certificate issuance.
//
// Most users should use the [CA] interface via [NewCAServer].
//
// # CA Interface
//
// The [CA] interface requires one method:
//
//	type CA interface {
//	    IssueCertificate(ctx, reqType, template, sender) (*Response, error)
//	}
//
// [CA.IssueCertificate] receives a certificate template with subject, public key,
// extensions, and SKI pre-populated from the CMP request. The CA sets the serial
// number, validity period, key usage, and signs the certificate.
//
// # Basic Example
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
//	func lookupSecret(sender pkix.Name, senderKID []byte) ([]byte, error) {
//	    return []byte("shared-secret"), nil
//	}
//
//	func lookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
//	    return nil, errors.New("not found")
//	}
//
//	// Create server
//	srv := server.NewCAServer(ca, caKey, caCert,
//	    []server.Middleware{server.LightweightPolicy()},
//	    server.WithSecretLookup(server.SecretLookupFunc(lookupSecret)),
//	    server.WithCertificateLookup(server.CertificateLookupFunc(lookupCertificate)),
//	)
//	http.ListenAndServe(":8080", srv)
//
// # Optional Interfaces
//
// CAs may implement additional optional interfaces:
//
//   - [PendingChecker]: For asynchronous certificate issuance with polling.
//   - [CertificateConfirmer]: To receive certificate confirmation notifications.
//
// # Asynchronous Issuance (Polling)
//
// For CAs that cannot issue certificates immediately (e.g., pending approval,
// HSM queue), implement the [PendingChecker] interface:
//
//	type PendingChecker interface {
//	    CheckPending(ctx context.Context, pollRef string, sender *SenderIdentity) (*Response, error)
//	}
//
// The polling flow works as follows:
//
//  1. Client sends IR/CR/KUR request.
//  2. [CA.IssueCertificate] returns [Response] with [WaitingResponse] set:
//     return &Response{Waiting: &WaitingResponse{CheckAfter: 30*time.Second, PollRef: "job-123"}}, nil
//  3. Server stores pollRef and responds with "waiting" status.
//  4. Client polls after CheckAfter duration.
//  5. Server calls [PendingChecker.CheckPending] with the stored pollRef.
//  6. CA checks its backend using pollRef and returns either:
//     - Certificate ready: &Response{Certificate: cert}
//     - Still waiting: &Response{Waiting: &WaitingResponse{...}}
//
// The pollRef is an opaque string the CA uses to correlate with its backend
// operation. It can be a database ID, job reference, or any identifier that
// allows the CA to check the status. This works across server replicas if
// the CA uses shared storage.
//
// # Certificate Confirmation
//
// To receive notifications when clients confirm or reject certificates,
// implement [CertificateConfirmer]:
//
//	type CertificateConfirmer interface {
//	    ConfirmCertificate(ctx context.Context, cert *x509.Certificate, accepted bool) error
//	}
//
// The cert parameter is the certificate that was issued. The CA can use
// cert.SerialNumber or any other field to identify which certificate was
// confirmed.
//
// # Authentication
//
// This package does not provide a credential store; it only defines the
// [SecretLookup] and [CertificateLookup] read interfaces. The caller provides
// the backing store, wires it with [WithSecretLookup] and [WithCertificateLookup],
// and must enforce uniqueness of credentials at provisioning time.
//
// For MAC-protected messages, the server passes both the sender DN and the
// senderKID to [SecretLookup.LookupSecret]. The implementation decides which
// fields to use for the lookup. RFC 9810 §5.1.1 describes two cases:
//
//   - When the sender is known, the sender field carries the sender's name and
//     senderKID SHOULD be included (RFC 9810 §5.1.1). Either or both may be
//     used to locate the shared secret.
//   - When the sender is unknown (e.g., initial enrollment), the sender field
//     MUST be a NULL-DN and the senderKID field MUST carry the reference number
//     that identifies the shared secret (RFC 4210 §5.1.3.1).
//
// These identifier fields are analogous to a username and the shared secret to
// a password. The server identifies clients by whichever fields the lookup uses.
// If two clients share the same identifier they become indistinguishable (shared
// transactions, shared rate limits, possible certificate hijacking). Uniqueness
// must be enforced by the provisioning system:
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
// certificate, not the senderKID. The sender DN in the header is used only as a
// search key — the server does not trust it. The flow is:
//
//  1. Server uses the sender DN to look up a candidate certificate from its own store.
//  2. Server verifies the message signature against that certificate's public key.
//  3. If the client lied about the DN, the lookup fails or the signature won't verify.
//
// Trust comes from the certificate being in the server's store (previously issued)
// and the signature proving the client holds the corresponding private key.
//
//	func LookupCertificate(issuer pkix.Name, subject pkix.Name, senderKID []byte) (*x509.Certificate, error) {
//	    return certStore[issuer, subject]
//	}
//
// # Authorization Middleware
//
// [NewCAServer] requires a middleware slice that implements authorization and
// request validation. The server handles authentication (verifying MAC or
// signature protection) but delegates authorization decisions to middleware.
// Without middleware, any authenticated client could request any certificate.
//
// [LightweightPolicy] implements the RFC 9483 Lightweight CMP Profile checks:
//
//   - Verifies Proof-of-Possession (POP) on certificate requests
//   - Requires KUR to use signature protection (not MAC)
//   - Validates that extraCerts contains a complete chain for signature-protected requests
//   - Enforces subject presence in certificate templates
//   - Rejects requests for CA certificates
//   - Validates BasicConstraints path-length
//
// Example with additional custom policy:
//
//	srv := server.NewCAServer(ca, caKey, caCert,
//	    []server.Middleware{server.LightweightPolicy(), myPolicy()},
//	    server.WithSecretLookup(server.SecretLookupFunc(lookupSecret)),
//	    server.WithCertificateLookup(server.CertificateLookupFunc(lookupCertificate)),
//	)
//
// A custom middleware follows the same pattern — reject or pass through:
//
//	func myPolicy() server.Middleware {
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
// # Multiple CAs
//
// Each [Server] instance serves a single CA. To support multiple CAs, create
// separate Server instances and route by URL path using standard HTTP
// multiplexing. RFC 9483 §6.1 defines the well-known URI structure:
//
//	/.well-known/cmp/p/<name>
//
// Example:
//
//	mux := http.NewServeMux()
//	mux.Handle("/.well-known/cmp/p/ca1", server.NewCAServer(ca1, ca1Key, ca1Cert,
//	    []server.Middleware{server.LightweightPolicy()},
//	    server.WithSecretLookup(ca1SecretLookup),
//	    server.WithCertificateLookup(ca1CertLookup),
//	))
//	mux.Handle("/.well-known/cmp/p/ca2", server.NewCAServer(ca2, ca2Key, ca2Cert,
//	    []server.Middleware{server.LightweightPolicy()},
//	    server.WithSecretLookup(ca2SecretLookup),
//	    server.WithCertificateLookup(ca2CertLookup),
//	))
//	http.ListenAndServe(":8080", mux)
//
// # Transaction Management
//
// The server tracks transactions across multi-message exchanges (IR→IP→CertConf→PKIConf
// and polling flows). Transactions are keyed by a composite of the client's
// cryptographically verified credentials and the client-supplied transactionID,
// preventing cross-client transaction hijacking (RFC 9810 §5.1.1).
//
// # Transaction Limits
//
// To prevent resource exhaustion, the server enforces transaction caps:
//
//   - [WithMaxTransactions]: Global cap on concurrent transactions (default 10000).
//   - [WithMaxTransactionsPerCredential]: Per-client cap (default 100).
//
// When limits are exceeded, new requests are rejected with failInfo systemUnavail.
//
// # Transaction Cleanup
//
// Call [Server.CleanupExpired] periodically to remove stale entries:
//
//	go func() {
//	    for range time.Tick(time.Minute) {
//	        srv.CleanupExpired()
//	    }
//	}()
//
// Entries are expired based on their last activity time (updated on each state
// transition). The expiry duration is controlled by [WithConfirmWaitTime].
package server
