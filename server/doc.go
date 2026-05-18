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
// Most users should use the [CA] interface via [NewCAHandler] or [NewCAServer].
//
// # CA Interface
//
// The [CA] interface requires three methods:
//
//	type CA interface {
//	    IssueCertificate(ctx, reqType, template, sender) (*Response, error)
//	    LookupSecret(senderKID) ([]byte, error)
//	    LookupCertificate(sender, senderKID) (*x509.Certificate, error)
//	}
//
// [CA.IssueCertificate] receives a certificate template with subject, public key,
// extensions, and SKI pre-populated from the CMP request. The CA sets the serial
// number, validity period, key usage, and signs the certificate.
//
// [CA.LookupSecret] and [CA.LookupCertificate] are used to verify message
// protection (MAC or signature).
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
//	func (c *myCA) LookupSecret(senderKID []byte) ([]byte, error) {
//	    return []byte("shared-secret"), nil
//	}
//
//	func (c *myCA) LookupCertificate(sender pkix.Name, senderKID []byte) (*x509.Certificate, error) {
//	    return nil, errors.New("not found")
//	}
//
//	// Create server
//	srv := server.NewCAServer(ca, caKey, caCert)
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
// # Middleware
//
// The [Handler] interface supports middleware for policy enforcement:
//
//	srv := server.New(
//	    server.Chain(server.NewCAHandler(ca), server.LightweightPolicy(), myPolicy()),
//	    server.WithSigner(caKey, caCert),
//	    server.WithSecretLookup(ca),
//	    server.WithCertificateLookup(ca),
//	)
//
// [LightweightPolicy] enforces RFC 9483 Lightweight CMP Profile requirements.
// Custom middleware can add additional policy checks.
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
//	mux.Handle("/.well-known/cmp/p/ca1", server.NewCAServer(ca1, ca1Key, ca1Cert))
//	mux.Handle("/.well-known/cmp/p/ca2", server.NewCAServer(ca2, ca2Key, ca2Cert))
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
