// Package client provides a Certificate Management Protocol (CMP) client for
// requesting X.509 certificates from a CA over HTTP.
//
// Four methods cover the standard enrollment flows: [Client.SendIR] (initial
// registration), [Client.SendCR] (certification), [Client.SendKUR] (key update),
// and [Client.SendP10CR] (PKCS#10 request). All handle the full lifecycle
// transparently: protection, response verification, polling, and certificate
// confirmation.
//
// # Initial enrollment with MAC protection
//
//	// Create the client.
//	c := client.NewClient("http://ca.example.com/.well-known/cmp/p/ca/")
//
//	// Generate a key for the new certificate.
//	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	// Create MAC credentials from the pre-shared secret.
//	creds, err := pkicmp.NewMACCredentials([]byte("my-shared-secret"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Send the Initialization Request (IR).
//	result, err := c.SendIR(context.Background(), key, creds,
//	    client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Got certificate:", result.Certificate.Subject)
//
// # Key update with signature protection
//
//	// Existing certificate and key used to authenticate the request.
//	oldCert := loadExistingCert()
//	oldKey := loadExistingKey()
//
//	// New key for the replacement certificate.
//	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	newCreds, err := pkicmp.NewSignatureCredentials(oldKey, oldCert)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	c := client.NewClient("http://ca.example.com/.well-known/cmp/p/ca/",
//	    client.WithTrustedCAs(trustedCAPool),
//	)
//	result, err := c.SendKUR(context.Background(), newKey, newCreds,
//	    client.WithSender(oldCert.Subject),
//	    client.WithTemplateSubject(oldCert.Subject),
//	)
//
// # Asynchronous enrollment and polling
//
// When a CA cannot issue immediately it replies with a "waiting" status. The
// client handles this transparently:
//
//  1. If the CA replies with a waiting status, the Send* method enters an
//     internal polling loop.
//  2. The client sleeps for the duration the CA specified in checkAfter before
//     sending the next PollReq.
//  3. The final response may identify either the last PollReq or the original
//     request whose processing was delayed, as RFC 9483 Section 4.4 requires.
//  4. Once the certificate is issued the client automatically sends certConf.
//  5. The Send* method returns only after the full exchange completes.
//
// Control the blocking behavior with:
//   - A [context.Context] with a deadline or timeout — the method returns the
//     context error if it expires while polling.
//   - [WithMaxPolls]: give up after a fixed number of poll attempts (default 60).
//
// # Response verification
//
// Every response is verified before being accepted:
//
//   - MAC-protected response: verified with the shared secret from the
//     [pkicmp.Credentials] passed to the Send* method.
//   - Signature-protected response: verified against trusted CAs configured
//     via [WithTrustedCAs]. The client rejects the response if no trusted CAs
//     are configured. If the server includes caPubs in an IP response,
//     those may be used directly as trusted CAs.
//
// CMP responses carried by HTTP 4xx or 5xx errors are parsed and verified
// before their status is returned. Authenticated failure bits remain available
// through [pkicmp.HasFailure] while the error also retains the HTTP status.
//
// By default a response may use either protection mechanism, whichever the
// server chose, because a CA that authenticates clients by shared secret and
// signs every response is a common and interoperable configuration. Use
// [WithResponseProtection] to require one mechanism throughout the operation, as
// RFC 9483 §3.1 asks for.
//
// Signature-protected responses must come from a certificate whose subject
// matches the sender named in the response header. A server may send extraCerts
// only on its first response, so the protection certificate authenticated
// earlier in the operation is retained and tried for later messages, which still
// have to satisfy the same chain, sender and signature checks against it.
//
// The issued certificate must certify the public key that was requested, and is
// validated against the configured trust anchors using any certificates the
// response carried in extraCerts to complete the path. Its subject is not
// checked, because a CA may return grantedWithMods after changing requested
// fields such as the subject.
//
// # Limits
//
// [DefaultMaxResponseBytes] (10 MiB) caps response body size to prevent memory
// exhaustion. [DefaultMaxPolls] (60) caps polling attempts. Override with
// [WithMaxResponseBytes] and [WithMaxPolls].
//
// # Stateless design
//
// All transaction-specific state (TransactionID, nonces) is managed within the
// lifetime of a single Send* call. A single [Client] instance can be used
// concurrently by multiple goroutines.
package client
