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
//  3. Once the certificate is issued the client automatically sends certConf.
//  4. The Send* method returns only after the full exchange completes.
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
