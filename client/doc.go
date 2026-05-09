// Package client provides a Certificate Management Protocol (CMP) client for
// requesting X.509 certificates from a CA over HTTP.
//
// It explicitly supports both CRMF (Certificate Request Message Format) and
// PKCS#10 (P10CR) as alternative enrollment mechanisms, with an explicit,
// orthogonal approach to message protection.
//
// # Initial Enrollment (CRMF) with Password-Based MAC
//
//	// 1. Create the client
//	c := client.NewClient("http://ca.example.com/pkix/")
//
//	// 2. Generate a new key for the certificate
//	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	// 3. Send the Initialization Request (IR) with MAC credentials
//	result, err := c.SendIR(context.Background(), key,
//	    pkicmp.NewMACCredentials([]byte("my-shared-secret")),
//	    client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
//	)
//	if err != nil {
//	    log.Fatalf("Enrollment failed: %v", err)
//	}
//
//	fmt.Println("Got certificate:", result.Certificate.Subject)
//
// # Key Update (PKCS#10) with Existing Certificate Signature
//
//	// 1. Create the client with trusted CAs for signature-protected responses
//	c := client.NewClient("http://ca.example.com/pkix/",
//	    client.WithTrustedCAs(trustedCAPool),
//	)
//
//	// 2. We have an existing certificate and key, and we generated a new CSR
//	oldCert := loadExistingCert()
//	oldKey := loadExistingKey()
//	newCSRDER := generateNewCSR()
//
//	// 3. Send the PKCS#10 Certification Request (P10CR) with signature credentials
//	creds, _ := pkicmp.NewSignatureCredentials(oldKey, oldCert)
//	result, err := c.SendP10CR(context.Background(), newCSRDER,
//	    creds,
//	    client.WithSender(oldCert.Subject),
//	)
//	if err != nil {
//	    log.Fatalf("Key update failed: %v", err)
//	}
//
//	fmt.Println("Got updated certificate:", result.Certificate.Subject)
//
// # Asynchronous Enrollment and Polling
//
// CMP supports asynchronous enrollment where the CA may return a "waiting" status
// if the certificate requires manual approval or delayed issuance.
//
// The [Client] handles this polling lifecycle completely transparently:
//  1. If the CA returns a waiting status, the Send* method will block and enter
//     an internal polling loop.
//  2. The client will automatically sleep for the duration requested by the CA
//     in the checkAfter field before sending the next poll request.
//  3. Once the certificate is finally issued, the client automatically sends the
//     required certificate confirmation (certConf) message to the CA.
//  4. Only after the entire exchange is complete does the Send* method return
//     the final [EnrollResult] to the caller.
//
// Users have two ways to control this blocking behavior:
//   - Context: Pass a [context.Context] with a deadline or timeout to the Send*
//     method. If the context expires while polling, the method returns immediately
//     with the context error.
//   - [WithMaxPolls]: Configure the client to give up after a certain number of
//     poll attempts (defaults to 60).
//
// # Response Verification
//
// The client verifies every response from the CA before accepting it.
// How verification works depends on the protection type:
//
//   - Signature protection: The client verifies the response signature against
//     trusted CAs configured via [WithTrustedCAs]. This is required for
//     signature-protected responses; the client rejects the response if no
//     trusted CAs are configured.
//
//   - PBM (shared secret) protection: The client verifies the MAC using the
//     shared secret from the [pkicmp.Credentials] passed to the Send* method.
//     No trusted CAs are needed. If the server includes caPubs in the response
//     (RFC 9810 §5.3.2), they may be directly trusted as root CAs for
//     verifying the issued certificate.
//
// # TLS Configuration
//
// The client uses [http.DefaultClient] by default, which verifies TLS certificates
// against the system root pool. For custom TLS (e.g., internal CAs, mTLS), use
// [WithHTTPClient] to provide a configured [*http.Client].
//
// # Default Limits
//
// [DefaultMaxResponseBytes] (10 MiB) limits response body size to prevent memory
// exhaustion. [DefaultMaxPolls] (60) caps polling attempts. Override with
// [WithMaxResponseBytes] and [WithMaxPolls] respectively.
//
// # Stateless Design
//
// The [Client] handles HTTP transport, automatic polling, and confirmation
// exchanges. All transaction-specific state (TransactionID, Nonces) is managed
// locally within the lifecycle of a single method call, allowing a single
// Client instance to be used concurrently by multiple goroutines.
package client
