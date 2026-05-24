# go-pkicmp

Go library for the Certificate Management Protocol (CMP).

> [!NOTE]
> This codebase is LLM-generated from [IETF protocol specifications](docs/specs).

## Overview

This project provides an implementation of the CMP protocol for certificate enrollment.

## Features

The library implements core CMP message types for enrollment:
- Initialization (IR/IP), Certification (CR/CP), and Key Update (KUR/KUP) flows
- PKCS#10 requests (P10CR)
- Certificate confirmation (CertConf/PKIConf)
- Polling (PollReq/PollRep) and error reporting

Protocol features include:
- Support for both PVNO 2 and PVNO 3
- Automated polling, respecting CA-provided `checkAfter` intervals
- Message protection using either shared-secret MAC (PBM) or X.509 signatures

## Usage

### Client

Use the `client` package to enroll certificates from a CMP-capable CA.

#### Initialization Request (IR) with Shared Secret

```go
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"log"

	"github.com/tsaarni/go-pkicmp/client"
	"github.com/tsaarni/go-pkicmp/pkicmp"
)

func main() {
	// Generate a new private key.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Configure MAC protection using a shared secret.
	creds, _ := pkicmp.NewMACCredentials([]byte("my-shared-secret"))

	// Create a client for the protocol implementation.
	c := client.NewClient("http://ejbca:8080/ejbca/publicweb/cmp/<cmp-alias>")

	// Send Initialization Request.
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Certificate issued: %s", result.Certificate.Subject)
}
```

#### Key Update Request (KUR) with Signature Protection

```go
// Protected by an existing certificate's signature.
creds, _ := pkicmp.NewSignatureCredentials(existingKey, existingCert)

c := client.NewClient("http://ejbca:8080/ejbca/publicweb/cmp/<cmp-alias>",
	// Adds trusted CAs for verifying signature-protected CMP responses.
	client.WithTrustedCAs(trustedCAs),
)

result, err := c.SendKUR(context.Background(), newKey, creds,
	client.WithSender(existingCert.Subject),
)
```

See integration tests for more examples.

### Server

Use the `server` package to add a CMP endpoint to an existing CA. Implement the `CA`
interface and wrap it with `NewCAServer`, which returns a standard `http.Handler`.

The `CA` interface has one required method:

- `IssueCertificate` — called for every enrollment request. Receives a certificate
  template pre-populated from the CMP request; sign it with your CA backend.

Protection verification is configured separately:

- `WithSecretLookup(...)` — provides shared secrets for MAC-protected requests.
- `WithCertificateLookup(...)` — provides signer certificates for signature-protected requests.

The server handles all protocol mechanics automatically: message parsing, protection
verification, response construction, nonce and transaction management, and the
certConf round-trip. See the `server` package documentation for optional interfaces
such as `PendingChecker` (asynchronous issuance) and `CertificateConfirmer`.

## Integration Testing

The project includes tests against both EJBCA and OpenSSL to verify protocol compatibility.

### EJBCA Integration

The [EJBCA integration tests](./test/integration/ejbca/) test the client implementation against a real EJBCA instance in Docker. They cover the full enrollment lifecycle, including IR with various key types, and certificate-based authentication for CR and KUR. The tests also verify the handling of CA chains and extra certificates returned by the server.

### OpenSSL Integration

The [OpenSSL integration tests](./test/integration/openssl/) test the client implementation using the OpenSSL mock server. This includes testing the polling mechanism and ensuring the implementation respects `checkAfter` suggestions, as well as verifying PBM protection and error handling.

### CMP Test Suite

The [CMP test suite integration](./test/integration/cmp-test-suite/) tests the server implementation by running the [Siemens CMP test suite](https://github.com/siemens/cmp-test-suite) against a Go mock server.

## Running Tests

### Unit Tests
```bash
make test
```

### Integration Tests
Running these tests requires Docker, OpenSSL 3.2+, Git and uv.
```bash
make setup            # Start EJBCA and setup cmp-test-suite
make test-integration # Run all integration tests
make teardown         # Stop EJBCA
```
