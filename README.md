# go-pkicmp

Go library for the Certificate Management Protocol (CMP).

> [!NOTE]
> This codebase is LLM-generated using [IETF protocol specifications](docs/specs).

## Standards Compliance

The library implements:
- **RFC 9810**: Certificate Management Protocol (CMP)
- **RFC 9483**: Lightweight CMP Profile
- **RFC 4211**: Certificate Request Message Format (CRMF)
- **RFC 6712**: Certificate Management Protocol (CMP) over HTTP

## Package Structure

The library is split into three packages:

*   **[`pkicmp`](./pkicmp/)**: Defines the Go types that map to CMP and CRMF ASN.1 structures. Handles message parsing, serialization, protection, and verification.
*   **[`client`](./client/)**: A client implementation to request certificates. It handles transaction ID tracking, nonces, polling, and the certificate confirmation round-trip.
*   **[`server`](./server/)**: A framework to add CMP support to an existing CA. It exposes a CMP endpoint as an `http.Handler` and implements verification, transaction binding, and nonce checking.

## Features

- **Enrollment Flows**: Supports Initialization (IR/IP), Certification (CR/CP), Key Update (KUR/KUP), and PKCS#10 requests (P10CR).
- **Protocol Versions**: Supports both PVNO 2 and PVNO 3.
- **Polling**: Automatically polls when the CA returns a waiting response, respecting the CA's `checkAfter` interval.
- **Protection**: Supports shared-secret MAC (PBM/PBMAC1) and X.509 signature-based protection.
- **Lightweight Profile**: Provides `LightweightPolicy()` middleware to enforce RFC 9483 requirements.

## Usage

### Client

Use the `client` package to enroll certificates from a CMP-capable CA.

#### Initialization Request (IR) with Shared Secret

```go
// Generate a key pair and configure MAC protection using a shared secret.
key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
creds, _ := pkicmp.NewMACCredentials([]byte("my-shared-secret"))

// Create a client and send the Initialization Request.
c := client.NewClient("http://localhost:8080/cmp")
result, err := c.SendIR(context.Background(), key, creds,
	client.WithSenderKID([]byte("my-device")),
	client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
)
```

#### Key Update Request (KUR) with Signature Protection

```go
// Protect using an existing key and certificate, and configure trust anchors.
creds, _ := pkicmp.NewSignatureCredentials(existingKey, existingCert)
c := client.NewClient("http://localhost:8080/cmp", client.WithTrustedCAs(trustedCAs))

// Send Key Update Request.
result, err := c.SendKUR(context.Background(), newKey, creds,
	client.WithSender(existingCert.Subject),
	client.WithTemplateSubject(existingCert.Subject),
)
```

See the [runnable examples](./examples/) or integration tests for more detailed client usage.

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

## Runnable Examples

For a complete, runnable demonstration of both client and server packages, check out the [examples](./examples/) directory. It contains:
- **[Mock Server](./examples/mockserver/)**: A simple HTTP server implementing the `server.CA` interface.
- **[Mock Client](./examples/mockclient/)**: A client executing a MAC-protected IR enrollment followed by a signature-protected KUR key update.

You can run them locally in separate terminals:
```bash
# In terminal 1: Start the CA server
go run ./examples/mockserver/cmd

# In terminal 2: Run the enrollment client
go run ./examples/mockclient/cmd
```

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
