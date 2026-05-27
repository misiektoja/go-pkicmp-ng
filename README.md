# go-pkicmp

Go library for the Certificate Management Protocol (CMP).

> [!NOTE]
> This codebase is LLM-generated using [IETF protocol specifications](docs/specs) as reference context.

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

Initialization Request (IR) with Shared Secret

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

Key Update Request (KUR) with Signature Protection

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

### Server

Use the `server` package to expose a CMP endpoint as a standard `http.Handler`. 

Implement the `server.CA` interface and credential lookup callbacks.
```go
type MyCA struct{}

func (ca *MyCA) IssueCertificate(ctx, reqType, template, sender) {
	// Called on enrollment requests (IR/CR/KUR). Signs template with CA private key.
}
func (ca *MyCA) LookupSecret(sender, senderKID) {
	// Called to verify MAC-protected requests. Finds pre-shared secret by DN or key ID.
}
func (ca *MyCA) LookupCertificate(issuer, subject, senderKID) {
	// Called to verify signature-protected requests. Finds existing cert by DN or Subject Key ID.
}
```

Initialize the server framework and run.
```go
myCA := &MyCA{}
srv := server.NewCAServer(myCA,
	[]server.Middleware{server.LightweightPolicy()},
	server.WithSigner(caKey, caCert),
	server.WithSecretLookup(myCA),
	server.WithCertificateLookup(myCA),
)

http.Handle("/cmp", srv)
http.ListenAndServe(":8080", nil)
```

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

## Contributing

Please refer to the [Contributing Guide](CONTRIBUTING.md).

