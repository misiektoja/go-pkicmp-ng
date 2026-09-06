# go-pkicmp-ng

[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pkicmp-ng.svg)](https://pkg.go.dev/github.com/misiektoja/go-pkicmp-ng)

Go library for the Certificate Management Protocol (CMP).
The library partially implements:
- **RFC 9810** (obsoletes RFC 4210 and RFC 9480): Certificate Management Protocol (CMP)
- **RFC 9483**: Lightweight CMP Profile
- **RFC 4211**: Certificate Request Message Format (CRMF)
- **RFC 9811** (obsoletes RFC 6712): HTTP Transfer for the Certificate Management Protocol (CMP)

Compliance is verified via integration tests: client against [EJBCA](https://docs.keyfactor.com/ejbca/latest/cmp) and [OpenSSL](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html); server against [Siemens CMP Test Suite](https://github.com/siemens/cmp-test-suite).

## Credits and relationship to go-pkicmp

This project began as a fork of [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp) by
[@tsaarni](https://github.com/tsaarni). That original work contributed the package layout, the ASN.1
types and the client and server designs this library still follows and it is what made everything
here possible. It is Apache-2.0 licensed and the credit for the foundation belongs to its author.

Development continued here because the changes are security relevant and were needed on a faster
cycle than waiting for review allowed. They are offered upstream in
[tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3), which is still open.

What this fork adds, in short: response verification that binds a signature to the sender it claims,
a check that an issued certificate really certifies the key that was requested, bounded PBKDF2
parameters and poll intervals taken from untrusted messages, correct CMP media type and
CMP-over-HTTP error handling, distinguished names that survive a round trip through a real CA, and
interoperability fixes against EJBCA, OpenSSL and vendor CMP clients. The
[release notes](RELEASE_NOTES.md) list the changes in full.

The API is pre-v1 and may change.

## Install

```bash
go get github.com/misiektoja/go-pkicmp-ng
```

## Package structure

The library is split into three packages:

*   **[`pkicmp`](./pkicmp/)**: Core types for CMP and CRMF ASN.1 structures. Handles parsing, serialization, PVNO 2/3, and protection (MAC or X.509 signatures).
*   **[`client`](./client/)**: Handles IR, CR, KUR, and P10CR enrollment flows, including automatic polling, response verification, and certificate confirmation.
*   **[`server`](./server/)**: Exposes an HTTP handler that authenticates clients, tracks transactions, supports async issuance, and enforces policies via middleware (including the lightweight profile).

## Usage

### Client

Use the `client` package to enroll certificates from a CMP-capable CA.

Initialization Request (IR) with Shared Secret

```go
// Generate a key pair and configure MAC protection using a shared secret.
key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
creds, _ := pkicmp.NewMACCredentials([]byte("my-shared-secret"))

// Create a client and send the Initialization Request. A bootstrapping device
// has no trust anchor yet, so none is set here. Add client.WithTrustedCAs
// wherever one is already available, so that a signed rejection can be verified.
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

// Send Key Update Request. SignatureCredentials lets SendKUR identify
// existingCert by issuer and serial in the recommended CRMF oldCertID control.
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
	server.LightweightPolicy(),
	server.WithSigner(caKey, caCert),
	server.WithSecretLookup(myCA),
	server.WithCertificateLookup(myCA),
	// A present messageTime outside this local tolerance is rejected as badTime.
	server.WithMessageTimeTolerance(5*time.Minute),
)
// Reports a misconfiguration such as a signer key that does not match its cert.
if err := srv.Err(); err != nil {
	log.Fatal(err)
}

http.Handle("/cmp", srv)
http.ListenAndServe(":8080", nil)
```

## Runnable examples

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

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
