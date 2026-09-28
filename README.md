# go-pkicmp-ng

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pkicmp-ng?style=flat-square&color=blue)](https://github.com/misiektoja/go-pkicmp-ng/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pkicmp-ng.svg)](https://pkg.go.dev/github.com/misiektoja/go-pkicmp-ng)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/test.yml)
[![Integration](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/integration.yml)
[![Supply chain](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkicmp-ng/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-pkicmp-ng&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pkicmp-ng)

Go library for the Certificate Management Protocol (CMP). The client enrolls, confirms, updates and
revokes certificates against a CMP CA. The server exposes the same operations to CMP clients as an
`http.Handler` in front of your CA. The library implements:

- **RFC 9810** (obsoletes RFC 4210 and RFC 9480): Certificate Management Protocol (CMP), CMPv2 and CMPv3
- **RFC 9483**: Lightweight CMP Profile
- **RFC 4211**: Certificate Request Message Format (CRMF)
- **RFC 9811** (obsoletes RFC 6712): HTTP Transfer for the Certificate Management Protocol (CMP)

Supported messages are `ir`, `cr`, `kur`, `p10cr`, `rr`, `certConf`, `pollReq` and `nested` with
their responses. Key recovery, cross-certification, proof-of-possession challenges, announcements and
general messages (`genm`) are not implemented.

## Interoperability and testing

CI runs the library against independent CMP implementations for every pull request and every push to
`dev` and `main`. The client enrolls and updates certificates against
[EJBCA](https://docs.keyfactor.com/ejbca/latest/cmp) and enrolls, updates and revokes them against the
[OpenSSL](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html) mock server. The server is checked
by the [Siemens CMP test suite](https://github.com/siemens/cmp-test-suite) and by OpenSSL as a
revoking client.

CI also runs the unit tests under the race detector and fuzzes message parsing, MAC protection
parameters and signature verification. golangci-lint, govulncheck and a gitleaks scan of the full
history run next to them. CodeQL and
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pkicmp-ng) analyze the
code and the repository setup.

Starting with v0.2.0, releases carry complete source archives, a CycloneDX SBOM, SHA-256 checksums
and a signed build provenance attestation. Check an artifact with
`gh attestation verify <file> --repo misiektoja/go-pkicmp-ng`.

[cmp-issuer](https://github.com/misiektoja/cmp-issuer), a cert-manager external issuer for CMP
servers, is built on this library.

## Install

```bash
go get github.com/misiektoja/go-pkicmp-ng
```

Requires Go 1.27.1 or newer.

ML-DSA-44, ML-DSA-65 and ML-DSA-87 support covers certificate keys, CRMF proof of possession and message signatures. The client confirms ML-DSA-signed certificates with an explicit SHA-512 hash algorithm under CMPv3. Peers must support these algorithms and confirmation fields. Classical enrollment remains available.

Use `pkicmp.NewCertStatus` when constructing confirmation manually. It includes the required hash identifier for ML-DSA. `pkicmp.CertHash` alone cannot represent that identifier. Pure ML-DSA uses an empty context and absent algorithm parameters. Composite signatures and older Dilithium encodings are not supported.

Peers that implement only RFC 4210 are supported. The server accepts their requests without a transactionID or with a short senderNonce. `server.WithStrictProfileValidation` restores the RFC 9483 rejections. SHA-1 is off by default because RFC 9481 deprecates it. `pkicmp.WithPBMAlgorithms(crypto.SHA1, crypto.SHA1)` selects the RFC 4210 PasswordBasedMac profile. `WithSHA1Signatures` in the `client` and `server` packages accepts SHA-1 signatures.

## Package structure

The library is split into three packages:

*   **[`pkicmp`](./pkicmp/)**: Core types for CMP and CRMF ASN.1 structures. Handles parsing, serialization, PVNO 2/3, and protection (MAC or X.509 signatures).
*   **[`client`](./client/)**: Handles IR, CR, KUR, and P10CR enrollment flows, including automatic polling, response verification, and certificate confirmation. Sends revocation requests (RR).
*   **[`server`](./server/)**: Exposes an HTTP handler that authenticates clients, tracks transactions, supports async issuance, handles revocation for CAs that implement it, accepts requests a registration authority forwards in nested messages and enforces policies via middleware (including the lightweight profile).

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

Revocation Request (RR)

```go
// RFC 9483 expects the request to be signed with the certificate being revoked.
creds, _ := pkicmp.NewSignatureCredentials(certKey, cert)
c := client.NewClient("http://localhost:8080/cmp", client.WithTrustedCAs(trustedCAs))

// A nil error means the CA revoked the certificate. A rejection such as
// certRevoked is returned as *pkicmp.PKIStatusError.
err := c.SendRR(context.Background(), cert, pkicmp.CRLReasonKeyCompromise, creds)
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
func (ca *MyCA) RevokeCertificate(ctx, req, sender) {
	// Optional. Called on revocation requests (RR) signed with the certificate being revoked.
	// Implement server.RevocationAuthorizer to also accept requests from other signers.
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
- **[Mock Client](./examples/mockclient/)**: A client executing a MAC-protected IR enrollment, a signature-protected KUR key update and a signature-protected RR revocation.

You can run them locally in separate terminals:
```bash
# In terminal 1: Start the CA server
go run ./examples/mockserver/cmd

# In terminal 2: Run the enrollment client
go run ./examples/mockclient/cmd
```

## Credits and relationship to go-pkicmp

This project began as a fork of [tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp) by
[@tsaarni](https://github.com/tsaarni). That original work contributed the package layout, the ASN.1
types and the client and server designs this library still follows. It is what made everything here
possible. It is Apache-2.0 licensed and the credit for the foundation belongs to its author.

Development continued here because the changes are security relevant and were needed on a faster
cycle than waiting for review allowed. The early hardening work is offered upstream in
[tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3), which is still open. Later
changes build on it here.

What this fork adds:

* **Stricter verification.** A signature is bound to the sender it claims. An issued certificate must
  certify the requested key and carry the certReqId of the request. PBKDF2 parameters and poll
  intervals taken from untrusted messages are bounded.
* **Post-quantum ML-DSA** for certificate keys, proof of possession and message signatures, with
  SHA-512 certificate confirmation.
* **Revocation** in the client and the server. The server also accepts requests that a registration
  authority forwards in nested messages.
* **Certificate confirmation checks.** The client reports a refused certificate to the CA. The server
  checks every `CertStatus` and can carry transactions across a restart with `SnapshotTransactions`
  and `RestoreTransactions`.
* **Support for RFC 4210 peers** that send no transactionID or a short senderNonce, use the SHA-1
  PasswordBasedMac profile or sign with SHA-1. The SHA-1 options are off by default.
* **Server hardening.** Proof of possession is required for every request. A `messageTime` tolerance
  can be enforced. Handler error text stays off the wire and `Server.Err` reports a signer
  misconfiguration.
* **Interoperability fixes** for EJBCA, OpenSSL and vendor CMP clients: the CMP media type,
  CMP-over-HTTP errors, distinguished names that survive a round trip through a real CA, Ed25519
  signing CAs and key updates that name the certificate they replace.

The [release notes](RELEASE_NOTES.md) list every change.

## Contributing and support

The [Contributing Guide](CONTRIBUTING.md) describes the development checks, the integration tests and the release process. [SUPPORT.md](SUPPORT.md) says where to ask a question or report a bug. Report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). [DEPENDENCIES.md](DEPENDENCIES.md) lists third-party dependencies and their licenses.
