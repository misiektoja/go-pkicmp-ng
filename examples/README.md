# Examples

This directory contains a complete, runnable demonstration of the `client` and `server` packages in memory. For instructions on how to run them, please refer to the root [README.md](../README.md).

## How It Works

**Server startup**

1. Generates a self-signed MockCA key pair and certificate (in memory).
2. Registers a shared secret (`"my-device"` → `"test-shared-secret"`) for
   MAC-based enrollment.
3. Connects the MockCA to `server.NewCAServer` with `LightweightPolicy` middleware
   and starts listening on `localhost:8080`.

**Step 1 — Initial enrollment (IR, MAC-protected)**

1. Client generates a fresh key pair.
2. Client sends an IR protected with a MAC derived from the shared secret.
   `senderKID` is set to `"my-device"` so the server can look up the secret.
3. Server verifies the MAC via `MockCA.LookupSecret`, builds a certificate
   template from the request, and calls `MockCA.IssueCertificate`.
4. MockCA sets serial number, validity, and signs the certificate with its key.
5. Server returns the signed certificate and the MockCA CA certificate in `caPubs`
   Implicit confirm is enabled, so no certConf round-trip is needed.
6. Client verifies the issued certificate against the MockCA CA certificate from
   `caPubs` and installs it as a trust anchor for future operations.

**Step 2 — Key update (KUR, signature-protected)**

1. Client generates another fresh key pair.
2. Client sends a KUR signed with the certificate and key from step 1.
   The full certificate chain (sender cert + CA cert) is included in
   `extraCerts`.
3. Server calls `MockCA.LookupCertificate` to find the sender's certificate by
   Subject Key Identifier, verifies the signature, and calls
   `MockCA.IssueCertificate`.
4. MockCA issues a new certificate for the new public key.
5. Server returns the renewed certificate. The client verifies the response
   signature using the trust anchor established in step 1.

Everything runs in memory — no files are written to disk.

## Code Structure

- [`mockserver/mockserver.go`](mockserver/mockserver.go) — implements the
  [`server.CA`](../server/ca.go) interface (certificate issuance, secret
  lookup, certificate lookup).
- [`mockserver/cmd/main.go`](mockserver/cmd/main.go) — connects the MockCA to
  [`server.NewCAServer`](../server/ca.go) and starts an HTTP server.
- [`mockclient/mockclient.go`](mockclient/mockclient.go) — shows MAC-based
  enrollment (IR) and signature-based key update (KUR) using the
  [`client`](../client/) package.
- [`mockclient/cmd/main.go`](mockclient/cmd/main.go) — runs both flows
  back-to-back against the mock server.
