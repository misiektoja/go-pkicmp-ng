# Release Notes

Notable changes to go-pkicmp. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.0.2 - TBD

Security and interoperability release. Response verification is stricter, shared-secret protection is safer against hostile input, and enrollment works reliably against common CAs and vendor CMP clients.

### `pkicmp`

* **Pin the protection mechanism you expect** with **`VerifyOptions.RequiredProtection`**. The default accepts either MAC or signature, which remains right when the peer's mechanism is unknown. When you already know what a message should use, pin that mechanism instead.
* **Signature verification binds the sender to the protection certificate**, so a trusted leaf cannot sign for another identity.
* **PBKDF2 parameters from untrusted messages are bounded** before key derivation, closing a remote crash and abusive CPU use.
* **PBMAC1 omits optional PBKDF2 fields** the way RFC 8018 allows; absent `keyLength` and `prf` now default correctly.
* **`confirmWaitTime` is encoded as `GeneralizedTime`**, with **`ParseConfirmWaitTime`** to read it.
* **CMP protection certificates with CMP extended key usages verify** instead of being rejected for lacking `serverAuth`.
* **An unsupported hash algorithm in PBMAC1 parameters is rejected** with a `VerificationError` instead of crashing during key derivation.
* **An expired protection certificate no longer authenticates** on the pre-trusted (`TrustedCert`) verification path used by `server.WithCertificateLookup`.
* **`VerifyResult.ProtectionCertificate`** carries the signer across a transaction when later messages omit `extraCerts`.
* **`RequireDigitalSignatureKeyUsage`** is available for strict deployments; off by default for common CA setups.
* **Package docs now list caller responsibilities** for verification, polling, `caPubs` trust and issued-certificate checks.

### `client`

* **Forged issuance responses are rejected** by binding the signer to the claimed sender, checking that the issued certificate matches the requested public key, and optionally pinning the response protection mechanism with **`WithResponseProtection`**.
* **Enrollment against real CAs is fixed**: recipient names built in Go are sent, distinguished names keep attributes Go cannot rebuild from typed fields (so a recipient copied from an EJBCA CA certificate is no longer truncated), intermediate-issued certificates validate against a configured root, and the final `pkiConf` verifies when `extraCerts` appear only once.
* **Other fixes**: CMP content on HTTP 4xx/5xx responses is handled, delayed issuance accepts the original request nonce, and CMP media type parsing follows HTTP rules instead of exact-string matching.
* **Polling is safer**: each `checkAfter` wait is clamped with **`WithCheckAfterLimits`** (default 1s to 1h), and deadline errors name the wait they expired in.
* **Unauthenticated CA rejections are surfaced** as **`UnverifiedStatusError`** when a shared-secret client has no trust anchors. Set **`WithTrustedCAs`** wherever an anchor is already available.

### `server`

* **Vendor clients complete enrollment** against the reference server (OpenSSL `cmp`, Nokia `ssh-cmpclient`).
* **Strict RFC 9483 profile checks are opt in** via **`WithStrictProfileValidation`**. Default behavior favors field interoperability.
* **Issuance is hardened**: proof of possession is enforced without a policy wrapper, malformed `BasicConstraints` are rejected, and looked-up protection certificates must match the header sender.
* **Other fixes**: `confirmWaitTime` is sent as a `GeneralizedTime`, response `extraCerts` lead with the protection certificate and no longer repeat one, and a transaction cleanup race under concurrent `CleanupExpired` is fixed.

## v0.0.1 - 2026-05-27

Initial pre-release, providing a partial implementation of CMP as specified in RFC 9810, which obsoletes RFC 4210, profiled by RFC 9483 (Lightweight CMP Profile), with RFC 4211 (CRMF) and RFC 6712 (CMP over HTTP), split into three packages. Both protocol versions defined by RFC 9810 are supported, so the library interoperates with peers implementing the original RFC 4210 CMPv2 (`cmp2000`) as well as CMPv3 (`cmp2021`).

### Features

* **`pkicmp`** provides the core CMP and CRMF ASN.1 types, covering parsing, serialization, PVNO 2 and 3, and message protection using either a shared secret (PasswordBasedMac and PBMAC1) or X.509 signatures.
* **`client`** implements the IR, CR, KUR and P10CR enrollment flows, including polling for deferred issuance, response verification and certificate confirmation.
* **`server`** exposes a CMP endpoint as a standard `http.Handler` that authenticates clients, tracks transactions, supports asynchronous issuance and enforces policy through middleware, including the Lightweight CMP Profile.

Interoperability is exercised by integration tests: the client against EJBCA and OpenSSL, and the server against the Siemens CMP Test Suite.
