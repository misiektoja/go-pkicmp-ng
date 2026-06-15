# Release Notes

Notable changes to go-pkicmp. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.0.2 - TBD

Hardening release for response authentication and shared-secret protection.

A client could previously be talked into accepting a forged issuance response by an attacker holding nothing more than a certificate that chains to any configured trust anchor. Three independent gaps combined to allow it, and all three are now closed: the protection mechanism is pinned to the credentials the operation started with, a signature is accepted only from the sender the message names, and the returned certificate must certify the key that was actually requested.

Shared-secret protection is hardened separately. PBKDF2 parameters taken from a received message are bounded before they reach key derivation, which closes a remote crash reachable before the message is authenticated, and PBMAC1 messages that leave out the optional PBKDF2 fields now interoperate instead of being rejected as malformed.

Clients talking to a CA that does not follow these rules will see enrollment fail where it previously succeeded. Each entry below describes what such a server must do.

### Security fixes

* **A response must use the protection mechanism the operation started with.** Verification dispatched purely on the algorithm named in the received message, so a client holding a shared secret that also configured trust anchors, which is the normal setup when the issued certificate has to be validated, silently accepted a signature-protected response from any certificate chaining to one of those anchors. RFC 9483 §3.1 requires the same kind of protection for every message of a PKI management operation, and RFC 9810 §5.2.3 reserves the failInfo bit `wrongIntegrity` for a message that arrives "password based instead of signature or vice versa". The `client` package now pins the mechanism to the credentials passed to the `Send*` method and rejects a switch with `ReasonUnexpectedProtection`. Direct users of `pkicmp` can pin it with the new **`VerifyOptions.RequiredProtection`** field, whose zero value `ProtectionAny` keeps accepting either mechanism, as a server needs for the first message of an operation.
* **Signature-protected messages must come from the sender they name.** Signature verification accepted the first certificate in `extraCerts` that chained to the trust pool and produced a valid signature, without ever comparing the header sender to the certificate subject. Chaining to a trust anchor only proves a certificate is trusted, so for an enterprise or public CA any certificate under that anchor was accepted for any claimed identity. The sender is now bound to the subject of the certificate that produced the signature, as RFC 9483 §3.5 requires, and a mismatch is reported as `ReasonSenderMismatch`. A NULL DN sender, which RFC 4210 §5.1.1 requires when the sender does not know its own name, carries no name to compare and is still accepted on the trust chain alone.
* **The issued certificate must certify the requested public key.** The client returned whatever certificate the response carried, checking only that it chained to a trusted CA. A compromised or buggy CA could therefore hand back a certificate for a key the client does not hold, which the client would store and only discover later as an unexplained TLS failure. The public key is now compared against the request before the certificate is returned. The **subject is deliberately not compared**, because a CA may legitimately return `grantedWithMods` after changing requested fields such as the subject.
* **PBKDF2 parameters from a received message are bounded before key derivation.** The PBKDF2 `keyLength` in a received message was used exactly as sent, before the message was authenticated. A negative or very large value crashed the process inside key derivation, so any peer able to reach a CMP endpoint could take it down without knowing the shared secret. A very small value was dangerous in the other direction: a one-byte key leaves 256 possible MAC keys, few enough to search and forge protection with. The accepted range is now **16 bytes through the MAC block size**, and anything outside it is rejected with a `ParseError` before any derivation runs. The floor is an absolute key strength requirement rather than the MAC digest size, so the widespread practice of deriving 32 bytes for every MAC keeps working with HMAC-SHA-384 and HMAC-SHA-512. The same bounds apply when a server protects a response with `WithProtectionAlgorithm`, which echoes the parameters from the request.
* **Unsupported hash algorithms in PBMAC1 parameters are rejected instead of crashing.** A message naming a hash that is not linked into the binary previously reached key derivation and panicked. It now returns a `VerificationError` with reason `ReasonUnsupportedAlgorithm`.

### Bug fixes

* **PBMAC1 messages that omit the optional PBKDF2 fields now verify.** RFC 8018 A.5 marks `keyLength` as OPTIONAL and gives `prf` a DEFAULT of HMAC-SHA-1, and DER requires an encoder to leave out a field that holds its default. Both fields were nevertheless required when parsing, so a conforming peer that omitted either one was rejected with `invalid PBKDF2-params` and could not enroll at all. An absent `keyLength` now defaults to the MAC digest size and an absent `prf` now defaults to HMAC-SHA-1, as the specification requires. Servers echoing such a request back in a response handle the omitted fields the same way.

## v0.0.1 - 2026-05-27

Initial pre-release, providing a partial implementation of CMP as specified in RFC 9810, which obsoletes RFC 4210, profiled by RFC 9483 (Lightweight CMP Profile), with RFC 4211 (CRMF) and RFC 6712 (CMP over HTTP), split into three packages. Both protocol versions defined by RFC 9810 are supported, so the library interoperates with peers implementing the original RFC 4210 CMPv2 (`cmp2000`) as well as CMPv3 (`cmp2021`).

### Features

* **`pkicmp`** provides the core CMP and CRMF ASN.1 types, covering parsing, serialization, PVNO 2 and 3, and message protection using either a shared secret (PasswordBasedMac and PBMAC1) or X.509 signatures.
* **`client`** implements the IR, CR, KUR and P10CR enrollment flows, including polling for deferred issuance, response verification and certificate confirmation.
* **`server`** exposes a CMP endpoint as a standard `http.Handler` that authenticates clients, tracks transactions, supports asynchronous issuance and enforces policy through middleware, including the Lightweight CMP Profile.

Interoperability is exercised by integration tests: the client against EJBCA and OpenSSL, and the server against the Siemens CMP Test Suite.
