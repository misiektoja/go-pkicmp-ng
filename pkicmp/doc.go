// Package pkicmp implements the Certificate Management Protocol (CMP) as defined
// in RFC 9810, with CRMF support per RFC 4211.
//
// This is the foundational package of the go-pkicmp module. It defines the
// protocol types, message construction, protection, and verification. The
// [server] and [client] packages build on it. Callers who need direct control
// over CMP messages — for custom tooling, RA proxying, or testing — can use
// this package independently.
//
// # Message construction
//
// [PKIMessage] is the top-level type, corresponding to the ASN.1 PKIMessage
// structure. Create one with [NewPKIMessage], supplying a [PKIBody] and
// [MessageOptions]. TransactionID and SenderNonce default to 128 bits of random
// data per RFC 9810 §5.1.1.
//
// [PKIBody] constructors (e.g., [NewIRBody], [NewIPBody], [NewPKIConfBody]) wrap
// the corresponding CHOICE variant. [PKIBody] is lazy: it carries the raw DER
// and decodes into the appropriate Go type only when a typed getter
// (e.g., [PKIBody.IR], [PKIBody.IP]) is called.
//
// [PKIMessage.MarshalBinary] and [ParsePKIMessage] are the only points where
// CMP messages become wire bytes and back; all other types exist only in memory.
// Implementing [encoding.BinaryMarshaler] and [encoding.BinaryUnmarshaler] makes
// [PKIMessage] compatible with standard Go HTTP tooling.
//
// # Protection
//
// [Credentials] is the interface for applying message protection. Two concrete
// types cover all standard CMP protection schemes:
//
//   - [MACCredentials]: password-based MAC, created with [NewMACCredentials].
//     Defaults to PBMAC1 (RFC 8018), the recommended algorithm per RFC 9481 §7.
//     Use [WithPBM] for PasswordBasedMac.
//   - [SignatureCredentials]: X.509 signature, created with [NewSignatureCredentials].
//
// Apply protection by calling [Credentials.Protect]:
//
//	creds, err := pkicmp.NewMACCredentials([]byte("shared-secret"))
//	if err != nil { ... }
//	err = creds.Protect(msg)
//
// # Verification
//
// [PKIMessage.Verify] verifies message protection. [VerifyOptions] accepts a
// shared secret (MAC), a [crypto/x509.CertPool] (signature), or both when the
// protection algorithm is not known in advance:
//
//	result, err := msg.Verify(pkicmp.VerifyOptions{SharedSecret: []byte("shared-secret")})
//
// When both are supplied, the message decides which mechanism is used. Set
// [VerifyOptions.RequiredProtection] to [ProtectionMAC] or [ProtectionSignature]
// to pin it instead, which RFC 9483 §3.1 asks for within one PKI management
// operation. The zero value accepts either mechanism. That is what a server needs
// for the first message of an operation, and what a client needs to talk to a CA
// that authenticates by shared secret and signs its responses.
//
// Signature verification also binds the protection certificate to the identity
// the message claims: when the header sender carries a directory name, it must
// equal the subject of the certificate that produced the signature (RFC 9483 §3.5).
// A NULL DN sender, which RFC 4210 §5.1.1 requires when the sender does not know
// its own name, carries no name to bind and is accepted on the trust chain alone.
//
// [VerifyResult.ProtectionParams] captures the algorithm parameters from a verified
// MAC-protected message. Pass it to [NewMACCredentials] with [WithProtectionAlgorithm]
// to protect a response with the same algorithm suite (with a fresh salt),
// as required by RFC 9483 §3.2.
//
// # Caller responsibilities
//
// This package verifies message protection and parses CMP on the wire. It does
// not implement a full enrollment client or CA policy. Integrators remain
// responsible for the checks below.
//
// Pin the protection mechanism per message. [VerifyOptions.RequiredProtection]
// defaults to [ProtectionAny], which accepts whichever mechanism the received
// message carries. That is appropriate when the peer's mechanism is genuinely
// unknown, such as a server seeing the first message of an operation. When you
// supply both a shared secret and trust anchors, or when you already know which
// mechanism the peer must use for this message, pin [RequiredProtection] to that
// mechanism instead. Pin to the mechanism you expect on the message being
// verified, not necessarily the one you use when sending: a client that enrolls
// with a shared secret but receives signature-protected CA responses should pin
// [ProtectionSignature] when verifying those responses. Leaving the default while
// holding both kinds of trust material lets an attacker satisfy verification
// with whichever mechanism is easier to forge.
//
// Retain the protection certificate across a transaction. A CA may send
// [extraCerts] only on its first response (RFC 9810 §5.1). Later messages such
// as [pkiConf] can arrive with no candidate signer in the message itself.
// [VerifyResult.ProtectionCertificate] is the certificate whose signature was
// accepted; offer it back through [VerifyOptions.ExtraCerts] or
// [VerifyOptions.TrustedCert] when verifying later messages in the same
// operation.
//
// Bind the issued certificate to the request. After a successful issuance
// response, compare the returned certificate's public key to the key you
// requested. This package does not perform that check. A CA may legitimately
// change the subject under [StatusGrantedWithMods]; comparing subjects is a
// policy choice left to the caller.
//
// Treat [VerifyResult.MACVerified] as authoritative for [caPubs]. RFC 9810
// §5.3.2 allows an end entity to trust CA certificates carried in [caPubs] only
// when the message was MAC-verified. Do not treat [caPubs] from a
// signature-verified message as automatically trustworthy without your own
// anchor and policy.
//
// Bound polling yourself when you implement deferred issuance. [PollRepContent]
// carries [checkAfter] as an integer seconds value chosen by the peer. This
// package parses it as sent; clamping abusive values before sleeping is the
// caller's responsibility.
//
// Optional strictness knobs. [VerifyOptions.RequireDigitalSignatureKeyUsage]
// rejects a protection certificate whose keyUsage extension omits
// digitalSignature, as RFC 9483 §3.5 requires. It is off by default because
// deployed CAs often protect CMP with a CA certificate that sets only keyCertSign
// and cRLSign. Enable it only when every peer is known to conform.
//
// Status text and failure bits. [PKIStatusInfo.AsError] joins server-supplied
// free text into [PKIStatusError.StatusString] without validating UTF-8 or
// stripping control characters. Treat it as diagnostic input from an
// authenticated peer at most, and do not log it verbatim in security-sensitive
// contexts without sanitization. [PKIFailureInfo] parsing does not fully
// validate BIT STRING unused-bits encoding; do not rely on rare failure bits
// without treating ambiguous parses as absent.
//
// # Errors
//
// All errors from this package are typed:
//
//   - [ParseError]: malformed message, missing required field, or an algorithm
//     parameter outside the range this package accepts from an untrusted peer.
//   - [ProtectionError]: failure applying protection.
//   - [VerificationError]: bad MAC or signature, a protection mechanism the caller
//     did not require, or a sender that does not match the protection certificate.
//
// Each carries an [InvalidReason] for programmatic inspection.
package pkicmp
