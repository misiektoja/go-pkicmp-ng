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
// [VerifyResult.ProtectionParams] captures the algorithm parameters from a verified
// MAC-protected message. Pass it to [NewMACCredentials] with [WithProtectionAlgorithm]
// to protect a response with the same algorithm suite (with a fresh salt),
// as required by RFC 9483 §3.2.
//
// # Errors
//
// All errors from this package are typed:
//
//   - [ParseError]: malformed message or missing required field.
//   - [ProtectionError]: failure applying protection.
//   - [VerificationError]: bad MAC or signature.
//
// Each carries an [InvalidReason] for programmatic inspection.
package pkicmp
