// Package pkicmp provides types for handling Certificate Management Protocol (CMP)
// messages as defined in RFC 9810.
//
// # How it works
//
// This package is built around the [PKIMessage] struct. While most structs in
// the package (like [PKIHeader] and [PKIBody]) are public so you can easily
// read or set their fields, only the top-level [PKIMessage] provides the
// standard Go [encoding.BinaryMarshaler] and [encoding.BinaryUnmarshaler]
// interfaces.
//
// # Standard Go Interfaces
//
// Use [PKIMessage.MarshalBinary] and [ParsePKIMessage] (which wraps UnmarshalBinary)
// to convert between Go structs and raw DER bytes. These methods make the
// package compatible with standard Go tools like [http.Client].
//
// # Message Construction
//
// Use [NewPKIMessage] to create a message with a body and header options.
// It auto-generates a random TransactionID and SenderNonce per RFC 9810 §5.1.1.
//
// # Protection and Verification
//
// [PKIMessage.Protect] is the primary API for applying message protection.
// It accepts a [Credentials] value — either [MACCredentials] (created
// with [NewMACCredentials]) or [SignatureCredentials] (created with
// [NewSignatureCredentials]). The sealed interface makes it impossible to
// accidentally mix protection modes.
//
// For lower-level control, [PKIMessage.ProtectWithMAC] and
// [PKIMessage.ProtectWithSignature] are also available.
//
// [PKIMessage.Verify] verifies the protection of a received message. Pass
// [VerifyOptions] with either a shared secret (for MAC) or a [crypto/x509.CertPool]
// (for signature). It returns a [VerifyResult] indicating which path was taken.
//
// Errors from this package are typed: [ParseError] for malformed messages,
// [ProtectionError] for protection failures, and [VerificationError] for
// verification failures. All carry an [InvalidReason] for programmatic inspection.
//
// # Internal Encoding Logic
//
// Components within the package use the cryptobyte library to process DER data
// as a stream. This approach is used for two practical reasons:
//
//  1. ASN.1 Nesting: In DER encoding, a "parent" (like a SEQUENCE) must know
//     the total size of its "children" before it can write its own length.
//     Marshaling is handled by passing a *cryptobyte.Builder to each component,
//     allowing them to append directly to a single shared buffer while the
//     library handles nested length calculations automatically.
//  2. Performance and Memory: Parsing is handled by passing a *cryptobyte.String.
//     This provides each component with a zero-copy "view" of the original
//     buffer, ensuring that no data is copied as the message is decoded into
//     the struct hierarchy.
//
// # Thread Safety
//
// Types in this package (including PKIMessage and PKIBody) are not thread-safe.
// Concurrent access to a message or any of its components must be synchronized
// by the caller.
//
// # Usage Example
//
// Building, protecting, sending, and verifying a CMP message:
//
//	// 1. Create a message
//	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
//	    Recipient: pkicmp.DirectoryName(caSubject),
//	})
//
//	// 2. Protect with a shared secret
//	_ = msg.ProtectWithMAC([]byte("my-shared-secret"))
//
//	// 3. Marshal and send via HTTP
//	der, _ := msg.MarshalBinary()
//	resp, _ := http.Post("https://ca.example.com/pkix/", "application/pkixcmp", bytes.NewReader(der))
//	defer resp.Body.Close()
//
//	// 4. Parse and verify the response
//	body, _ := io.ReadAll(resp.Body)
//	parsed, _ := pkicmp.ParsePKIMessage(body)
//	_, _ = parsed.Verify(pkicmp.VerifyOptions{Credentials: creds})
package pkicmp
