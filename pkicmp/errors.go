package pkicmp

import (
	"fmt"
)

// InvalidReason defines specific reasons for protection or verification failure.
type InvalidReason int

const (
	// ReasonUnknown indicates an unspecified failure.
	ReasonUnknown InvalidReason = iota
	// ReasonUnsupportedAlgorithm indicates an unrecognized or unavailable OID.
	ReasonUnsupportedAlgorithm
	// ReasonMissingSharedSecret indicates a MAC-based operation lacked a key.
	ReasonMissingSharedSecret
	// ReasonMissingSigner indicates a signature-based operation lacked a key.
	ReasonMissingSigner
	// ReasonBadMAC indicates the message integrity check failed.
	ReasonBadMAC
	// ReasonSignatureFailed indicates the cryptographic signature was invalid.
	ReasonSignatureFailed
	// ReasonMissingTrustAnchors indicates no trust anchors were provided for signature verification.
	ReasonMissingTrustAnchors
)

func (r InvalidReason) String() string {
	switch r {
	case ReasonUnsupportedAlgorithm:
		return "unsupported algorithm"
	case ReasonMissingSharedSecret:
		return "missing shared secret"
	case ReasonMissingSigner:
		return "missing signer"
	case ReasonBadMAC:
		return "MAC verification failed"
	case ReasonSignatureFailed:
		return "signature verification failed"
	case ReasonMissingTrustAnchors:
		return "missing trust anchors"
	default:
		return "unknown"
	}
}

// VerificationError indicates that message protection verification failed.
type VerificationError struct {
	Reason InvalidReason
	Err    error
}

func (e *VerificationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pkicmp: verification failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("pkicmp: verification failed: %s", e.Reason)
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

// ProtectionError indicates that applying message protection failed.
type ProtectionError struct {
	Reason InvalidReason
	Err    error
}

func (e *ProtectionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pkicmp: protection failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("pkicmp: protection failed: %s", e.Reason)
}

func (e *ProtectionError) Unwrap() error {
	return e.Err
}

// ParseError indicates that a CMP message or structure could not be decoded.
type ParseError struct {
	Detail string // human-readable description of what failed
	Err    error  // optional wrapped error
}

func (e *ParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pkicmp: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("pkicmp: %s", e.Detail)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}
