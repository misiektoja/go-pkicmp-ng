package client

import (
	"fmt"
	"strings"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// Error indicates a CMP client operational failure.
type Error struct {
	Op  string // operation that failed (e.g., "verify response", "HTTP request")
	Err error  // optional wrapped error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cmp: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("cmp: %s", e.Op)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// UnverifiedStatusError reports the status carried by an error message whose
// protection the client could not verify.
//
// A CA signs an error message whatever protected the request (RFC 4210 §5.3.21
// and RFC 9810 §5.3.21), so a client configured only with a shared secret and no
// trust anchors cannot authenticate one. The exchange still fails, and the
// wrapped error says why verification failed, but the status the peer claimed is
// reported here rather than discarded, because a rejection such as
// transactionIdInUse is what tells an operator what to do next.
//
// Nothing in this error is authenticated. Any peer able to answer the request,
// including one that has taken over the connection, chooses these values freely.
// Log them, and where a trust anchor is available configure [WithTrustedCAs] so
// that a rejection is verified instead. The type deliberately does not wrap a
// [pkicmp.PKIStatusError], so [pkicmp.HasFailure] keeps reporting only
// authenticated failure bits.
type UnverifiedStatusError struct {
	// Status is the unauthenticated status the peer claimed.
	Status pkicmp.PKIStatus
	// StatusString is the unauthenticated free text the peer supplied, joined
	// into one string. It is peer-controlled and unvalidated, so it is left out
	// of the error text: escape it before writing it to a log or a terminal.
	StatusString string
	// FailInfo holds the unauthenticated failure bits the peer claimed.
	FailInfo pkicmp.PKIFailureInfo
	// Err is the verification failure that made the status untrustworthy.
	Err error
}

func (e *UnverifiedStatusError) Error() string {
	msg := fmt.Sprintf("cmp: unverified status %s", e.Status)
	if e.FailInfo != 0 {
		msg += fmt.Sprintf(", failInfo: %s", e.FailInfo)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(": %v", e.Err)
	}
	return msg
}

func (e *UnverifiedStatusError) Unwrap() error {
	return e.Err
}

// withUnverifiedStatus reports the status of an unverifiable error message alongside the verification failure
func withUnverifiedStatus(msg *pkicmp.PKIMessage, err error) error {
	if msg.Body == nil || msg.Body.Type != pkicmp.BodyTypeError {
		return err
	}
	content, parseErr := msg.Body.Error()
	if parseErr != nil {
		return err
	}
	return &UnverifiedStatusError{
		Status:       content.PKIStatusInfo.Status,
		StatusString: strings.Join(content.PKIStatusInfo.StatusString, "; "),
		FailInfo:     content.PKIStatusInfo.FailInfo,
		Err:          err,
	}
}
