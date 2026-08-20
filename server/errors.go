package server

import (
	"fmt"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// Error can be returned by Handler to control the CMP error response.
// If a Handler returns a plain error, the server maps it to systemFailure.
type Error struct {
	// Status is the PKI status code for the response.
	Status pkicmp.PKIStatus
	// FailureInfo gives machine-readable reason bits.
	FailureInfo pkicmp.PKIFailureInfo
	// StatusText is an optional human-readable explanation.
	StatusText string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("server: status %s", e.Status)
	if e.FailureInfo != 0 {
		msg += fmt.Sprintf(", failInfo: %s", e.FailureInfo)
	}
	if e.StatusText != "" {
		msg += fmt.Sprintf(": %s", e.StatusText)
	}
	return msg
}

// errorToStatusInfo maps a handler error to PKIStatusInfo for CMP responses.
func errorToStatusInfo(err error) pkicmp.PKIStatusInfo {
	if err == nil {
		return pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}
	}
	if se, ok := err.(*Error); ok {
		si := pkicmp.PKIStatusInfo{
			Status:   se.Status,
			FailInfo: se.FailureInfo,
		}
		if se.StatusText != "" {
			si.StatusString = pkicmp.PKIFreeText{se.StatusText}
		}
		return si
	}
	// Unknown error → systemFailure.
	return pkicmp.PKIStatusInfo{
		Status:       pkicmp.StatusRejection,
		FailInfo:     pkicmp.FailSystemFailure,
		StatusString: pkicmp.PKIFreeText{err.Error()},
	}
}
