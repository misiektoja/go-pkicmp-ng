package client

import "fmt"

// ClientError indicates a CMP client operational failure.
type ClientError struct {
	Op  string // operation that failed (e.g., "verify response", "HTTP request")
	Err error  // optional wrapped error
}

func (e *ClientError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cmp: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("cmp: %s", e.Op)
}

func (e *ClientError) Unwrap() error {
	return e.Err
}
