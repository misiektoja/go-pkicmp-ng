//go:build integration

package cmptestsuite

import (
	"bytes"
	"io"
)

// prefixWriter wraps an io.Writer and prepends a prefix to each complete line.
// Incomplete lines are buffered until a newline arrives.
type prefixWriter struct {
	w      io.Writer
	prefix []byte
	buf    []byte // buffered incomplete line
}

func newPrefixWriter(w io.Writer, prefix string) *prefixWriter {
	return &prefixWriter{w: w, prefix: []byte(prefix)}
}

func (pw *prefixWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		nl := bytes.IndexByte(p, '\n')
		if nl == -1 {
			pw.buf = append(pw.buf, p...)
			return total, nil
		}
		if _, err := pw.w.Write(pw.prefix); err != nil {
			return total, err
		}
		if len(pw.buf) > 0 {
			if _, err := pw.w.Write(pw.buf); err != nil {
				return total, err
			}
			pw.buf = pw.buf[:0]
		}
		if _, err := pw.w.Write(p[:nl+1]); err != nil {
			return total, err
		}
		p = p[nl+1:]
	}
	return total, nil
}
