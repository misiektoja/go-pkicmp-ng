package client

import (
	"context"
	"crypto/x509"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// SendP10CR sends a PKCS#10 CSR to the CA (RFC 9810 §5.3.3).
// The message envelope is protected by the provided credentials.
func (c *Client) SendP10CR(ctx context.Context, csrDER []byte, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}

	body := pkicmp.NewP10CRBody(csr)
	return c.enroll(ctx, body, pkicmp.BodyTypeCP, creds, ropts)
}
