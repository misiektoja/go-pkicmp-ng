package client

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// SendIR performs an Initialization Request (RFC 9810 §5.3.1).
// Typically protected by a shared-secret MAC.
func (c *Client) SendIR(ctx context.Context, key crypto.Signer, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, key, creds, pkicmp.BodyTypeIP, opts)
}

// SendCR performs a Certification Request for an additional certificate (RFC 9810 §5.3.3).
// Typically protected by an existing certificate's signature.
func (c *Client) SendCR(ctx context.Context, key crypto.Signer, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, key, creds, pkicmp.BodyTypeCP, opts)
}

// SendKUR performs a Key Update Request (RFC 9810 §5.3.5).
// Typically protected by an existing certificate's signature.
func (c *Client) SendKUR(ctx context.Context, newKey crypto.Signer, creds pkicmp.Credentials, opts ...RequestOption) (*EnrollResult, error) {
	return c.sendCRMF(ctx, newKey, creds, pkicmp.BodyTypeKUP, opts)
}

func (c *Client) sendCRMF(ctx context.Context, key crypto.Signer, creds pkicmp.Credentials, expectedRepType pkicmp.BodyType, opts []RequestOption) (*EnrollResult, error) {
	ropts := &requestOptions{}
	for _, opt := range opts {
		opt(ropts)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, &Error{Op: "marshal public key", Err: err}
	}

	tmpl := pkicmp.CertTemplate{
		PublicKey: pubDER,
	}

	if ropts.templateSubject != nil {
		tmpl.Subject = pkicmp.NewDirectoryName(*ropts.templateSubject)
	}

	if len(ropts.templateExts) > 0 {
		extDER, err := asn1.Marshal(ropts.templateExts)
		if err != nil {
			return nil, &Error{Op: "marshal extensions", Err: err}
		}
		tmpl.Extensions = extDER
	}

	certReq := pkicmp.CertRequest{
		CertReqID:    0,
		CertTemplate: tmpl,
	}

	certReqMsg := pkicmp.CertReqMsg{
		CertReq: certReq,
	}

	if err := certReqMsg.GeneratePOP(key); err != nil {
		return nil, &Error{Op: "generate POP", Err: err}
	}

	reqs := pkicmp.CertReqMessages{certReqMsg}
	var body *pkicmp.PKIBody
	switch expectedRepType {
	case pkicmp.BodyTypeIP:
		body = pkicmp.NewIRBody(&reqs)
	case pkicmp.BodyTypeCP:
		body = pkicmp.NewCRBody(&reqs)
	case pkicmp.BodyTypeKUP:
		body = pkicmp.NewKURBody(&reqs)
	default:
		return nil, &Error{Op: fmt.Sprintf("unsupported CRMF expected response type %d", expectedRepType)}
	}

	return c.enroll(ctx, body, expectedRepType, creds, ropts)
}
