package client

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

type requestOptions struct {
	sender          *pkix.Name
	senderKID       []byte
	templateSubject *pkix.Name
	templateExts    []pkix.Extension
	oldCertificate  *x509.Certificate
}

// RequestOption configures a specific enrollment request.
type RequestOption func(*requestOptions)

// WithSender sets the sender name in the PKIHeader.
func WithSender(name pkix.Name) RequestOption {
	return func(o *requestOptions) { o.sender = &name }
}

// WithSenderKID sets the PKIHeader senderKID field for all outgoing messages
// in this request. For MAC-protected requests, this carries the reference
// number that identifies the shared secret to the recipient
// (RFC 9810 §5.1.1, RFC 4210 §5.1.3.1).
func WithSenderKID(kid []byte) RequestOption {
	return func(o *requestOptions) { o.senderKID = kid }
}

// WithTemplateSubject sets the subject name in the CRMF CertTemplate.
func WithTemplateSubject(subject pkix.Name) RequestOption {
	return func(o *requestOptions) { o.templateSubject = &subject }
}

// WithTemplateExtension adds an extension to the CRMF CertTemplate.
func WithTemplateExtension(ext pkix.Extension) RequestOption {
	return func(o *requestOptions) { o.templateExts = append(o.templateExts, ext) }
}

// WithOldCertificate overrides the certificate identified by the oldCertID control in a KUR.
func WithOldCertificate(certificate *x509.Certificate) RequestOption {
	return func(o *requestOptions) { o.oldCertificate = certificate }
}
