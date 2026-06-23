package client

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// Client handles CMP message transport and polling.
type Client struct {
	endpoint           string
	httpClient         *http.Client
	recipient          pkix.Name
	extraCerts         []*x509.Certificate
	trustedCAs         *x509.CertPool
	responseProtection pkicmp.ProtectionMechanism
	maxResponseBytes   int64
	maxPolls           int
}

const (
	// DefaultMaxResponseBytes limits CMP HTTP response size to reduce memory DoS risk.
	DefaultMaxResponseBytes int64 = 10 * 1024 * 1024 // 10 MiB

	// DefaultMaxPolls limits how many pollReq messages are attempted before the
	// client gives up.
	//
	// Prefer using context timeouts/deadlines to cap total operation time because
	// server-provided checkAfter values can vary greatly and total polling time is
	// maxPolls multiplied by those intervals.
	DefaultMaxPolls = 60
)

// Option is a functional option for configuring a Client.
type Option func(*Client)

// NewClient creates a new CMP client.
func NewClient(endpoint string, opts ...Option) *Client {
	c := &Client{
		endpoint:         endpoint,
		httpClient:       http.DefaultClient,
		maxResponseBytes: DefaultMaxResponseBytes,
		maxPolls:         DefaultMaxPolls,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithRecipient sets the expected CA name in the header.
//
// Many CAs route on this field and refuse a request that omits it, so set it
// whenever the CA name is known.
func WithRecipient(name pkix.Name) Option {
	return func(c *Client) { c.recipient = name }
}

// WithResponseProtection requires every response in an operation to use the given protection mechanism.
//
// The default, [pkicmp.ProtectionAny], accepts whichever mechanism the server
// used. RFC 9483 §3.1 asks for one kind of protection throughout a PKI
// management operation, but deployed CAs answer a shared-secret request with a
// signature and remain interoperable, and RFC 9810 §5.3.21 requires an error
// message to be signed regardless of how the request was protected. Pinning the
// mechanism therefore has to be the caller's decision.
//
// Pinning is not what stops a peer from substituting an identity: a response is
// already bound to the operation by the transaction ID and nonces, a
// signature-protected response must chain to a configured trust anchor and name
// its own protection certificate in the sender field, and an issued certificate
// must certify the requested public key.
func WithResponseProtection(mechanism pkicmp.ProtectionMechanism) Option {
	return func(c *Client) { c.responseProtection = mechanism }
}

// WithExtraCerts sets extra certificates to include in requests.
func WithExtraCerts(certs []*x509.Certificate) Option {
	return func(c *Client) { c.extraCerts = certs }
}

// WithTrustedCAs sets the trusted CA certificate pool used for response
// verification and issued certificate validation.
//
// Required for signature-protected responses (RFC 9810 §8.9): the client
// rejects responses whose signer does not chain to a trusted CA.
//
// Not required for PBM-protected responses: the MAC provides authenticity,
// and caPubs from the response may be directly trusted as root CAs
// (RFC 9810 §5.3.2).
func WithTrustedCAs(trustedCAs *x509.CertPool) Option {
	return func(c *Client) { c.trustedCAs = trustedCAs }
}

// WithMaxResponseBytes sets the maximum number of bytes accepted from a CMP
// HTTP response body. Set to 0 or a negative value to disable the limit.
func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) { c.maxResponseBytes = n }
}

// WithMaxPolls sets the maximum number of poll attempts.
//
// Prefer using context timeouts/deadlines to cap total operation time because
// server-provided checkAfter values can vary greatly and total polling time is
// maxPolls multiplied by those intervals.
func WithMaxPolls(n int) Option {
	return func(c *Client) { c.maxPolls = n }
}

// EnrollResult holds the result of a successful enrollment.
type EnrollResult struct {
	// Certificate is the issued end-entity certificate from the server.
	Certificate *x509.Certificate
	// CAPubs contains CA certificates from the caPubs field of the response (RFC 9810 §5.3.4).
	CAPubs []*x509.Certificate
	// ExtraCertificates contains certificates from the PKIMessage extraCerts field (RFC 9810 §5.1).
	ExtraCertificates []*x509.Certificate
}
