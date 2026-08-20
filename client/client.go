package client

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
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
	minCheckAfter      time.Duration
	maxCheckAfter      time.Duration
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

	// DefaultMinCheckAfter is the shortest interval the client waits between poll
	// attempts, however short an interval the server asks for in checkAfter.
	//
	// RFC 9810 §5.3.22 asks an end entity to wait at least the interval the
	// server sent, so a floor only ever waits longer than it was told to.
	DefaultMinCheckAfter = 1 * time.Second

	// DefaultMaxCheckAfter is the longest interval the client waits between poll
	// attempts, however long an interval the server asks for in checkAfter.
	//
	// RFC 9810 §5.3.22 tells an end entity to wait at least the number of seconds
	// the server sent and notes that the value depends heavily on the deployment,
	// because issuance may be delayed by backend load, by an offline transfer
	// between PKI management entities or by an RA operator approving by hand. A
	// ceiling that cuts a server's interval down therefore polls sooner than the
	// CA asked for. The default sits far above any interval a CA is expected to
	// request, so that it guards only against a value large enough to park an
	// operation indefinitely or, once past what a duration can hold, wrap into no
	// wait at all.
	//
	// Polling can take up to [DefaultMaxPolls] such intervals, so a context
	// deadline remains the only bound covering a whole operation.
	DefaultMaxCheckAfter = 60 * time.Minute
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
		minCheckAfter:    DefaultMinCheckAfter,
		maxCheckAfter:    DefaultMaxCheckAfter,
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
// rejects a response whose signer does not chain to a trusted CA.
//
// A successful shared-secret enrollment does not need the pool. The MAC
// provides authenticity, and caPubs from the response may be trusted directly
// as root CAs (RFC 9810 §5.3.2), which is how a device holding only an initial
// authentication key obtains its first anchor.
//
// Configure it anyway wherever an anchor is already available, for two reasons
// that apply even to a shared-secret client. A CA must sign an error message
// however the request was protected (RFC 4210 §5.3.21 and RFC 9810 §5.3.21), so
// without a pool a rejection such as transactionIdInUse cannot be verified, and
// that is the message a caller most needs to act on. Some CAs are also
// configured to sign every response, not only errors, and a shared-secret client
// cannot complete an operation with one of those at all.
//
// A client with no anchor yet is a supported configuration, not a
// misconfiguration. The status of an error message it cannot verify is still
// reported, as an [UnverifiedStatusError] the caller may log but must not act
// on.
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

// WithCheckAfterLimits sets the interval range the client clamps a
// server-provided checkAfter value into while polling.
//
// checkAfter is an unbounded integer chosen by the peer, so an unclamped value
// either parks the operation far past any interval an operator intended or, once
// it exceeds what a duration can hold, collapses into no wait at all and turns
// polling into a tight request loop. The defaults are [DefaultMinCheckAfter] and
// [DefaultMaxCheckAfter].
//
// A maximum below the interval a CA asks for makes the client poll sooner than
// RFC 9810 §5.3.22 tells it to wait, so lower it only for a deployment whose CA
// is known to issue quickly.
//
// A negative bound is treated as zero, and a maximum below the minimum is raised
// to it, which polls at a fixed interval. Setting both to zero polls as fast as
// the server asks and leaves [WithMaxPolls] and the context deadline as the only
// bound on the operation.
func WithCheckAfterLimits(minimum, maximum time.Duration) Option {
	return func(c *Client) {
		if minimum < 0 {
			minimum = 0
		}
		if maximum < minimum {
			maximum = minimum
		}
		c.minCheckAfter = minimum
		c.maxCheckAfter = maximum
	}
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
