package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// enroll performs the full CMP enrollment transaction:
// request → response → [poll] → certConf → pkiConf
// (RFC 9810 §5.3.1–§5.3.4, Appendix C.4).
func (c *Client) enroll(ctx context.Context, reqBody *pkicmp.PKIBody, expectedRepType pkicmp.BodyType, creds pkicmp.Credentials, opts *requestOptions, requestedKey crypto.PublicKey) (*EnrollResult, error) {
	if creds == nil {
		return nil, &Error{Op: "protect request", Err: fmt.Errorf("no credentials provided")}
	}
	sender := pkicmp.GeneralName{}
	if opts.sender != nil {
		sender = pkicmp.NewDirectoryName(*opts.sender)
	} else if sc, ok := creds.(*pkicmp.SignatureCredentials); ok && sc.Certificate() != nil {
		// RFC 9810 §C.5/C.6: sender name SHOULD be present for CR/KUR.
		sender = pkicmp.NewDirectoryName(sc.Certificate().Subject)
	}

	recipient := pkicmp.GeneralName{}
	if !isEmptyName(c.recipient) {
		recipient = pkicmp.NewDirectoryName(c.recipient)
	}

	msg := pkicmp.NewPKIMessage(reqBody, pkicmp.MessageOptions{
		Sender:    sender,
		Recipient: recipient,
	})

	for _, cert := range c.extraCerts {
		msg.ExtraCerts = append(msg.ExtraCerts, pkicmp.CMPCertificate{Raw: cert.Raw})
	}

	// RFC 9810 §5.1.1: senderKID identifies the key used for protection.
	// For MAC-protected requests it carries the reference number of the shared secret.
	msg.Header.SenderKID = opts.senderKID

	if err := creds.Protect(msg); err != nil {
		return nil, &Error{Op: "protect request", Err: err}
	}

	reqDER, err := msg.MarshalBinary()
	if err != nil {
		return nil, &Error{Op: "marshal request", Err: err}
	}

	httpResp, err := c.sendHTTP(ctx, reqDER)
	if err != nil {
		return nil, err
	}

	cmpResp, err := httpResp.parse("parse response")
	if err != nil {
		return nil, err
	}
	resp := cmpResp.message

	vr, err := c.verifyResponse(msg, resp, creds, c.trustedCAs, nil)
	if err != nil {
		return nil, cmpResp.wrapError(withUnverifiedStatus(resp, &Error{Op: "verify response", Err: err}))
	}
	// Keep the signer authenticated here so the rest of the operation can still
	// be verified when the server stops sending extraCerts.
	var knownSigner *x509.Certificate
	if vr != nil {
		knownSigner = vr.ProtectionCertificate
	}

	if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
		return nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unsupported protocol version: %d", resp.Header.PVNO)})
	}

	if resp.Body.Type == pkicmp.BodyTypeError {
		return nil, cmpResp.wrapError(parseErrorResponse(resp))
	}

	if resp.Body.Type != expectedRepType {
		return nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unexpected response body type: %d", resp.Body.Type)})
	}

	certResp, rep, err := extractCertRespAndRep(resp, expectedRepType)
	if err != nil {
		return nil, cmpResp.wrapError(err)
	}

	if certResp.Status.Status == pkicmp.StatusWaiting {
		cmpResp, vr, err = c.poll(ctx, msg.Header, resp, creds, certResp.CertReqID, knownSigner)
		if err != nil {
			return nil, err
		}
		resp = cmpResp.message
		if vr != nil && vr.ProtectionCertificate != nil {
			knownSigner = vr.ProtectionCertificate
		}
		certResp, rep, err = extractCertRespAndRep(resp, expectedRepType)
		if err != nil {
			return nil, cmpResp.wrapError(err)
		}
	}

	if certResp.Status.Status != pkicmp.StatusAccepted && certResp.Status.Status != pkicmp.StatusGrantedWithMods {
		return nil, cmpResp.wrapError(certResp.Status.AsError())
	}

	cert, err := extractCertificate(certResp)
	if err != nil {
		return nil, cmpResp.wrapError(err)
	}

	// Build effective trust pool: start with pre-configured trusted CAs, add any
	// caPubs bootstrapped via PBM (RFC 9810 §5.3.2).
	effectiveTrustPool := c.trustedCAs
	// D20: TrustedCAPubs removed; manually check MACVerified and iterate CAPubs.
	if vr != nil && vr.MACVerified && len(rep.CAPubs) > 0 {
		var caPubs []*x509.Certificate
		for _, c := range rep.CAPubs {
			parsed, err := c.Parse()
			if err != nil {
				continue
			}
			caPubs = append(caPubs, parsed)
		}
		if len(caPubs) > 0 {
			if effectiveTrustPool != nil {
				effectiveTrustPool = effectiveTrustPool.Clone()
			} else {
				effectiveTrustPool = x509.NewCertPool()
			}
			for _, ca := range caPubs {
				effectiveTrustPool.AddCert(ca)
			}
		}
	}

	// RFC 9810 §8.9: Verify the issued certificate against trusted CAs.
	if effectiveTrustPool != nil {
		// RFC 9810 §5.1: extraCerts carries the certificates needed to build the
		// path. A CA that issues from an intermediate returns that intermediate
		// here, so without this pool the chain cannot be completed against a
		// trust anchor that is the root.
		intermediates := x509.NewCertPool()
		for _, extraCert := range resp.ExtraCerts {
			if parsed, err := extraCert.Parse(); err == nil {
				intermediates.AddCert(parsed)
			}
		}
		verifyOpts := x509.VerifyOptions{
			Roots:         effectiveTrustPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(verifyOpts); err != nil {
			return nil, cmpResp.wrapError(&Error{Op: "verify certificate trust", Err: err})
		}
	}

	if err := checkIssuedKey(cert, requestedKey); err != nil {
		return nil, cmpResp.wrapError(err)
	}

	var parsedCACerts []*x509.Certificate
	for _, certPub := range rep.CAPubs {
		if pc, err := certPub.Parse(); err == nil {
			parsedCACerts = append(parsedCACerts, pc)
		}
	}

	var parsedExtraCerts []*x509.Certificate
	for _, extraCert := range resp.ExtraCerts {
		if pc, err := extraCert.Parse(); err == nil {
			parsedExtraCerts = append(parsedExtraCerts, pc)
		}
	}

	// RFC 9810 §5.3.18: certHash uses the hash algorithm from the certificate's
	// signature algorithm.
	certHash, err := certHashForCert(cert)
	if err != nil {
		return nil, cmpResp.wrapError(&Error{Op: "compute certHash", Err: err})
	}
	certStatus := pkicmp.CertStatus{
		CertHash:  certHash,
		CertReqID: certResp.CertReqID,
	}

	confMsg := pkicmp.NewPKIMessage(
		pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{certStatus}),
		pkicmp.MessageOptions{
			Sender:     sender,
			Recipient:  recipient,
			RecipNonce: resp.Header.SenderNonce,
		},
	)
	confMsg.Header.TransactionID = msg.Header.TransactionID
	// Preserve senderKID across all messages in this transaction (RFC 9810 §5.1.1).
	// For signature-based creds, ProtectWithSignature will overwrite this with the
	// cert SubjectKeyId; for MAC-based creds it must be set explicitly.
	confMsg.Header.SenderKID = msg.Header.SenderKID

	if err := creds.Protect(confMsg); err != nil {
		return nil, &Error{Op: "protect certConf", Err: err}
	}

	confDER, err := confMsg.MarshalBinary()
	if err != nil {
		return nil, &Error{Op: "marshal certConf", Err: err}
	}

	confHTTPResp, err := c.sendHTTP(ctx, confDER)
	if err != nil {
		return nil, &Error{Op: "certConf exchange", Err: err}
	}

	// RFC 9810 §5.3.18: The server MUST respond with PKIConf.
	confCMPResp, err := confHTTPResp.parse("parse PKIConf")
	if err != nil {
		return nil, err
	}
	confResp := confCMPResp.message

	if _, err := c.verifyResponse(confMsg, confResp, creds, effectiveTrustPool, knownSigner); err != nil {
		return nil, confCMPResp.wrapError(withUnverifiedStatus(confResp, &Error{Op: "verify PKIConf", Err: err}))
	}

	if confResp.Body.Type == pkicmp.BodyTypeError {
		return nil, confCMPResp.wrapError(parseErrorResponse(confResp))
	}

	if confResp.Body.Type != pkicmp.BodyTypePKIConf {
		return nil, confCMPResp.wrapError(&Error{Op: fmt.Sprintf("expected PKIConf but got body type %d", confResp.Body.Type)})
	}

	return &EnrollResult{
		Certificate:       cert,
		CAPubs:            parsedCACerts,
		ExtraCertificates: parsedExtraCerts,
	}, nil
}

func extractCertRespAndRep(resp *pkicmp.PKIMessage, expectedRepType pkicmp.BodyType) (*pkicmp.CertResponse, *pkicmp.CertRepMessage, error) {
	var rep *pkicmp.CertRepMessage
	var err error

	switch expectedRepType {
	case pkicmp.BodyTypeIP:
		rep, err = resp.Body.IP()
	case pkicmp.BodyTypeCP:
		rep, err = resp.Body.CP()
	case pkicmp.BodyTypeKUP:
		rep, err = resp.Body.KUP()
	default:
		return nil, nil, &Error{Op: fmt.Sprintf("unsupported expected response type %d", expectedRepType)}
	}
	if err != nil {
		return nil, nil, err
	}
	if len(rep.Response) == 0 {
		return nil, nil, &Error{Op: "empty response"}
	}
	return &rep.Response[0], rep, nil
}

// rawHTTPResponse holds a bounded CMP response body together with its HTTP status.
type rawHTTPResponse struct {
	body       []byte
	statusCode int
}

// cmpHTTPResponse holds a parsed CMP response together with its HTTP status.
type cmpHTTPResponse struct {
	message    *pkicmp.PKIMessage
	statusCode int
}

// parse parses the response body and retains a non-200 status as error context.
func (r *rawHTTPResponse) parse(op string) (*cmpHTTPResponse, error) {
	msg, err := pkicmp.ParsePKIMessage(r.body)
	if err != nil {
		return nil, r.wrapError(&Error{Op: op, Err: err})
	}
	return &cmpHTTPResponse{message: msg, statusCode: r.statusCode}, nil
}

// wrapError adds a non-200 HTTP status without hiding the wrapped CMP error.
func (r *rawHTTPResponse) wrapError(err error) error {
	if r.statusCode == http.StatusOK {
		return err
	}
	return &Error{Op: fmt.Sprintf("HTTP %d: %s", r.statusCode, http.StatusText(r.statusCode)), Err: err}
}

// wrapError adds a non-200 HTTP status without hiding the wrapped CMP error.
func (r *cmpHTTPResponse) wrapError(err error) error {
	if r.statusCode == http.StatusOK {
		return err
	}
	return &Error{Op: fmt.Sprintf("HTTP %d: %s", r.statusCode, http.StatusText(r.statusCode)), Err: err}
}

// supportsCMPResponse reports whether RFC 9811 requires handling CMP content for the HTTP status.
func supportsCMPResponse(statusCode int) bool {
	statusClass := statusCode / 100
	return statusClass == 2 || statusClass == 4 || statusClass == 5
}

// isCMPMediaType reports whether a Content-Type value identifies the CMP media type.
func isCMPMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/pkixcmp"
}

// newHTTPStatusError returns an operational error for an HTTP response without usable CMP content.
func newHTTPStatusError(statusCode int) error {
	return &Error{Op: fmt.Sprintf("HTTP %d: %s", statusCode, http.StatusText(statusCode))}
}

// sendHTTP sends a CMP request and returns bounded response content for supported HTTP status classes.
func (c *Client) sendHTTP(ctx context.Context, reqDER []byte) (*rawHTTPResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqDER))
	if err != nil {
		return nil, &Error{Op: "create HTTP request", Err: err}
	}
	httpReq.Header.Set("Content-Type", "application/pkixcmp")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &Error{Op: "HTTP request", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	readBody := io.Reader(resp.Body)
	if c.maxResponseBytes > 0 {
		readBody = io.LimitReader(resp.Body, c.maxResponseBytes+1)
	}

	body, err := io.ReadAll(readBody)
	if err != nil {
		return nil, &Error{Op: "read response", Err: err}
	}
	if c.maxResponseBytes > 0 && int64(len(body)) > c.maxResponseBytes {
		return nil, &Error{Op: fmt.Sprintf("response body too large: limit=%d", c.maxResponseBytes)}
	}

	if !supportsCMPResponse(resp.StatusCode) {
		return nil, newHTTPStatusError(resp.StatusCode)
	}

	// RFC 9811 Section 3.2: Response Content-Type MUST be application/pkixcmp.
	if ct := resp.Header.Get("Content-Type"); !isCMPMediaType(ct) {
		if resp.StatusCode != http.StatusOK {
			return nil, newHTTPStatusError(resp.StatusCode)
		}
		return nil, &Error{Op: fmt.Sprintf("unexpected Content-Type: %s", ct)}
	}

	if len(body) == 0 && resp.StatusCode != http.StatusOK {
		return nil, newHTTPStatusError(resp.StatusCode)
	}

	return &rawHTTPResponse{body: body, statusCode: resp.StatusCode}, nil
}

func parseErrorResponse(msg *pkicmp.PKIMessage) error {
	errContent, err := msg.Body.Error()
	if err != nil {
		return &Error{Op: "error parsing ErrorMsgContent", Err: err}
	}
	return errContent.PKIStatusInfo.AsError()
}

// isEmptyName reports whether a distinguished name carries no attributes at all.
func isEmptyName(name pkix.Name) bool {
	// pkix.Name.Names is populated only when a name is decoded from DER, so a
	// name a caller built in Go has it empty. Testing it to decide whether a
	// name was set silently discards every programmatically built name.
	return len(name.Country) == 0 &&
		len(name.Organization) == 0 &&
		len(name.OrganizationalUnit) == 0 &&
		len(name.Locality) == 0 &&
		len(name.Province) == 0 &&
		len(name.StreetAddress) == 0 &&
		len(name.PostalCode) == 0 &&
		name.SerialNumber == "" &&
		name.CommonName == "" &&
		len(name.Names) == 0 &&
		len(name.ExtraNames) == 0
}

// checkIssuedKey verifies that the issued certificate certifies the public key the client asked for.
func checkIssuedKey(cert *x509.Certificate, requested crypto.PublicKey) error {
	if requested == nil {
		return nil
	}
	// The subject is deliberately not compared: RFC 9810 §5.2.3 lets a CA return
	// grantedWithMods after changing requested fields such as the subject. The
	// public key is different, because a certificate for a key the client does
	// not hold is unusable and the mismatch would only surface later, far from
	// this exchange.
	type publicKeyComparer interface{ Equal(crypto.PublicKey) bool }
	issued, ok := cert.PublicKey.(publicKeyComparer)
	if !ok {
		return &Error{Op: fmt.Sprintf("cannot compare issued certificate public key of type %T with the requested key", cert.PublicKey)}
	}
	if !issued.Equal(requested) {
		return &Error{Op: "issued certificate does not certify the requested public key"}
	}
	return nil
}

func extractCertificate(resp *pkicmp.CertResponse) (*x509.Certificate, error) {
	if resp.CertifiedKeyPair == nil {
		return nil, &Error{Op: "missing certifiedKeyPair in response"}
	}
	cert := resp.CertifiedKeyPair.CertOrEncCert.Certificate
	if cert == nil {
		return nil, &Error{Op: "encrypted certificates not yet supported"}
	}
	return cert.Parse()
}

// clampCheckAfter converts a server-provided checkAfter, in seconds, into a wait within the configured limits
func (c *Client) clampCheckAfter(seconds int64) time.Duration {
	if seconds <= 0 {
		return c.minCheckAfter
	}
	// The comparison is made in seconds because converting first overflows
	// time.Duration for anything past about 292 years, and a negative duration
	// makes the wait elapse immediately.
	if seconds >= int64(c.maxCheckAfter/time.Second)+1 {
		return c.maxCheckAfter
	}
	wait := time.Duration(seconds) * time.Second
	if wait < c.minCheckAfter {
		return c.minCheckAfter
	}
	if wait > c.maxCheckAfter {
		return c.maxCheckAfter
	}
	return wait
}

// poll implements the client-side polling state machine (RFC 9810 §5.3.22).
// It sends pollReq messages and respects the server's checkAfter interval
// until a final response (ip/cp/kup) or error is received.
func (c *Client) poll(ctx context.Context, origHeader pkicmp.PKIHeader, lastResp *pkicmp.PKIMessage, creds pkicmp.Credentials, certReqID int64, knownSigner *x509.Certificate) (*cmpHTTPResponse, *pkicmp.VerifyResult, error) {
	var waitTime time.Duration

	for i := 0; i < c.maxPolls; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(waitTime):
			}
		}

		pollReq := pkicmp.PollReqContent{certReqID}

		pollMsg := pkicmp.NewPKIMessage(
			pkicmp.NewPollReqBody(&pollReq),
			pkicmp.MessageOptions{
				Sender:     origHeader.Sender,
				Recipient:  origHeader.Recipient,
				RecipNonce: lastResp.Header.SenderNonce,
			},
		)
		pollMsg.Header.TransactionID = origHeader.TransactionID
		pollMsg.Header.SenderKID = origHeader.SenderKID

		if err := creds.Protect(pollMsg); err != nil {
			return nil, nil, &Error{Op: "protect poll request", Err: err}
		}

		pollDER, err := pollMsg.MarshalBinary()
		if err != nil {
			return nil, nil, &Error{Op: "marshal poll request", Err: err}
		}

		httpResp, err := c.sendHTTP(ctx, pollDER)
		if err != nil {
			return nil, nil, err
		}

		cmpResp, err := httpResp.parse("parse polled response")
		if err != nil {
			return nil, nil, err
		}
		resp := cmpResp.message

		var delayedRequestNonce []byte
		if resp.Body.Type != pkicmp.BodyTypePollRep {
			// RFC 9483 Section 4.4: the final response may refer back to the request
			// whose processing was delayed rather than to the last pollReq.
			delayedRequestNonce = origHeader.SenderNonce
		}
		vr, err := c.verifyResponse(pollMsg, resp, creds, c.trustedCAs, knownSigner, delayedRequestNonce)
		if err != nil {
			return nil, nil, cmpResp.wrapError(withUnverifiedStatus(resp, &Error{Op: "verify polled response", Err: err}))
		}
		if vr != nil && vr.ProtectionCertificate != nil {
			knownSigner = vr.ProtectionCertificate
		}

		if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
			return nil, nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unsupported protocol version: %d", resp.Header.PVNO)})
		}

		if resp.Body.Type == pkicmp.BodyTypeError {
			return nil, nil, cmpResp.wrapError(parseErrorResponse(resp))
		}

		if resp.Body.Type == pkicmp.BodyTypePollRep {
			pollRep, err := resp.Body.PollRep()
			if err != nil {
				return nil, nil, err
			}
			if len(*pollRep) > 0 {
				waitTime = c.clampCheckAfter((*pollRep)[0].CheckAfter)
			}
			lastResp = resp
			continue
		}
		return cmpResp, vr, nil
	}

	return nil, nil, &Error{Op: fmt.Sprintf("polling exceeded max retries (%d)", c.maxPolls)}
}

// verifyResponse checks that a response belongs to the request and that its protection verifies.
//
// knownSigner, when not nil, is a protection certificate already authenticated
// earlier in the same operation. It is offered as an additional candidate
// signer because a server may send extraCerts only on its first message
// (RFC 9810 §5.1), while the candidate still has to satisfy the same chain,
// sender and signature checks as one the server supplied.
func (c *Client) verifyResponse(req *pkicmp.PKIMessage, resp *pkicmp.PKIMessage, creds pkicmp.Credentials, trustedCAs *x509.CertPool, knownSigner *x509.Certificate, alternativeRecipNonce ...[]byte) (*pkicmp.VerifyResult, error) {
	if !bytes.Equal(resp.Header.TransactionID, req.Header.TransactionID) {
		return nil, &Error{Op: "transaction ID mismatch"}
	}

	nonceMatches := bytes.Equal(resp.Header.RecipNonce, req.Header.SenderNonce)
	if !nonceMatches && len(alternativeRecipNonce) > 0 {
		nonceMatches = bytes.Equal(resp.Header.RecipNonce, alternativeRecipNonce[0])
	}
	if !nonceMatches {
		return nil, &Error{Op: "recipient nonce mismatch"}
	}

	// NOTE: Do NOT compare resp.Header.Sender against c.recipient here.
	// RFC 9810 §5.1.1 defines the sender field as a hint to locate the
	// verification key, not as an identity that must match the request's
	// recipient. The response sender is the CA/RA's own name, which may
	// legitimately differ from the recipient the client addressed (e.g.,
	// RA-forwarded requests, or CAs using a separate CMP signing identity).
	// Authenticity is established by verifying the protection: signature
	// chain against trusted CAs (§8.9), or MAC via shared secret.

	if resp.Header.ProtectionAlg == nil {
		return nil, &Error{Op: "missing protection algorithm in response"}
	}

	candidates := resp.ExtraCerts
	if knownSigner != nil {
		candidates = append(append([]pkicmp.CMPCertificate(nil), candidates...), pkicmp.CMPCertificate{Raw: knownSigner.Raw})
	}

	vr, err := resp.Verify(pkicmp.VerifyOptions{
		RequiredProtection: c.responseProtection,
		SharedSecret: func() []byte {
			type sharedSecreter interface{ SharedSecret() []byte }
			if ss, ok := creds.(sharedSecreter); ok {
				return ss.SharedSecret()
			}
			return nil
		}(),
		TrustPool:  trustedCAs,
		ExtraCerts: candidates,
		SenderKID:  resp.Header.SenderKID,
	})
	if err != nil {
		// The bare reason reads as an internal detail on a shared-secret client,
		// which is exactly the client that meets a signed error message without a
		// pool to check it against, so name the configuration that is missing.
		var verifyErr *pkicmp.VerificationError
		if trustedCAs == nil && errors.As(err, &verifyErr) && verifyErr.Reason == pkicmp.ReasonMissingTrustAnchors {
			return nil, &Error{Op: "verify protection", Err: fmt.Errorf("%w: the response is signature-protected and no trusted CAs are configured, which a shared-secret client also needs because error messages are signed (RFC 9810 §5.3.21)", err)}
		}
		return nil, &Error{Op: "verify protection", Err: err}
	}

	return vr, nil
}

// certHashForCert computes the certificate hash using the hash algorithm
// matching the certificate's signature algorithm (RFC 9810 §5.3.18).
func certHashForCert(cert *x509.Certificate) ([]byte, error) {
	hash := hashFromCertSigAlg(cert.SignatureAlgorithm)
	if hash == 0 {
		return nil, fmt.Errorf("unsupported signature algorithm: %v", cert.SignatureAlgorithm)
	}
	h := hash.New()
	h.Write(cert.Raw)
	return h.Sum(nil), nil
}

// hashFromCertSigAlg maps x509.SignatureAlgorithm to crypto.Hash.
func hashFromCertSigAlg(sigAlg x509.SignatureAlgorithm) crypto.Hash {
	switch sigAlg {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512
	default:
		return 0
	}
}
