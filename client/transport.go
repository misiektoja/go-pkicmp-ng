package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// enroll performs the full CMP enrollment transaction:
// request → response → [poll] → certConf → pkiConf
// (RFC 9810 §5.3.1–§5.3.4, Appendix C.4).
func (c *Client) enroll(ctx context.Context, reqBody *pkicmp.PKIBody, expectedRepType pkicmp.BodyType, creds pkicmp.Credentials, opts *requestOptions) (*EnrollResult, error) {
	if creds == nil {
		return nil, &ClientError{Op: "protect request", Err: fmt.Errorf("no credentials provided")}
	}
	sender := pkicmp.GeneralName{}
	if opts.sender != nil {
		sender = pkicmp.NewDirectoryName((*opts.sender).ToRDNSequence())
	} else if sc, ok := creds.(*pkicmp.SignatureCredentials); ok && sc.Cert != nil {
		// RFC 9810 §C.5/C.6: sender name SHOULD be present for CR/KUR.
		sender = pkicmp.NewDirectoryName(sc.Cert.Subject.ToRDNSequence())
	}

	recipient := pkicmp.GeneralName{}
	if len(c.recipient.Names) > 0 || len(c.recipient.ExtraNames) > 0 {
		recipient = pkicmp.NewDirectoryName(c.recipient.ToRDNSequence())
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
		return nil, &ClientError{Op: "protect request", Err: err}
	}

	reqDER, err := msg.MarshalBinary()
	if err != nil {
		return nil, &ClientError{Op: "marshal request", Err: err}
	}

	respDER, err := c.sendHTTP(ctx, reqDER)
	if err != nil {
		return nil, err
	}

	resp, err := pkicmp.ParsePKIMessage(respDER)
	if err != nil {
		return nil, &ClientError{Op: "parse response", Err: err}
	}

	vr, err := c.verifyResponse(msg, resp, creds, c.trustedCAs)
	if err != nil {
		return nil, &ClientError{Op: "verify response", Err: err}
	}

	if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
		return nil, &ClientError{Op: fmt.Sprintf("unsupported protocol version: %d", resp.Header.PVNO)}
	}

	if resp.Body.Type == pkicmp.BodyTypeError {
		return nil, parseErrorResponse(resp)
	}

	if resp.Body.Type != expectedRepType {
		return nil, &ClientError{Op: fmt.Sprintf("unexpected response body type: %d", resp.Body.Type)}
	}

	certResp, rep, err := extractCertRespAndRep(resp, expectedRepType)
	if err != nil {
		return nil, err
	}

	if certResp.Status.Status == pkicmp.StatusWaiting {
		resp, vr, err = c.poll(ctx, msg.Header, resp, creds, certResp.CertReqID)
		if err != nil {
			return nil, err
		}
		certResp, rep, err = extractCertRespAndRep(resp, expectedRepType)
		if err != nil {
			return nil, err
		}
	}

	if certResp.Status.Status != pkicmp.StatusAccepted && certResp.Status.Status != pkicmp.StatusGrantedWithMods {
		return nil, certResp.Status.AsError()
	}

	cert, err := extractCertificate(certResp)
	if err != nil {
		return nil, err
	}

	// Build effective trust pool: start with pre-configured trusted CAs, add any
	// caPubs bootstrapped via PBM (RFC 9810 §5.3.2).
	effectiveTrustPool := c.trustedCAs
	caPubs := rep.TrustedCAPubs(vr)
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

	// RFC 9810 §8.9: Verify the issued certificate against trusted CAs.
	if effectiveTrustPool != nil {
		verifyOpts := x509.VerifyOptions{
			Roots:     effectiveTrustPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(verifyOpts); err != nil {
			return nil, &ClientError{Op: "verify certificate trust", Err: err}
		}
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
		return nil, &ClientError{Op: "compute certHash", Err: err}
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
		return nil, &ClientError{Op: "protect certConf", Err: err}
	}

	confDER, err := confMsg.MarshalBinary()
	if err != nil {
		return nil, &ClientError{Op: "marshal certConf", Err: err}
	}

	confRespDER, err := c.sendHTTP(ctx, confDER)
	if err != nil {
		return nil, &ClientError{Op: "certConf exchange", Err: err}
	}

	// RFC 9810 §5.3.18: The server MUST respond with PKIConf.
	confResp, err := pkicmp.ParsePKIMessage(confRespDER)
	if err != nil {
		return nil, &ClientError{Op: "parse PKIConf", Err: err}
	}

	if _, err := c.verifyResponse(confMsg, confResp, creds, effectiveTrustPool); err != nil {
		return nil, &ClientError{Op: "verify PKIConf", Err: err}
	}

	if confResp.Body.Type == pkicmp.BodyTypeError {
		return nil, parseErrorResponse(confResp)
	}

	if confResp.Body.Type != pkicmp.BodyTypePKIConf {
		return nil, &ClientError{Op: fmt.Sprintf("expected PKIConf but got body type %d", confResp.Body.Type)}
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
		return nil, nil, &ClientError{Op: fmt.Sprintf("unsupported expected response type %d", expectedRepType)}
	}
	if err != nil {
		return nil, nil, err
	}
	if len(rep.Response) == 0 {
		return nil, nil, &ClientError{Op: "empty response"}
	}
	return &rep.Response[0], rep, nil
}

func (c *Client) sendHTTP(ctx context.Context, reqDER []byte) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqDER))
	if err != nil {
		return nil, &ClientError{Op: "create HTTP request", Err: err}
	}
	httpReq.Header.Set("Content-Type", "application/pkixcmp")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &ClientError{Op: "HTTP request", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	readBody := io.Reader(resp.Body)
	if c.maxResponseBytes > 0 {
		readBody = io.LimitReader(resp.Body, c.maxResponseBytes+1)
	}

	body, err := io.ReadAll(readBody)
	if err != nil {
		return nil, &ClientError{Op: "read response", Err: err}
	}
	if c.maxResponseBytes > 0 && int64(len(body)) > c.maxResponseBytes {
		return nil, &ClientError{Op: fmt.Sprintf("response body too large: limit=%d", c.maxResponseBytes)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &ClientError{Op: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))}
	}

	// RFC 6712 §3: Response Content-Type MUST be application/pkixcmp.
	if ct := resp.Header.Get("Content-Type"); ct != "application/pkixcmp" {
		return nil, &ClientError{Op: fmt.Sprintf("unexpected Content-Type: %s", ct)}
	}

	return body, nil
}

func parseErrorResponse(msg *pkicmp.PKIMessage) error {
	errContent, err := msg.Body.Error()
	if err != nil {
		return &ClientError{Op: "error parsing ErrorMsgContent", Err: err}
	}
	return errContent.PKIStatusInfo.AsError()
}

func extractCertificate(resp *pkicmp.CertResponse) (*x509.Certificate, error) {
	if resp.CertifiedKeyPair == nil {
		return nil, &ClientError{Op: "missing certifiedKeyPair in response"}
	}
	cert := resp.CertifiedKeyPair.CertOrEncCert.Certificate
	if cert == nil {
		return nil, &ClientError{Op: "encrypted certificates not yet supported"}
	}
	return cert.Parse()
}

// poll implements the client-side polling state machine (RFC 9810 §5.3.22).
// It sends pollReq messages and respects the server's checkAfter interval
// until a final response (ip/cp/kup) or error is received.
func (c *Client) poll(ctx context.Context, origHeader pkicmp.PKIHeader, lastResp *pkicmp.PKIMessage, creds pkicmp.Credentials, certReqID int64) (*pkicmp.PKIMessage, *pkicmp.VerifyResult, error) {
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
			return nil, nil, &ClientError{Op: "protect poll request", Err: err}
		}

		pollDER, err := pollMsg.MarshalBinary()
		if err != nil {
			return nil, nil, &ClientError{Op: "marshal poll request", Err: err}
		}

		respDER, err := c.sendHTTP(ctx, pollDER)
		if err != nil {
			return nil, nil, err
		}

		resp, err := pkicmp.ParsePKIMessage(respDER)
		if err != nil {
			return nil, nil, &ClientError{Op: "parse polled response", Err: err}
		}

		vr, err := c.verifyResponse(pollMsg, resp, creds, c.trustedCAs)
		if err != nil {
			return nil, nil, &ClientError{Op: "verify polled response", Err: err}
		}

		if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
			return nil, nil, &ClientError{Op: fmt.Sprintf("unsupported protocol version: %d", resp.Header.PVNO)}
		}

		if resp.Body.Type == pkicmp.BodyTypeError {
			return nil, nil, parseErrorResponse(resp)
		}

		if resp.Body.Type == pkicmp.BodyTypePollRep {
			pollRep, err := resp.Body.PollRep()
			if err != nil {
				return nil, nil, err
			}
			if len(*pollRep) > 0 {
				waitTime = time.Duration((*pollRep)[0].CheckAfter) * time.Second
			}
			lastResp = resp
			continue
		}
		return resp, vr, nil
	}

	return nil, nil, &ClientError{Op: fmt.Sprintf("polling exceeded max retries (%d)", c.maxPolls)}
}

func (c *Client) verifyResponse(req *pkicmp.PKIMessage, resp *pkicmp.PKIMessage, creds pkicmp.Credentials, trustedCAs *x509.CertPool) (*pkicmp.VerifyResult, error) {
	if !bytes.Equal(resp.Header.TransactionID, req.Header.TransactionID) {
		return nil, &ClientError{Op: "transaction ID mismatch"}
	}

	if !bytes.Equal(resp.Header.RecipNonce, req.Header.SenderNonce) {
		return nil, &ClientError{Op: "recipient nonce mismatch"}
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
		return nil, &ClientError{Op: "missing protection algorithm in response"}
	}

	vr, err := resp.Verify(pkicmp.VerifyOptions{
		Credentials: creds,
		TrustPool:   trustedCAs,
		ExtraCerts:  resp.ExtraCerts,
		SenderKID:   resp.Header.SenderKID,
	})
	if err != nil {
		return nil, &ClientError{Op: "verify protection", Err: err}
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
