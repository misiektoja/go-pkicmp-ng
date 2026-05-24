package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
	"github.com/tsaarni/go-pkicmp/client"
	"github.com/tsaarni/go-pkicmp/pkicmp"
)

type mockServerConfig struct {
	caCert        *x509.Certificate
	serverKey     crypto.Signer
	serverCert    *x509.Certificate
	wrongCACert   *x509.Certificate
	otherEECert   *x509.Certificate
	respProtector string // "pbm" or "sig" or "pbm-server-secret"
	postProtect   func(req, resp *pkicmp.PKIMessage)
}

func setupValidationCerts() mockServerConfig {
	ca := &certyaml.Certificate{Subject: "cn=validation-test-ca"}
	caCert, _ := ca.X509Certificate()

	serverCert := &certyaml.Certificate{Subject: "cn=cmp-server", Issuer: ca}
	serverTLS, _ := serverCert.TLSCertificate()
	serverX509, _ := serverCert.X509Certificate()

	otherCA := &certyaml.Certificate{Subject: "cn=other-ca"}
	otherEE := &certyaml.Certificate{Subject: "cn=other-ee", Issuer: otherCA}
	otherEECert, _ := otherEE.X509Certificate()

	wrongCA := &certyaml.Certificate{Subject: "cn=malicious-ca"}
	wrongCACert, _ := wrongCA.X509Certificate()

	return mockServerConfig{
		caCert:      &caCert,
		serverKey:   serverTLS.PrivateKey.(crypto.Signer),
		serverCert:  &serverX509,
		wrongCACert: &wrongCACert,
		otherEECert: &otherEECert,
	}
}

func setupMockServer(cfg mockServerConfig, mutateResp func(req, resp *pkicmp.PKIMessage)) *httptest.Server {
	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee"}
	eeCert, _ := ee.X509Certificate()

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
			Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
					},
				}},
			}),
		}

		if mutateResp != nil {
			mutateResp(req, resp)
		}

		switch cfg.respProtector {
		case "sig":
			_ = resp.ProtectWithSignature(cfg.serverKey, cfg.serverCert)
		case "pbm-server-secret":
			_ = resp.ProtectWithMAC([]byte("server-secret"))
		default:
			_ = resp.ProtectWithMAC([]byte("secret"))
		}

		if cfg.postProtect != nil {
			cfg.postProtect(req, resp)
		}

		der, _ := resp.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}

	return httptest.NewServer(http.HandlerFunc(handler))
}

func TestCAPubsTrustBootstrap(t *testing.T) {
	recipient := pkix.Name{CommonName: "target-ca"}

	targetCA := &certyaml.Certificate{Subject: "cn=target-ca"}
	targetCACert, _ := targetCA.X509Certificate()

	ee := &certyaml.Certificate{Subject: "cn=enrolled-ee", Issuer: targetCA}
	eeCert, _ := ee.X509Certificate()

	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		req, _ := pkicmp.ParsePKIMessage(body)

		var respMsg *pkicmp.PKIMessage
		if callCount == 1 {
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewIPBody(&pkicmp.CertRepMessage{
					CAPubs: []pkicmp.CMPCertificate{{Raw: targetCACert.Raw}},
					Response: []pkicmp.CertResponse{{
						CertReqID: 0,
						Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
						CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
							CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: eeCert.Raw}},
						},
					}},
				}),
			}
			_ = respMsg.ProtectWithMAC([]byte("secret"))
		} else {
			respMsg = &pkicmp.PKIMessage{
				Header: pkicmp.PKIHeader{
					PVNO:          req.Header.PVNO,
					TransactionID: req.Header.TransactionID,
					RecipNonce:    req.Header.SenderNonce,
				},
				Body: pkicmp.NewPKIConfBody(),
			}
			_ = respMsg.ProtectWithMAC([]byte("secret"))
		}

		der, _ := respMsg.MarshalBinary()
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithRecipient(recipient))
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))

	require.NoError(t, err)
	assert.NotNil(t, result.Certificate)
	assert.Equal(t, eeCert.SerialNumber, result.Certificate.SerialNumber)

	require.Len(t, result.CAPubs, 1)
	assert.Equal(t, targetCACert.Raw, result.CAPubs[0].Raw)
}

func TestResponseValidationRejectsMismatchedIssuer(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		ipBody, _ := resp.Body.IP()
		ipBody.CAPubs = []pkicmp.CMPCertificate{{Raw: cfg.wrongCACert.Raw}}
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithRecipient(pkix.Name{CommonName: "target-ca"}))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.ClientError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
}

func TestResponseValidationRejectsMismatchedTransactionID(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		resp.Header.TransactionID = []byte("evil-transaction-id")
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.ClientError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify response", ce.Op)
	var inner *client.ClientError
	require.ErrorAs(t, ce.Err, &inner)
	assert.Equal(t, "transaction ID mismatch", inner.Op)
}

func TestResponseValidationRejectsMismatchedNonce(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		resp.Header.RecipNonce = []byte("evil-nonce")
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.ClientError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify response", ce.Op)
	var inner *client.ClientError
	require.ErrorAs(t, ce.Err, &inner)
	assert.Equal(t, "recipient nonce mismatch", inner.Op)
}

func TestResponseValidationRejectsInvalidMAC(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.postProtect = func(req, resp *pkicmp.PKIMessage) {
		resp.Protection[0] ^= 0xFF
	}
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonBadMAC, ve.Reason)
}

func TestResponseValidationRejectsInvalidSignature(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "sig"
	cfg.postProtect = func(req, resp *pkicmp.PKIMessage) {
		resp.Protection[0] ^= 0xFF
	}
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonSignatureFailed, ve.Reason)
}

func TestResponseValidationRejectsUntrustedCA(t *testing.T) {
	cfg := setupValidationCerts()
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		ipBody, _ := resp.Body.IP()
		ipBody.Response[0].CertifiedKeyPair.CertOrEncCert.Certificate = &pkicmp.CMPCertificate{Raw: cfg.otherEECert.Raw}
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.ClientError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify certificate trust", ce.Op)
	assert.Contains(t, ce.Err.Error(), "certificate signed by unknown authority")
}

func TestResponseValidationRejectsSignatureWithoutTrustedCAs(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "sig"
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingTrustAnchors, ve.Reason)
}

func TestResponseValidationRejectsPBMResponseWithoutSecret(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "pbm-server-secret"
	server := setupMockServer(cfg, nil)
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)
	// Signature protection for request, but response uses PBM with unknown secret.
	creds, err := pkicmp.NewSignatureCredentials(cfg.serverKey, cfg.serverCert)
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithTrustedCAs(trustedCAs))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonMissingSharedSecret, ve.Reason)
}

func TestResponseValidationRejectsMismatchedSenderKID(t *testing.T) {
	cfg := setupValidationCerts()
	cfg.respProtector = "sig"
	server := setupMockServer(cfg, func(req, resp *pkicmp.PKIMessage) {
		resp.Header.Sender = pkicmp.NewDirectoryName(pkix.Name{CommonName: "cmp-server"}.ToRDNSequence())
		resp.Header.SenderKID = []byte("wrong-sender-kid")
	})
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(cfg.caCert)

	c := client.NewClient(
		server.URL,
		client.WithTrustedCAs(trustedCAs),
		client.WithRecipient(pkix.Name{CommonName: "cmp-server"}),
	)

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ve *pkicmp.VerificationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, pkicmp.ReasonSignatureFailed, ve.Reason)
}

func TestResponseValidationRejectsOversizedHTTPResponse(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(make([]byte, 129))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithMaxResponseBytes(128))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var ce *client.ClientError
	require.ErrorAs(t, err, &ce)
	assert.Contains(t, ce.Op, "response body too large")
}

func TestResponseValidationCustomResponseLimitAllowsSmallResponse(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write([]byte{0x00})
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)
	c := client.NewClient(server.URL, client.WithMaxResponseBytes(1024))

	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	var pe *pkicmp.ParseError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Detail, "invalid PKIMessage sequence")
}
