package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/client"
	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
	"github.com/misiektoja/go-pkicmp-ng/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
)

func TestUnprotectedMessage(t *testing.T) {
	secret := []byte("unprot-secret")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	errContent, _ := respMsg.Body.Error()
	assert.NotZero(t, errContent.PKIStatusInfo.FailInfo&pkicmp.FailBadMessageCheck)
}

func TestMACNotConfigured(t *testing.T) {
	srv := server.New(&mockHandler{})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	protectMAC(msg, []byte("some-secret"))
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestSignatureNotConfigured(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	clientCert := &certyaml.Certificate{Subject: "CN=Client", Issuer: ca}
	clientX509, _ := clientCert.X509Certificate()
	clientKey, _ := clientCert.PrivateKey()

	srv := server.New(&mockHandler{})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	{
		_sc, _ := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
		_ = _sc.Protect(msg)
	}
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	errContent, _ := respMsg.Body.Error()
	assert.Equal(t, pkicmp.StatusRejection, errContent.PKIStatusInfo.Status)
}

func TestBadMACVerification(t *testing.T) {
	secret := []byte("server-secret")

	srv := server.New(&mockHandler{}, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, _ := pkicmp.NewMACCredentials([]byte("wrong-secret"))
	c := client.NewClient(ts.URL)

	_, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "bad-mac-test"}),
		client.WithSender(pkix.Name{CommonName: "bad-mac-test"}),
	)
	require.Error(t, err)
}

func TestSignatureVerificationWithBadSigner(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Trusted CA"}

	untrustedCA := &certyaml.Certificate{Subject: "CN=Untrusted CA"}
	clientCert := &certyaml.Certificate{Subject: "CN=Client", Issuer: untrustedCA}
	clientX509, _ := clientCert.X509Certificate()
	clientKey, _ := clientCert.PrivateKey()

	srv := server.New(&mockHandler{}, server.WithCertificateLookup(&failingCertLookup{}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	{
		_sc, _ := pkicmp.NewSignatureCredentials(clientKey, &clientX509)
		_ = _sc.Protect(msg)
	}
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
	_ = ca
}

func TestMACLookupReturnsEmptySecret(t *testing.T) {
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&emptySecretLookup{}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	protectMAC(msg, []byte("some-secret"))
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestMACLookupReturnsError(t *testing.T) {
	srv := server.New(&mockHandler{}, server.WithSecretLookup(&failingLookup{}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	msg := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&pkicmp.CertReqMessages{
		{CertReq: pkicmp.CertRequest{CertReqID: 0}},
	}), macMessageOpts())
	protectMAC(msg, []byte("some-secret"))
	msgDER, _ := msg.MarshalBinary()

	resp, err := http.Post(ts.URL, "application/pkixcmp", strings.NewReader(string(msgDER)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	respMsg, _ := pkicmp.ParsePKIMessage(buf[:n])
	assert.Equal(t, pkicmp.BodyTypeError, respMsg.Body.Type)
}

func TestPBMAC1Protection(t *testing.T) {
	secret := []byte("pbmac1-secret")

	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	handler := &mockHandler{
		handleCertRequest: func(ctx context.Context, req *certRequest) (*certResponse, error) {
			return &certResponse{Certificate: issueCert(ca, req)}, nil
		},
	}

	srv := server.New(handler, server.WithSecretLookup(&staticMACLookup{secret: secret}))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds := &pbmac1Creds{secret: secret}

	c := client.NewClient(ts.URL)
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "pbmac1-test"}),
		client.WithSender(pkix.Name{CommonName: "pbmac1-test"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "CN=pbmac1-test", result.Certificate.Subject.String())
}

// pbmac1Creds explicitly uses PBMAC1 protection for testing.
// PBMAC1 is now the default, so this just wraps NewMACCredentials.
type pbmac1Creds struct {
	secret []byte
}

func (c *pbmac1Creds) Protect(msg *pkicmp.PKIMessage) error {
	mc, err := pkicmp.NewMACCredentials(c.secret)
	if err != nil {
		return err
	}
	return mc.Protect(msg)
}

func (c *pbmac1Creds) SharedSecret() []byte {
	return c.secret
}

// A signer key that does not match its certificate must be reported and must not
// leave the server issuing certificates it cannot protect.
func TestSignerMismatchIsRejected(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "CN=Test CA"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	secret := []byte("signer-mismatch-secret")

	issued := 0
	handler := &mockHandler{handleCertRequest: func(_ context.Context, req *certRequest) (*certResponse, error) {
		issued++
		return &certResponse{Certificate: issueCert(ca, req), CACerts: []*x509.Certificate{&caCert}}, nil
	}}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := server.New(handler,
		server.WithSigner(otherKey, &caCert),
		server.WithSecretLookup(&staticMACLookup{secret: secret}),
	)
	require.Error(t, srv.Err(), "New must report the mismatched signer")

	ts := httptest.NewServer(srv)
	defer ts.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	message := pkicmp.NewPKIMessage(
		pkicmp.NewIRBody(&pkicmp.CertReqMessages{newCertReqMsg(t, key, "signer-mismatch")}),
		macMessageOpts(),
	)
	protectMAC(message, secret)
	response := postCMP(t, ts, message)

	require.Equal(t, pkicmp.BodyTypeError, response.Body.Type)
	errorContent, err := response.Body.Error()
	require.NoError(t, err)
	assert.NotZero(t, errorContent.PKIStatusInfo.FailInfo&pkicmp.FailSystemFailure)
	assert.Zero(t, issued, "no certificate may be issued while protection is broken")
}
