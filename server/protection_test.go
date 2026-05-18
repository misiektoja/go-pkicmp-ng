package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
	"github.com/tsaarni/go-pkicmp/client"
	"github.com/tsaarni/go-pkicmp/pkicmp"
	"github.com/tsaarni/go-pkicmp/server"
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
	_ = msg.ProtectWithSignature(clientKey, &clientX509)
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
	_ = msg.ProtectWithSignature(clientKey, &clientX509)
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
type pbmac1Creds struct {
	secret []byte
}

func (c *pbmac1Creds) Protect(msg *pkicmp.PKIMessage) error {
	return msg.ProtectWithPBMAC1(c.secret)
}

func (c *pbmac1Creds) SharedSecret() []byte {
	return c.secret
}
