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

// enrollmentExchange serves one enrollment: an ip for the first request and a pkiConf for the certConf.
type enrollmentExchange struct {
	// issuer mints the end-entity certificate returned in the ip.
	issuer *certyaml.Certificate
	// sender, when set, is placed in the header of every response.
	sender pkix.Name
	// extraCertsOnIP and extraCertsOnPKIConf model servers that stop sending
	// certificates after their first message.
	extraCertsOnIP      []*x509.Certificate
	extraCertsOnPKIConf []*x509.Certificate
	// protect applies message protection to each response.
	protect func(*pkicmp.PKIMessage)

	// recipientSeen records the recipient the client put in its first request.
	recipientSeen pkicmp.GeneralName
	issuedCert    *x509.Certificate
	calls         int
}

func (e *enrollmentExchange) start(t *testing.T) *httptest.Server {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := pkicmp.ParsePKIMessage(body)
		require.NoError(t, err)

		e.calls++
		resp := &pkicmp.PKIMessage{
			Header: pkicmp.PKIHeader{
				PVNO:          req.Header.PVNO,
				TransactionID: req.Header.TransactionID,
				RecipNonce:    req.Header.SenderNonce,
			},
		}
		if !isEmptyTestName(e.sender) {
			resp.Header.Sender = pkicmp.NewDirectoryName(e.sender)
		}

		var attached []*x509.Certificate
		if e.calls == 1 {
			e.recipientSeen = req.Header.Recipient
			e.issuedCert = issueForRequest(e.issuer, pkix.Name{CommonName: "enrolled-ee"}, req)
			require.NotNil(t, e.issuedCert)
			resp.Body = pkicmp.NewIPBody(&pkicmp.CertRepMessage{
				Response: []pkicmp.CertResponse{{
					CertReqID: 0,
					Status:    pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
					CertifiedKeyPair: &pkicmp.CertifiedKeyPair{
						CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: e.issuedCert.Raw}},
					},
				}},
			})
			attached = e.extraCertsOnIP
		} else {
			resp.Body = pkicmp.NewPKIConfBody()
			attached = e.extraCertsOnPKIConf
		}
		for _, cert := range attached {
			resp.ExtraCerts = append(resp.ExtraCerts, pkicmp.CMPCertificate{Raw: cert.Raw})
		}

		e.protect(resp)

		der, err := resp.MarshalBinary()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(der)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return server
}

func isEmptyTestName(name pkix.Name) bool {
	return name.CommonName == "" && len(name.Organization) == 0 && len(name.Country) == 0
}

func macProtector(secret string) func(*pkicmp.PKIMessage) {
	return func(msg *pkicmp.PKIMessage) {
		creds, _ := pkicmp.NewMACCredentials([]byte(secret))
		_ = creds.Protect(msg)
	}
}

func signatureProtector(key crypto.Signer, cert *x509.Certificate) func(*pkicmp.PKIMessage) {
	return func(msg *pkicmp.PKIMessage) {
		creds, _ := pkicmp.NewSignatureCredentials(key, cert)
		_ = creds.Protect(msg)
		// ProtectWithSignature sets senderKID from the certificate. Clearing it
		// models a server that omits the field, which leaves the sender name as
		// the only hint to the signer.
		msg.Header.SenderKID = nil
	}
}

// A CA routes on the recipient field, so a name the caller built in Go must
// reach the wire. pkix.Name.Names is empty for such a name, so testing it to
// decide whether a recipient was configured silently drops it.
func TestRequestCarriesProgrammaticallyBuiltRecipient(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=recipient-test-ca"}
	exchange := &enrollmentExchange{issuer: ca, protect: macProtector("secret")}
	server := exchange.start(t)

	recipient := pkix.Name{
		Country:      []string{"DE"},
		Organization: []string{"Example"},
		CommonName:   "issuing-ca",
	}
	require.Empty(t, recipient.Names, "a programmatically built name has no parsed attributes")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithRecipient(recipient))
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)

	require.NotEmpty(t, exchange.recipientSeen.DirectoryName, "recipient must not be dropped")
	assert.Equal(t, recipient.String(), exchange.recipientSeen.DirectoryName.String())
}

// A CA that issues from an intermediate returns that intermediate in
// extraCerts, so the issued certificate must validate against a trust anchor
// that holds only the root.
func TestIssuedCertificateChainsThroughExtraCertsIntermediate(t *testing.T) {
	isCA := true
	root := &certyaml.Certificate{Subject: "cn=interop-root"}
	rootCert, err := root.X509Certificate()
	require.NoError(t, err)
	intermediate := &certyaml.Certificate{Subject: "cn=interop-intermediate", Issuer: root, IsCA: &isCA}
	intermediateCert, err := intermediate.X509Certificate()
	require.NoError(t, err)

	exchange := &enrollmentExchange{
		issuer:         intermediate,
		extraCertsOnIP: []*x509.Certificate{&intermediateCert},
		protect:        macProtector("secret"),
	}
	server := exchange.start(t)

	trustPool := x509.NewCertPool()
	trustPool.AddCert(&rootCert)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithTrustedCAs(trustPool))
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
	assert.Equal(t, "interop-intermediate", result.Certificate.Issuer.CommonName)
}

// A server may send extraCerts only on its first message, so a later message in
// the same operation must still verify against the signer already authenticated.
func TestPKIConfVerifiesAgainstSignerFromEarlierMessage(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=retained-signer-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	cmpSigner := &certyaml.Certificate{Subject: "cn=cmp-signer", Issuer: ca}
	cmpSignerCert, err := cmpSigner.X509Certificate()
	require.NoError(t, err)
	cmpSignerTLS, err := cmpSigner.TLSCertificate()
	require.NoError(t, err)

	exchange := &enrollmentExchange{
		issuer:              ca,
		sender:              pkix.Name{CommonName: "cmp-signer"},
		extraCertsOnIP:      []*x509.Certificate{&cmpSignerCert},
		extraCertsOnPKIConf: nil,
		protect:             signatureProtector(cmpSignerTLS.PrivateKey.(crypto.Signer), &cmpSignerCert),
	}
	server := exchange.start(t)

	trustPool := x509.NewCertPool()
	trustPool.AddCert(&caCert)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithTrustedCAs(trustPool))
	result, err := c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
}

// Retaining the earlier signer must not let any other certificate close the
// operation, even one that chains to the same trust anchor.
func TestPKIConfRejectsSignerThatDidNotProtectEarlierMessage(t *testing.T) {
	ca := &certyaml.Certificate{Subject: "cn=retained-signer-ca"}
	caCert, err := ca.X509Certificate()
	require.NoError(t, err)
	cmpSigner := &certyaml.Certificate{Subject: "cn=cmp-signer", Issuer: ca}
	cmpSignerCert, err := cmpSigner.X509Certificate()
	require.NoError(t, err)
	cmpSignerTLS, err := cmpSigner.TLSCertificate()
	require.NoError(t, err)
	impostor := &certyaml.Certificate{Subject: "cn=impostor", Issuer: ca}
	impostorCert, err := impostor.X509Certificate()
	require.NoError(t, err)
	impostorTLS, err := impostor.TLSCertificate()
	require.NoError(t, err)

	exchange := &enrollmentExchange{
		issuer:         ca,
		sender:         pkix.Name{CommonName: "cmp-signer"},
		extraCertsOnIP: []*x509.Certificate{&cmpSignerCert},
	}
	signWithCMPSigner := signatureProtector(cmpSignerTLS.PrivateKey.(crypto.Signer), &cmpSignerCert)
	signWithImpostor := signatureProtector(impostorTLS.PrivateKey.(crypto.Signer), &impostorCert)
	exchange.protect = func(msg *pkicmp.PKIMessage) {
		if exchange.calls == 1 {
			signWithCMPSigner(msg)
			return
		}
		signWithImpostor(msg)
	}
	server := exchange.start(t)

	trustPool := x509.NewCertPool()
	trustPool.AddCert(&caCert)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	creds, err := pkicmp.NewMACCredentials([]byte("secret"))
	require.NoError(t, err)

	c := client.NewClient(server.URL, client.WithTrustedCAs(trustPool))
	_, err = c.SendIR(context.Background(), key, creds, client.WithTemplateSubject(pkix.Name{CommonName: "test"}))
	require.Error(t, err)

	var ce *client.Error
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "verify PKIConf", ce.Op)
}
