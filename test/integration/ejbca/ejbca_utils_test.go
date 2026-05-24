//go:build integration

// Package integration provides helpers for managing EJBCA end entities during integration tests.
//
// EJBCA is configured in client mode (pre-registering end entities) rather than RA mode.
// This allows certificate-based CMPv2 authentication for CR/KUR requests, which enables
// signature-protected flows that would fail in RA mode with EJBCA Community Edition.
//
// EJBCA SOAP/Web Service API: https://docs.keyfactor.com/ejbca/latest/web-service-interface
//
// SOAP operations used:
//   - editUser  — create or reset an end entity (upsert)
//   - revokeUser — revoke and optionally delete an end entity
//
// EJBCA REST API: https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface
//
// The SOAP interface is used here instead of REST because the /endentity/ REST resource
// is an EJBCA Enterprise-only feature and is not available in Community Edition. Had it
// been available, the following endpoints would have been used instead:
//   - POST   /ejbca/ejbca-rest-api/v1/endentity                        — create end entity
//   - DELETE /ejbca/ejbca-rest-api/v1/endentity/{endentity_name}       — delete end entity

package ejbca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	ejbcaSuperAdminCert = "testdata/superadmin-cert.pem"
	ejbcaSuperAdminKey  = "testdata/superadmin-key.pem"
	ejbcaCACert         = "testdata/ca.pem"
	ejbcaCAName         = "TestCA"
	ejbcaCMPEndpoint    = "http://localhost:8080/ejbca/publicweb/cmp/integration"
)

// ejbcaAdmin provides an admin client for managing EJBCA resources in tests.
type ejbcaAdmin struct {
	httpClient *http.Client
	soapURL    string
	CACert     *x509.Certificate
	Endpoint   string
}

// newEJBCAAdminClient creates a new EJBCA admin client.
func newEJBCAAdminClient(t testing.TB) *ejbcaAdmin {
	t.Helper()

	tlsCert, err := tls.LoadX509KeyPair(ejbcaSuperAdminCert, ejbcaSuperAdminKey)
	require.NoError(t, err, "load superadmin cert/key")

	caPEM, err := os.ReadFile(ejbcaCACert)
	require.NoError(t, err, "read CA cert")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caPEM)
	block, _ := pem.Decode(caPEM)
	require.NotNil(t, block, "no PEM block in CA cert")
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "parse CA cert")

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{tlsCert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			},
		},
	}

	return &ejbcaAdmin{
		httpClient: httpClient,
		soapURL:    "https://localhost:8443/ejbca/ejbcaws/ejbcaws",
		CACert:     caCert,
		Endpoint:   ejbcaCMPEndpoint,
	}
}

// TrustedCAs returns a CertPool containing the CA certificate for trust verification.
func (a *ejbcaAdmin) TrustedCAs() *x509.CertPool {
	trustedCAs := x509.NewCertPool()
	trustedCAs.AddCert(a.CACert)
	return trustedCAs
}

// soapCall sends a SOAP request to EJBCA and returns the response body.
func (a *ejbcaAdmin) soapCall(t testing.TB, body string) []byte {
	t.Helper()

	envelope := fmt.Sprintf(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.protocol.core.ejbca.org/"><soapenv:Body>%s</soapenv:Body></soapenv:Envelope>`, body)

	resp, err := a.httpClient.Post(a.soapURL, "text/xml; charset=utf-8", strings.NewReader(envelope))
	require.NoError(t, err, "SOAP request")
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read SOAP response")

	t.Logf("SOAP response: %s", string(respBody))

	if strings.Contains(string(respBody), "<soap:Fault>") {
		t.Fatalf("SOAP fault: %s", string(respBody))
	}

	return respBody
}

// CreateEndEntity creates an end entity with the given username and password.
// Uses editUser which is an upsert — creates or resets the entity.
func (a *ejbcaAdmin) CreateEndEntity(t testing.TB, username, password string) {
	t.Helper()

	a.soapCall(t, fmt.Sprintf(`<ws:editUser><arg0>`+
		`<caName>`+ejbcaCAName+`</caName>`+
		`<certificateProfileName>MYENDUSER</certificateProfileName>`+
		`<clearPwd>true</clearPwd>`+
		`<endEntityProfileName>MYENDUSER</endEntityProfileName>`+
		`<password>%s</password>`+
		`<status>10</status>`+
		`<subjectDN>CN=%s</subjectDN>`+
		`<tokenType>USERGENERATED</tokenType>`+
		`<username>%s</username>`+
		`</arg0></ws:editUser>`, password, username, username))

	t.Logf("Created end entity: %s", username)
	t.Cleanup(func() { a.DeleteEndEntity(t, username) })
}

// DeleteEndEntity removes an end entity by username. Errors are logged but do not fail the test.
func (a *ejbcaAdmin) DeleteEndEntity(t testing.TB, username string) {
	t.Helper()

	// EJBCA WS does not expose deleteUser directly; use revokeUser with deleteUser=true.
	envelope := fmt.Sprintf(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.protocol.core.ejbca.org/"><soapenv:Body>`+
		`<ws:revokeUser><arg0>%s</arg0><arg1>0</arg1><arg2>true</arg2></ws:revokeUser>`+
		`</soapenv:Body></soapenv:Envelope>`, username)
	resp, err := a.httpClient.Post(a.soapURL, "text/xml; charset=utf-8", strings.NewReader(envelope))
	if err != nil {
		t.Logf("DeleteEndEntity %s: HTTP error: %v", username, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "<soap:Fault>") {
		t.Logf("DeleteEndEntity %s: SOAP fault (ignored): %s", username, string(body))
		return
	}
	t.Logf("Deleted end entity: %s", username)
}
