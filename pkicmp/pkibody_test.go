package pkicmp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// RFC 9810 §5.1.2 (PKIBody getters and constructors tests)
func TestPKIBodyGetters(t *testing.T) {
	t.Run("IR", func(t *testing.T) {
		req := &CertReqMessages{
			{CertReq: CertRequest{CertReqID: 1}},
		}
		body := NewIRBody(req)
		assert.Equal(t, BodyTypeIR, body.Type)

		got, err := body.IR()
		require.NoError(t, err)
		assert.Equal(t, req, got)

		// Test mismatching getter
		_, err = body.CR()
		assert.Error(t, err)
	})

	t.Run("CR", func(t *testing.T) {
		req := &CertReqMessages{
			{CertReq: CertRequest{CertReqID: 2}},
		}
		body := NewCRBody(req)
		assert.Equal(t, BodyTypeCR, body.Type)

		got, err := body.CR()
		require.NoError(t, err)
		assert.Equal(t, req, got)
	})

	t.Run("KUR", func(t *testing.T) {
		req := &CertReqMessages{
			{CertReq: CertRequest{CertReqID: 3}},
		}
		body := NewKURBody(req)
		assert.Equal(t, BodyTypeKUR, body.Type)

		got, err := body.KUR()
		require.NoError(t, err)
		assert.Equal(t, req, got)
	})

	t.Run("KUP", func(t *testing.T) {
		rep := &CertRepMessage{
			Response: []CertResponse{{CertReqID: 4}},
		}
		body := NewKUPBody(rep)
		assert.Equal(t, BodyTypeKUP, body.Type)

		got, err := body.KUP()
		require.NoError(t, err)
		assert.Equal(t, rep, got)
	})

	t.Run("P10CR", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "test"},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
		require.NoError(t, err)

		csr, err := x509.ParseCertificateRequest(csrDER)
		require.NoError(t, err)

		body := NewP10CRBody(csr)
		assert.Equal(t, BodyTypeP10CR, body.Type)

		got, err := body.P10CR()
		if assert.NoError(t, err) {
			assert.Equal(t, csr.Raw, got.Raw)
		}
	})

	t.Run("CP", func(t *testing.T) {
		rep := &CertRepMessage{
			Response: []CertResponse{{CertReqID: 5, Status: PKIStatusInfo{Status: StatusAccepted}}},
		}
		body := NewCPBody(rep)
		assert.Equal(t, BodyTypeCP, body.Type)

		got, err := body.CP()
		require.NoError(t, err)
		assert.Equal(t, rep.Response[0].CertReqID, got.Response[0].CertReqID)
	})

	t.Run("IP", func(t *testing.T) {
		rep := &CertRepMessage{
			Response: []CertResponse{{CertReqID: 6, Status: PKIStatusInfo{Status: StatusAccepted}}},
		}
		body := NewIPBody(rep)
		assert.Equal(t, BodyTypeIP, body.Type)

		got, err := body.IP()
		require.NoError(t, err)
		assert.Equal(t, rep.Response[0].CertReqID, got.Response[0].CertReqID)
	})

	t.Run("PKIConf", func(t *testing.T) {
		body := NewPKIConfBody()
		assert.Equal(t, BodyTypePKIConf, body.Type)

		got, err := body.PKIConf()
		require.NoError(t, err)
		assert.NotNil(t, got)
	})

	t.Run("CertConf", func(t *testing.T) {
		conf := &CertConfirmContent{
			{CertHash: []byte{0x01, 0x02}, CertReqID: 1},
		}
		body := NewCertConfBody(conf)
		assert.Equal(t, BodyTypeCertConf, body.Type)

		got, err := body.CertConf()
		require.NoError(t, err)
		assert.Equal(t, (*conf)[0].CertHash, (*got)[0].CertHash)
	})

	t.Run("PollReq", func(t *testing.T) {
		req := &PollReqContent{1, 2}
		body := NewPollReqBody(req)
		assert.Equal(t, BodyTypePollReq, body.Type)

		got, err := body.PollReq()
		require.NoError(t, err)
		assert.Equal(t, *req, *got)
	})

	t.Run("PollRep", func(t *testing.T) {
		rep := &PollRepContent{
			{CertReqID: 1, CheckAfter: 30},
		}
		body := NewPollRepBody(rep)
		assert.Equal(t, BodyTypePollRep, body.Type)

		got, err := body.PollRep()
		require.NoError(t, err)
		assert.Equal(t, (*rep)[0].CheckAfter, (*got)[0].CheckAfter)
	})

	t.Run("Error", func(t *testing.T) {
		e := &ErrorMsgContent{
			PKIStatusInfo: PKIStatusInfo{Status: StatusRejection},
		}
		body := NewErrorBody(e)
		assert.Equal(t, BodyTypeError, body.Type)

		got, err := body.Error()
		require.NoError(t, err)
		assert.Equal(t, e.PKIStatusInfo.Status, got.PKIStatusInfo.Status)
	})
}

func TestPKIBodyGetterMismatches(t *testing.T) {
	body := NewPKIConfBody()

	t.Run("IRMismatch", func(t *testing.T) { _, err := body.IR(); assert.Error(t, err) })
	t.Run("CRMismatch", func(t *testing.T) { _, err := body.CR(); assert.Error(t, err) })
	t.Run("KURMismatch", func(t *testing.T) { _, err := body.KUR(); assert.Error(t, err) })
	t.Run("KUPMismatch", func(t *testing.T) { _, err := body.KUP(); assert.Error(t, err) })
	t.Run("P10CRMismatch", func(t *testing.T) { _, err := body.P10CR(); assert.Error(t, err) })
	t.Run("CPMismatch", func(t *testing.T) { _, err := body.CP(); assert.Error(t, err) })
	t.Run("IPMismatch", func(t *testing.T) { _, err := body.IP(); assert.Error(t, err) })
	t.Run("CertConfMismatch", func(t *testing.T) { _, err := body.CertConf(); assert.Error(t, err) })
	t.Run("PollReqMismatch", func(t *testing.T) { _, err := body.PollReq(); assert.Error(t, err) })
	t.Run("PollRepMismatch", func(t *testing.T) { _, err := body.PollRep(); assert.Error(t, err) })
	t.Run("ErrorMismatch", func(t *testing.T) { _, err := body.Error(); assert.Error(t, err) })
}

func TestPKIBodyUnmarshalBodyContentErrors(t *testing.T) {
	t.Run("InvalidInnerTag", func(t *testing.T) {
		der := []byte{0x80, 0x01, 0x01}
		body := &PKIBody{Type: BodyTypeIR, Raw: der}
		_, err := body.IR()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid body content")
	})
	t.Run("ShortData", func(t *testing.T) {
		body := &PKIBody{Type: BodyTypeIR, Raw: []byte{0xa0}}
		_, err := body.IR()
		assert.Error(t, err)
	})
}

func TestPKIBodyUnmarshalErrors(t *testing.T) {
	t.Run("InvalidTag", func(t *testing.T) {
		body := &PKIBody{}
		s := cryptobyte.String([]byte{0x30, 0x00})
		err := body.unmarshal(&s)
		assert.Error(t, err)
	})
	t.Run("ShortData", func(t *testing.T) {
		body := &PKIBody{}
		s := cryptobyte.String([]byte{0x80})
		err := body.unmarshal(&s)
		assert.Error(t, err)
	})
}
