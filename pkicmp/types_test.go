package pkicmp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// RFC 9810 §5.1.1 (AlgorithmIdentifier ASN.1 tests)
func TestAlgorithmIdentifierASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		alg := AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
			Parameters: []byte{0x05, 0x00},                                 // NULL
		}

		var b cryptobyte.Builder
		alg.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled AlgorithmIdentifier
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		assert.True(t, alg.Algorithm.Equal(unmarshaled.Algorithm))
		assert.Equal(t, alg.Parameters, unmarshaled.Parameters)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00})
		var unmarshaled AlgorithmIdentifier
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}

// RFC 9810 §5.1.1 (InfoTypeAndValue ASN.1 tests)
func TestInfoTypeAndValueASN1(t *testing.T) {
	itv := InfoTypeAndValue{
		InfoType:  asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 1}, // id-it-caProtConn
		InfoValue: []byte{0x04, 0x03, 0x01, 0x02, 0x03},             // OctetString
	}

	var b cryptobyte.Builder
	itv.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
	marshaled, err := b.Bytes()
	require.NoError(t, err)

	var unmarshaled InfoTypeAndValue
	s := cryptobyte.String(marshaled)
	err = unmarshaled.unmarshal(&s)
	require.NoError(t, err)

	assert.True(t, itv.InfoType.Equal(unmarshaled.InfoType))
	assert.Equal(t, itv.InfoValue, unmarshaled.InfoValue)
}

// RFC 9810 §5.1.1 (PKIFreeText ASN.1 tests)
func TestPKIFreeTextASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		ft := PKIFreeText{"hello", "world"}

		var b cryptobyte.Builder
		ft.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled PKIFreeText
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		assert.Equal(t, ft, unmarshaled)
	})

	t.Run("Empty", func(t *testing.T) {
		var b cryptobyte.Builder
		var ft PKIFreeText
		ft.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)
		assert.Empty(t, marshaled)
	})
}

// RFC 9810 §5.1.1 (GeneralName ASN.1 tests)
func TestGeneralNameASN1(t *testing.T) {
	t.Run("DirectoryName", func(t *testing.T) {
		name := pkix.RDNSequence{
			{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test Name"}},
		}
		gn := NewDirectoryName(name)

		var b cryptobyte.Builder
		gn.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled GeneralName
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		// Compare RDN sequences by re-marshaling or deep comparison
		assert.Equal(t, len(name), len(unmarshaled.DirectoryName))
	})

	t.Run("RFC822Name", func(t *testing.T) {
		// rfc822Name [1] IMPLICIT IA5String
		data := []byte{0x81, 0x03, 'f', 'o', 'o'}
		s := cryptobyte.String(data)
		var unmarshaled GeneralName
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.Equal(t, "foo", unmarshaled.RFC822Name)

		// Round-trip via marshal.
		gn := NewRFC822Name("foo")
		var b cryptobyte.Builder
		gn.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)
		assert.Equal(t, data, marshaled)
	})

	t.Run("UnsupportedTag", func(t *testing.T) {
		// dNSName [2] IMPLICIT IA5String — not parsed into a dedicated field,
		// but accepted and preserved in Raw for round-tripping.
		data := []byte{0x82, 0x07, 'f', 'o', 'o', '.', 'c', 'o', 'm'}
		s := cryptobyte.String(data)
		var unmarshaled GeneralName
		err := unmarshaled.unmarshal(&s)
		assert.NoError(t, err)
		assert.Equal(t, data, unmarshaled.Raw)
		assert.Empty(t, unmarshaled.RFC822Name)
		assert.Nil(t, unmarshaled.DirectoryName)
	})
}

// RFC 9810 §5.1 (CMPCertificate ASN.1 tests)
func TestCMPCertificateASN1(t *testing.T) {
	// Mock certificate (just a valid sequence)
	cert := CMPCertificate{
		Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01},
	}

	var b cryptobyte.Builder
	cert.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
	marshaled, err := b.Bytes()
	require.NoError(t, err)

	var unmarshaled CMPCertificate
	s := cryptobyte.String(marshaled)
	err = unmarshaled.unmarshal(&s)
	require.NoError(t, err)

	assert.Equal(t, cert.Raw, unmarshaled.Raw)
}

func TestEncryptedKeyASN1(t *testing.T) {
	t.Run("EncryptedValue", func(t *testing.T) {
		ev := &EncryptedValue{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
		var b cryptobyte.Builder
		ev.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled EncryptedValue
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.Equal(t, ev.Raw, unmarshaled.Raw)

		ek := EncryptedKey{
			EncryptedValue: ev,
		}

		var b2 cryptobyte.Builder
		ek.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b2)
		marshaled, _ = b2.Bytes()

		var unmarshaledKey EncryptedKey
		s = cryptobyte.String(marshaled)
		err = unmarshaledKey.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaledKey.EncryptedValue)
	})

	t.Run("EnvelopedData", func(t *testing.T) {
		ek := EncryptedKey{
			EnvelopedData: &EnvelopedData{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x02}},
		}

		var b cryptobyte.Builder
		ek.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, _ := b.Bytes()

		var unmarshaled EncryptedKey
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaled.EnvelopedData)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x80}) // Tag [0] but no content
		var unmarshaled EncryptedKey
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}
