package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

var (
	// Message Digest Algorithms (RFC 9481 §2.1).
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signature Algorithms (RFC 9481 §3).
	oidSHA256WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519                 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// MAC Algorithms (RFC 9481 §6.1, RFC 9810 §5.1.3.4).
	oidPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	oidPBMMac_HMACSHA1  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	// oidKemBasedMac      = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 16} // Unused but reserved for KEM-based MAC (RFC 9810 §5.1.3.4)
	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	// PBKDF2 (RFC 8018 §A.2).
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	// HMAC Algorithms (RFC 9481 §6.2.1).
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	// CMP InfoType OIDs (RFC 9810 §5.1.1).
	oidConfirmWaitTime = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 14}
	oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}
	oidCertProfile     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 21}
)

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA1): // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1, nil
	case oid.Equal(oidSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, &ParseError{Detail: fmt.Sprintf("unsupported hash algorithm: %v", oid)}
}

func hmacHashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidHMACWithSHA1) || oid.Equal(oidPBMMac_HMACSHA1): // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1, nil
	case oid.Equal(oidHMACWithSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidHMACWithSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidHMACWithSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidHMACWithSHA512):
		return crypto.SHA512, nil
	}
	return 0, &ParseError{Detail: fmt.Sprintf("unsupported HMAC algorithm: %v", oid)}
}

// sigAlgFromOID maps an OID to x509.SignatureAlgorithm.
func sigAlgFromOID(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case oid.Equal(oidSHA256WithRSAEncryption):
		return x509.SHA256WithRSA, nil
	case oid.Equal(oidSHA384WithRSAEncryption):
		return x509.SHA384WithRSA, nil
	case oid.Equal(oidSHA512WithRSAEncryption):
		return x509.SHA512WithRSA, nil
	case oid.Equal(oidECDSAWithSHA256):
		return x509.ECDSAWithSHA256, nil
	case oid.Equal(oidECDSAWithSHA384):
		return x509.ECDSAWithSHA384, nil
	case oid.Equal(oidECDSAWithSHA512):
		return x509.ECDSAWithSHA512, nil
	case oid.Equal(oidEd25519):
		return x509.PureEd25519, nil
	}
	return x509.UnknownSignatureAlgorithm, &ParseError{Detail: fmt.Sprintf("unsupported signature algorithm: %v", oid)}
}

// hashFromSigAlg maps x509.SignatureAlgorithm to crypto.Hash.
func hashFromSigAlg(sigAlg x509.SignatureAlgorithm) crypto.Hash {
	switch sigAlg {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1: // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512
	case x509.PureEd25519:
		// RFC 9481 §3.3: EdDSA uses SHA-512 for certHash.
		return crypto.SHA512
	}
	return 0
}

func signatureAlgorithmFromKey(key crypto.Signer) (asn1.ObjectIdentifier, crypto.Hash, error) {
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		// Select hash strength based on key size (NIST SP 800-57 Part 1).
		switch {
		case pub.N.BitLen() >= 4096:
			return oidSHA512WithRSAEncryption, crypto.SHA512, nil
		case pub.N.BitLen() >= 3072:
			return oidSHA384WithRSAEncryption, crypto.SHA384, nil
		default:
			return oidSHA256WithRSAEncryption, crypto.SHA256, nil
		}
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			return oidECDSAWithSHA256, crypto.SHA256, nil
		case 384:
			return oidECDSAWithSHA384, crypto.SHA384, nil
		case 521:
			return oidECDSAWithSHA512, crypto.SHA512, nil
		default:
			return nil, 0, &ParseError{Detail: fmt.Sprintf("unsupported ECDSA curve size: %d", pub.Curve.Params().BitSize)}
		}
	case ed25519.PublicKey:
		return oidEd25519, crypto.Hash(0), nil
	default:
		return nil, 0, &ParseError{Detail: fmt.Sprintf("unsupported public key type: %T", pub)}
	}
}

// ImplicitConfirmInfoValue returns an InfoTypeAndValue for the implicitConfirm
// info type (RFC 9810 §5.1.1).
func ImplicitConfirmInfoValue() InfoTypeAndValue {
	return InfoTypeAndValue{
		InfoType: oidImplicitConfirm,
	}
}

// ConfirmWaitTimeInfoValue returns an InfoTypeAndValue for the confirmWaitTime
// info type (RFC 9810 §5.1.1). The duration is encoded as a 32-bit integer
// number of seconds (ASN.1 INTEGER).
func ConfirmWaitTimeInfoValue(d time.Duration) InfoTypeAndValue {
	secs := max(int(d.Seconds()), 0)
	val, _ := asn1.Marshal(secs)
	return InfoTypeAndValue{
		InfoType:  oidConfirmWaitTime,
		InfoValue: val,
	}
}
