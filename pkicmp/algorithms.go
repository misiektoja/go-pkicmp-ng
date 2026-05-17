package pkicmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var (
	// Message Digest Algorithms (RFC 9481 §2.1).
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	OIDSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signature Algorithms (RFC 9481 §3).
	OIDSHA256WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDECDSAWithSHA256         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDEd25519                 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// MAC Algorithms (RFC 9481 §6.1, RFC 9810 §5.1.3.4).
	OIDPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	OIDPBMMac_HMACSHA1  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	OIDKemBasedMac      = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 16}
	OIDPBMAC1           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	// PBKDF2 (RFC 8018 §A.2).
	OIDPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	// HMAC Algorithms (RFC 9481 §6.2.1).
	OIDHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7} // Deprecated: SHOULD NOT be used (RFC 9481 §7.1)
	OIDHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	OIDHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	OIDHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	OIDHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	// CMP InfoType OIDs (RFC 9810 §5.1.1).
	OIDConfirmWaitTime = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 14}
	OIDImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}
	OIDCertProfile     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 21}
)

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDSHA1): // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1, nil
	case oid.Equal(OIDSHA224):
		return crypto.SHA224, nil
	case oid.Equal(OIDSHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDSHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDSHA512):
		return crypto.SHA512, nil
	}
	return 0, &ParseError{Detail: fmt.Sprintf("unsupported hash algorithm: %v", oid)}
}

func hmacHashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDHMACWithSHA1) || oid.Equal(OIDPBMMac_HMACSHA1): // Deprecated (RFC 9481 §7.1)
		return crypto.SHA1, nil
	case oid.Equal(OIDHMACWithSHA224):
		return crypto.SHA224, nil
	case oid.Equal(OIDHMACWithSHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDHMACWithSHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDHMACWithSHA512):
		return crypto.SHA512, nil
	}
	return 0, &ParseError{Detail: fmt.Sprintf("unsupported HMAC algorithm: %v", oid)}
}

// SigAlgFromOID maps an OID to x509.SignatureAlgorithm.
func SigAlgFromOID(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case oid.Equal(OIDSHA256WithRSAEncryption):
		return x509.SHA256WithRSA, nil
	case oid.Equal(OIDSHA384WithRSAEncryption):
		return x509.SHA384WithRSA, nil
	case oid.Equal(OIDSHA512WithRSAEncryption):
		return x509.SHA512WithRSA, nil
	case oid.Equal(OIDECDSAWithSHA256):
		return x509.ECDSAWithSHA256, nil
	case oid.Equal(OIDECDSAWithSHA384):
		return x509.ECDSAWithSHA384, nil
	case oid.Equal(OIDECDSAWithSHA512):
		return x509.ECDSAWithSHA512, nil
	case oid.Equal(OIDEd25519):
		return x509.PureEd25519, nil
	}
	return x509.UnknownSignatureAlgorithm, &ParseError{Detail: fmt.Sprintf("unsupported signature algorithm: %v", oid)}
}

// HashFromSigAlg maps x509.SignatureAlgorithm to crypto.Hash.
func HashFromSigAlg(sigAlg x509.SignatureAlgorithm) crypto.Hash {
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
			return OIDSHA512WithRSAEncryption, crypto.SHA512, nil
		case pub.N.BitLen() >= 3072:
			return OIDSHA384WithRSAEncryption, crypto.SHA384, nil
		default:
			return OIDSHA256WithRSAEncryption, crypto.SHA256, nil
		}
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			return OIDECDSAWithSHA256, crypto.SHA256, nil
		case 384:
			return OIDECDSAWithSHA384, crypto.SHA384, nil
		case 521:
			return OIDECDSAWithSHA512, crypto.SHA512, nil
		default:
			return nil, 0, &ParseError{Detail: fmt.Sprintf("unsupported ECDSA curve size: %d", pub.Curve.Params().BitSize)}
		}
	case ed25519.PublicKey:
		return OIDEd25519, crypto.Hash(0), nil
	default:
		return nil, 0, &ParseError{Detail: fmt.Sprintf("unsupported public key type: %T", pub)}
	}
}
