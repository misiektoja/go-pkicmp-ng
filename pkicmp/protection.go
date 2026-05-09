package pkicmp

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// DefaultPBMSaltLength is the default length of the salt for Password-Based MAC.
	DefaultPBMSaltLength = 16

	// DefaultPBMIterationCount is the default number of iterations for Password-Based MAC.
	// EJBCA allows max 10 000 iterations for PBM, see:
	// https://github.com/Keyfactor/ejbca-ce/blob/3eca262162abacada9c19aa535304a1f8677b756/modules/ejbca-common-web/src/org/ejbca/core/protocol/cmp/CmpPbeVerifyer.java#L56-L92
	DefaultPBMIterationCount = 10000

	// DefaultPBMOWF is the default one-way function (OWF) algorithm OID for Password-Based MAC.
	DefaultPBMOWF = OIDSHA256

	// DefaultPBMMAC is the default MAC algorithm OID for Password-Based MAC.
	DefaultPBMMAC = OIDHMACWithSHA256

	// DefaultPBMMinIterationCount and DefaultPBMMaxIterationCount bound PBM
	// iteration processing to reduce CPU DoS risk from untrusted inputs.
	DefaultPBMMinIterationCount = 1
	DefaultPBMMaxIterationCount = 100000
)

// Verifier is the base interface for message protection verification.
type Verifier interface {
	Verify(data, protection []byte) error
}

// SignatureVerifier verifies X.509 signatures over ProtectedPart.
type SignatureVerifier interface {
	Verifier
	SetTrustedCerts(certs []CMPCertificate)
	SetTrustPool(roots *x509.CertPool)
}

// MACVerifier verifies PBM and KEM-MAC outputs.
type MACVerifier interface {
	Verifier
	SetSharedSecret(secret []byte)
}

// Protector is the base interface for message protection.
type Protector interface {
	Protect(data []byte) ([]byte, error)
	Algorithm() *AlgorithmIdentifier
}

// SignatureProtector signs ProtectedPart.
type SignatureProtector interface {
	Protector
}

// MACProtector calculates MAC over ProtectedPart.
type MACProtector interface {
	Protector
	SharedSecret() []byte
}

// Verify verifies the message protection using the provided verifier.
func (m *PKIMessage) Verify(v Verifier) error {
	if m.Body == nil {
		return errors.New("pkicmp: missing message body")
	}
	if len(m.Protection) == 0 {
		return errors.New("pkicmp: message is not protected")
	}
	data, err := m.protectedPart()
	if err != nil {
		return err
	}
	return v.Verify(data, m.Protection)
}

// Protect applies protection to the message using the provided protector.
func (m *PKIMessage) Protect(p Protector) error {
	if m.Body == nil {
		return errors.New("pkicmp: missing message body")
	}
	m.Header.ProtectionAlg = p.Algorithm()

	// 1. Marshal body first to discover required PVNO
	mctx := &MarshalContext{MinRequiredPVNO: PVNO2}
	if m.Header.PVNO > PVNO2 {
		mctx.MinRequiredPVNO = m.Header.PVNO
	}

	var bodyBuilder cryptobyte.Builder
	m.Body.marshal(mctx, &bodyBuilder)
	var err error
	m.RawBody, err = bodyBuilder.Bytes()
	if err != nil {
		return err
	}

	// 2. Update Header PVNO and marshal header
	m.Header.PVNO = mctx.MinRequiredPVNO

	var headerBuilder cryptobyte.Builder
	m.Header.marshal(mctx, &headerBuilder)
	m.RawHeader, err = headerBuilder.Bytes()
	if err != nil {
		return err
	}

	// 3. Apply protection
	data, err := m.protectedPart()
	if err != nil {
		return err
	}
	protection, err := p.Protect(data)
	if err != nil {
		return err
	}
	m.Protection = protection
	return nil
}

func (m *PKIMessage) protectedPart() ([]byte, error) {
	if m.Body == nil {
		return nil, errors.New("pkicmp: missing message body")
	}
	if len(m.RawHeader) == 0 || len(m.RawBody) == 0 {
		return nil, errors.New("pkicmp: raw header or body missing")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(m.RawHeader)
		b.AddBytes(m.RawBody)
	})
	return b.Bytes()
}

// ProtectionVerifier returns a Verifier for the given algorithm.
func ProtectionVerifier(alg AlgorithmIdentifier) (Verifier, error) {
	// Router that dispatches based on OID
	if alg.Algorithm.Equal(OIDPasswordBasedMac) {
		return &pbmVerifier{alg: alg}, nil
	}

	if _, err := sigAlgFromOID(alg.Algorithm); err == nil {
		return &signatureVerifier{alg: alg}, nil
	}

	return nil, fmt.Errorf("pkicmp: unsupported protection algorithm: %v", alg.Algorithm)
}

// PBMParameter per RFC 9810 §5.1.3.1.
//
//	PBMParameter ::= SEQUENCE {
//	   salt                OCTET STRING,
//	   owf                 AlgorithmIdentifier,
//	   iterationCount      INTEGER,
//	   mac                 AlgorithmIdentifier
//	}
type PBMParameter struct {
	// Salt randomizes password-based key derivation.
	Salt []byte
	// OWF is the hash function used during key derivation.
	OWF AlgorithmIdentifier
	// IterationCount controls PBM key-stretching cost.
	IterationCount int
	// MAC is the final integrity algorithm applied to the protected part.
	MAC AlgorithmIdentifier
}

func (p *PBMParameter) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return errors.New("pkicmp: invalid PBMParameter sequence")
	}
	if !seq.ReadASN1Bytes(&p.Salt, cbasn1.OCTET_STRING) {
		return errors.New("pkicmp: invalid salt")
	}
	if err := p.OWF.unmarshal(&seq); err != nil {
		return err
	}
	var count int64
	if !seq.ReadASN1Integer(&count) {
		return errors.New("pkicmp: invalid iterationCount")
	}
	p.IterationCount = int(count)
	if err := validatePBMIterationCount(p.IterationCount); err != nil {
		return err
	}
	return p.MAC.unmarshal(&seq)
}

func (p *PBMParameter) marshal(mctx *MarshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(p.Salt)
		p.OWF.marshal(mctx, b)
		b.AddASN1Int64(int64(p.IterationCount))
		p.MAC.marshal(mctx, b)
	})
}

// Basic PBM Verifier implementation
type pbmVerifier struct {
	alg    AlgorithmIdentifier
	secret []byte
}

func (v *pbmVerifier) SetSharedSecret(secret []byte) {
	v.secret = secret
}

func (v *pbmVerifier) Verify(data, protection []byte) error {
	if len(v.secret) == 0 {
		return errors.New("pkicmp: shared secret not set")
	}

	var p PBMParameter
	params := cryptobyte.String(v.alg.Parameters)
	if err := p.unmarshal(&params); err != nil {
		return err
	}

	return verifyPBM(data, protection, v.secret, p)
}

func verifyPBM(data, protection, secret []byte, p PBMParameter) error {
	if err := validatePBMIterationCount(p.IterationCount); err != nil {
		return err
	}

	hash, err := hashFromOID(p.OWF.Algorithm)
	if err != nil {
		return err
	}
	if !hash.Available() {
		return fmt.Errorf("pkicmp: hash algorithm %v not available", p.OWF.Algorithm)
	}

	macHash, err := hmacHashFromOID(p.MAC.Algorithm)
	if err != nil {
		return err
	}
	if !macHash.Available() {
		return fmt.Errorf("pkicmp: MAC hash algorithm %v not available", p.MAC.Algorithm)
	}

	k := derivePBMKey(secret, p.Salt, p.IterationCount, hash)

	mac := hmac.New(macHash.New, k)
	mac.Write(data)
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expected, protection) != 1 {
		return errors.New("pkicmp: PBM verification failed")
	}

	return nil
}

func validatePBMIterationCount(iterationCount int) error {
	if iterationCount < DefaultPBMMinIterationCount {
		return fmt.Errorf("pkicmp: PBM iterationCount too small: %d", iterationCount)
	}
	if iterationCount > DefaultPBMMaxIterationCount {
		return fmt.Errorf("pkicmp: PBM iterationCount too large: %d", iterationCount)
	}
	return nil
}

func derivePBMKey(secret, salt []byte, iterationCount int, hash crypto.Hash) []byte {
	h := hash.New()
	h.Write(secret)
	h.Write(salt)
	k := h.Sum(nil)

	for i := 1; i < iterationCount; i++ {
		h.Reset()
		h.Write(k)
		k = h.Sum(nil)
	}
	return k
}

type pbmProtector struct {
	secret []byte
	alg    AlgorithmIdentifier
}

func (p *pbmProtector) Protect(data []byte) ([]byte, error) {
	var params PBMParameter
	s := cryptobyte.String(p.alg.Parameters)
	if err := params.unmarshal(&s); err != nil {
		return nil, err
	}

	hash, err := hashFromOID(params.OWF.Algorithm)
	if err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, fmt.Errorf("pkicmp: hash algorithm %v not available", params.OWF.Algorithm)
	}

	macHash, err := hmacHashFromOID(params.MAC.Algorithm)
	if err != nil {
		return nil, err
	}

	k := derivePBMKey(p.secret, params.Salt, params.IterationCount, hash)

	mac := hmac.New(macHash.New, k)
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (p *pbmProtector) Algorithm() *AlgorithmIdentifier {
	return &p.alg
}

func (p *pbmProtector) SharedSecret() []byte {
	return p.secret
}

// NewPBMProtector creates a new Protector using Password-Based MAC.
func NewPBMProtector(secret, salt []byte, iterationCount int, owfOID, macOID asn1.ObjectIdentifier) (Protector, error) {
	if err := validatePBMIterationCount(iterationCount); err != nil {
		return nil, err
	}
	// RFC 9481 §6.1: Salt should provide sufficient entropy for key derivation.
	if len(salt) < 8 {
		return nil, fmt.Errorf("pkicmp: PBM salt too short: %d bytes (minimum 8)", len(salt))
	}
	// Validate algorithm OIDs early to fail fast.
	if _, err := hashFromOID(owfOID); err != nil {
		return nil, err
	}
	if _, err := hmacHashFromOID(macOID); err != nil {
		return nil, err
	}

	p := PBMParameter{
		Salt:           salt,
		IterationCount: iterationCount,
		OWF:            AlgorithmIdentifier{Algorithm: owfOID},
		MAC:            AlgorithmIdentifier{Algorithm: macOID},
	}
	var b cryptobyte.Builder
	p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
	params, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	return &pbmProtector{
		secret: secret,
		alg: AlgorithmIdentifier{
			Algorithm:  OIDPasswordBasedMac,
			Parameters: params,
		},
	}, nil
}

// NewDefaultPBMProtector creates a new Protector using Password-Based MAC with default parameters.
func NewDefaultPBMProtector(secret []byte) (Protector, error) {
	salt := make([]byte, DefaultPBMSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return NewPBMProtector(secret, salt, DefaultPBMIterationCount, DefaultPBMOWF, DefaultPBMMAC)
}

type signatureVerifier struct {
	alg               AlgorithmIdentifier
	certs             []CMPCertificate
	roots             *x509.CertPool
	expectedSenderKID []byte
}

func (v *signatureVerifier) SetTrustedCerts(certs []CMPCertificate) {
	v.certs = certs
}

func (v *signatureVerifier) SetTrustPool(roots *x509.CertPool) {
	v.roots = roots
}

func (v *signatureVerifier) SetExpectedSenderKID(senderKID []byte) {
	v.expectedSenderKID = senderKID
}

func (v *signatureVerifier) Verify(data, protection []byte) error {
	sigAlg, err := sigAlgFromOID(v.alg.Algorithm)
	if err != nil {
		return err
	}

	// RFC 9810 §5.1.3.3: Verify the signature using certificates from extraCerts.
	// If a trust pool is configured, filter to trusted certificates first.
	// Build an intermediates pool from extraCerts for chain verification.
	intermediates := x509.NewCertPool()
	for _, cert := range v.certs {
		x509Cert, err := cert.Parse()
		if err != nil {
			continue
		}
		intermediates.AddCert(x509Cert)
	}

	for _, cert := range v.certs {
		x509Cert, err := cert.Parse()
		if err != nil {
			continue
		}
		// RFC 9810 §5.1.1: senderKID identifies the key used for protection.
		if len(v.expectedSenderKID) > 0 {
			if len(x509Cert.SubjectKeyId) == 0 || !bytes.Equal(x509Cert.SubjectKeyId, v.expectedSenderKID) {
				continue
			}
		}
		// If we have roots, verify trust before checking the signature.
		if v.roots != nil {
			opts := x509.VerifyOptions{
				Roots:         v.roots,
				Intermediates: intermediates,
			}
			if _, err := x509Cert.Verify(opts); err != nil {
				continue
			}
		}
		if err := x509Cert.CheckSignature(sigAlg, data, protection); err == nil {
			return nil
		}
	}

	return errors.New("pkicmp: signature verification failed")
}

type signatureProtector struct {
	signer crypto.Signer
	cert   *x509.Certificate
	alg    AlgorithmIdentifier
}

func (p *signatureProtector) Protect(data []byte) ([]byte, error) {
	sigAlg, err := sigAlgFromOID(p.alg.Algorithm)
	if err != nil {
		return nil, err
	}

	var opts crypto.SignerOpts
	var digest []byte

	hash := hashFromSigAlg(sigAlg)
	if hash != 0 {
		h := hash.New()
		h.Write(data)
		digest = h.Sum(nil)
		opts = hash
	} else {
		// e.g. Ed25519
		digest = data
		opts = crypto.Hash(0)
	}

	return p.signer.Sign(nil, digest, opts)
}

func (p *signatureProtector) Algorithm() *AlgorithmIdentifier {
	return &p.alg
}

// NewSignatureProtector creates a new Protector using X.509 signatures.
func NewSignatureProtector(signer crypto.Signer, cert *x509.Certificate) (Protector, error) {
	sigAlgOID, _, err := signatureAlgorithmFromKey(signer)
	if err != nil {
		return nil, err
	}
	return &signatureProtector{
		signer: signer,
		cert:   cert,
		alg: AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
	}, nil
}
