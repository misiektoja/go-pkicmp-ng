package pkicmp

import (

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CertRepMessage per RFC 9810 §5.3.4.
//
//	CertRepMessage ::= SEQUENCE {
//	    caPubs          [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
//	                        OPTIONAL,
//	    response            SEQUENCE OF CertResponse
//	}
type CertRepMessage struct {
	// CAPubs carries optional CA certificates for path building.
	CAPubs []CMPCertificate
	// Response contains one result entry per CertRequest.
	Response []CertResponse
}

func (m *CertRepMessage) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if len(m.CAPubs) > 0 {
			// caPubs [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, cert := range m.CAPubs {
						cert.marshal(mctx, b)
					}
				})
			})
		}
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, resp := range m.Response {
				resp.marshal(mctx, b)
			}
		})
	})
}

func (m *CertRepMessage) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertRepMessage sequence"}
	}

	if seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(1).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid caPubs tag"}
		}
		var certsSeq cryptobyte.String
		if !sub.ReadASN1(&certsSeq, cbasn1.SEQUENCE) {
			return &ParseError{Detail: "invalid caPubs sequence"}
		}
		for !certsSeq.Empty() {
			var cert CMPCertificate
			if err := cert.unmarshal(&certsSeq); err != nil {
				return err
			}
			m.CAPubs = append(m.CAPubs, cert)
		}
	}

	var respSeq cryptobyte.String
	if !seq.ReadASN1(&respSeq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid response sequence"}
	}
	for !respSeq.Empty() {
		var resp CertResponse
		if err := resp.unmarshal(&respSeq); err != nil {
			return err
		}
		m.Response = append(m.Response, resp)
	}
	return nil
}

// CertResponse per RFC 9810 §5.3.4.
//
//	CertResponse ::= SEQUENCE {
//	    certReqId           INTEGER,
//	    status              PKIStatusInfo,
//	    certifiedKeyPair    CertifiedKeyPair     OPTIONAL,
//	    rspInfo             OCTET STRING         OPTIONAL
//	}
type CertResponse struct {
	// CertReqID identifies which request this response belongs to.
	CertReqID int64
	// Status reports accepted, waiting, or rejection for this request.
	Status PKIStatusInfo
	// CertifiedKeyPair carries the issued certificate or encrypted cert, if any.
	CertifiedKeyPair *CertifiedKeyPair
	// RspInfo is opaque server-specific response data.
	RspInfo []byte
}

func (r *CertResponse) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(r.CertReqID)
		r.Status.marshal(mctx, b)
		if r.CertifiedKeyPair != nil {
			r.CertifiedKeyPair.marshal(mctx, b)
		}
		if len(r.RspInfo) > 0 {
			b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
				b.AddBytes(r.RspInfo)
			})
		}
	})
}

func (r *CertResponse) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertResponse sequence"}
	}
	if !seq.ReadASN1Integer(&r.CertReqID) {
		return &ParseError{Detail: "invalid certReqId"}
	}
	if err := r.Status.unmarshal(&seq); err != nil {
		return err
	}

	if !seq.Empty() && (seq.PeekASN1Tag(cbasn1.SEQUENCE) || cbasn1.Tag(seq[0]).ContextSpecific() == cbasn1.Tag(seq[0])) {
		r.CertifiedKeyPair = &CertifiedKeyPair{}
		if err := r.CertifiedKeyPair.unmarshal(&seq); err != nil {
			return err
		}
	}

	if !seq.Empty() && seq.PeekASN1Tag(cbasn1.OCTET_STRING) {
		if !seq.ReadASN1Bytes(&r.RspInfo, cbasn1.OCTET_STRING) {
			return &ParseError{Detail: "invalid rspInfo"}
		}
	}

	return nil
}

// CertifiedKeyPair per RFC 9810 §5.3.4.
//
//	CertifiedKeyPair ::= SEQUENCE {
//	    certOrEncCert       CertOrEncCert,
//	    privateKey      [0] encryptedKey         OPTIONAL,
//	    publicationInfo [1] PKIPublicationInfo   OPTIONAL
//	}
type CertifiedKeyPair struct {
	// CertOrEncCert carries either the issued certificate or encrypted certificate.
	CertOrEncCert CertOrEncCert
	// PrivateKey carries an optional encrypted private key for the subject.
	PrivateKey *encryptedKey
}

func (ckp *CertifiedKeyPair) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		ckp.CertOrEncCert.marshal(mctx, b)
		if ckp.PrivateKey != nil {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				ckp.PrivateKey.marshal(mctx, b)
			})
		}
	})
}

func (ckp *CertifiedKeyPair) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertifiedKeyPair sequence"}
	}
	if err := ckp.CertOrEncCert.unmarshal(&seq); err != nil {
		return err
	}
	if !seq.Empty() && seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid privateKey tag"}
		}
		ckp.PrivateKey = &encryptedKey{}
		if err := ckp.PrivateKey.unmarshal(&sub); err != nil {
			return err
		}
	}
	return nil
}

// CertOrEncCert per RFC 9810 §5.3.4.
//
//	CertOrEncCert ::= CHOICE {
//	    certificate     [0] CMPCertificate,
//	    encryptedCert   [1] encryptedKey
//	}
type CertOrEncCert struct {
	// Certificate is the plaintext issued certificate.
	Certificate *CMPCertificate
	// EncryptedCert is an encrypted-certificate alternative.
	EncryptedCert *encryptedKey
}

func (c *CertOrEncCert) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	if c.Certificate != nil {
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			c.Certificate.marshal(mctx, b)
		})
	} else if c.EncryptedCert != nil {
		b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			c.EncryptedCert.marshal(mctx, b)
		})
	}
}

func (c *CertOrEncCert) unmarshal(s *cryptobyte.String) error {
	if s.Empty() {
		return &ParseError{Detail: "missing CertOrEncCert"}
	}
	tag := cbasn1.Tag((*s)[0])
	if tag == cbasn1.Tag(0).ContextSpecific().Constructed() {
		var sub cryptobyte.String
		if !s.ReadASN1(&sub, tag) {
			return &ParseError{Detail: "invalid certificate tag"}
		}
		c.Certificate = &CMPCertificate{}
		return c.Certificate.unmarshal(&sub)
	} else if tag == cbasn1.Tag(1).ContextSpecific().Constructed() {
		var sub cryptobyte.String
		if !s.ReadASN1(&sub, tag) {
			return &ParseError{Detail: "invalid encryptedCert tag"}
		}
		c.EncryptedCert = &encryptedKey{}
		return c.EncryptedCert.unmarshal(&sub)
	}
	return &ParseError{Detail: "unsupported CertOrEncCert variant"}
}

// CertConfirmContent per RFC 9810 §5.3.18.
//
//	CertConfirmContent ::= SEQUENCE OF CertStatus
type CertConfirmContent []CertStatus

func (c *CertConfirmContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, status := range *c {
			status.marshal(mctx, b)
		}
	})
}

func (c *CertConfirmContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertConfirmContent sequence"}
	}
	for !seq.Empty() {
		var status CertStatus
		if err := status.unmarshal(&seq); err != nil {
			return err
		}
		*c = append(*c, status)
	}
	return nil
}

// CertStatus per RFC 9810 §5.3.18.
//
//	CertStatus ::= SEQUENCE {
//	    certHash    OCTET STRING,
//	    certReqId   INTEGER,
//	    statusInfo  PKIStatusInfo OPTIONAL,
//	    hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}}
//	                OPTIONAL
//	}
type CertStatus struct {
	// CertHash is the digest of the certificate being acknowledged.
	CertHash []byte
	// CertReqID identifies the related certificate request.
	CertReqID int64
	// StatusInfo optionally returns explicit confirmation status.
	StatusInfo *PKIStatusInfo
	HashAlg    *AlgorithmIdentifier // CMPv3
}

func (s *CertStatus) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddBytes(s.CertHash)
		})
		b.AddASN1Int64(s.CertReqID)
		if s.StatusInfo != nil {
			s.StatusInfo.marshal(mctx, b)
		}
		if s.HashAlg != nil {
			mctx.MinRequiredPVNO = PVNO3
			// hashAlg [0] AlgorithmIdentifier OPTIONAL (IMPLICIT)
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				s.HashAlg.marshalInner(mctx, b)
			})
		}
	})
}

func (s *CertStatus) unmarshal(inner *cryptobyte.String) error {
	var seq cryptobyte.String
	if !inner.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid CertStatus sequence"}
	}
	if !seq.ReadASN1Bytes(&s.CertHash, cbasn1.OCTET_STRING) {
		return &ParseError{Detail: "invalid certHash"}
	}
	if !seq.ReadASN1Integer(&s.CertReqID) {
		return &ParseError{Detail: "invalid certReqId"}
	}
	if !seq.Empty() && seq.PeekASN1Tag(cbasn1.SEQUENCE) {
		s.StatusInfo = &PKIStatusInfo{}
		if err := s.StatusInfo.unmarshal(&seq); err != nil {
			return err
		}
	}
	if !seq.Empty() && seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid hashAlg tag"}
		}
		s.HashAlg = &AlgorithmIdentifier{}
		if err := s.HashAlg.unmarshalInner(&sub); err != nil {
			return err
		}
	}
	return nil
}

// PKIConfirmContent per RFC 9810 §5.3.19.
//
//	PKIConfirmContent ::= NULL
type PKIConfirmContent struct{}

func (c *PKIConfirmContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	// PKIConfirmContent ::= NULL — encoded as ASN.1 NULL inside the constructed body tag.
	b.AddASN1(cbasn1.NULL, func(b *cryptobyte.Builder) {})
}

func (c *PKIConfirmContent) unmarshal(s *cryptobyte.String) error {
	// Accept both empty content and explicit NULL encoding for interoperability.
	// Strict DER requires NULL (05 00), but some implementations send empty content
	// when the outer constructed tag has zero-length body.
	if s.Empty() {
		return nil
	}
	var dummy cryptobyte.String
	if !s.ReadASN1(&dummy, cbasn1.NULL) {
		return &ParseError{Detail: "invalid PKIConfirmContent (expected NULL)"}
	}
	return nil
}

// PollReqContent per RFC 9810 §5.3.22.
//
//	PollReqContent ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
//	    certReqId       INTEGER
//	}
type PollReqContent []int64

func (c *PollReqContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, id := range *c {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(id)
			})
		}
	})
}

func (c *PollReqContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid PollReqContent sequence"}
	}
	for !seq.Empty() {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.SEQUENCE) {
			return &ParseError{Detail: "invalid pollReq element"}
		}
		var id int64
		if !sub.ReadASN1Integer(&id) {
			return &ParseError{Detail: "invalid certReqId in pollReq"}
		}
		*c = append(*c, id)
	}
	return nil
}

// PollRepContent per RFC 9810 §5.3.22.
//
//	PollRepContent ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
//	    certReqId       INTEGER,
//	    checkAfter      INTEGER,  -- time in seconds
//	    reason          PKIFreeText OPTIONAL
//	}
type PollRepContent []PollRepItem

type PollRepItem struct {
	// CertReqID identifies the request that is still pending.
	CertReqID int64
	// CheckAfter is the server-recommended wait time in seconds.
	CheckAfter int64
	// Reason provides optional human-readable polling context.
	Reason PKIFreeText
}

func (c *PollRepContent) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, item := range *c {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(item.CertReqID)
				b.AddASN1Int64(item.CheckAfter)
				if len(item.Reason) > 0 {
					item.Reason.marshal(mctx, b)
				}
			})
		}
	})
}

func (c *PollRepContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid PollRepContent sequence"}
	}
	for !seq.Empty() {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.SEQUENCE) {
			return &ParseError{Detail: "invalid pollRep element"}
		}
		var item PollRepItem
		if !sub.ReadASN1Integer(&item.CertReqID) {
			return &ParseError{Detail: "invalid certReqId in pollRep"}
		}
		if !sub.ReadASN1Integer(&item.CheckAfter) {
			return &ParseError{Detail: "invalid checkAfter in pollRep"}
		}
		if !sub.Empty() {
			if err := item.Reason.unmarshal(&sub); err != nil {
				return err
			}
		}
		*c = append(*c, item)
	}
	return nil
}
