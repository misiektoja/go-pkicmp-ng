package pkicmp

import (
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PKIBody per RFC 9810 §5.1.2.
//
// PKIBody ::= CHOICE {       -- message-specific body elements
//
//	    ir       [0]  CertReqMessages,        --Initialization Request
//	    ip       [1]  CertRepMessage,         --Initialization Response
//	    cr       [2]  CertReqMessages,        --Certification Request
//	    cp       [3]  CertRepMessage,         --Certification Response
//	    p10cr    [4]  CertificationRequest,   --imported from [RFC2986]
//	    popdecc  [5]  POPODecKeyChallContent, --pop Challenge
//	    popdecr  [6]  POPODecKeyRespContent,  --pop Response
//	    kur      [7]  CertReqMessages,        --Key Update Request
//	    kup      [8]  CertRepMessage,         --Key Update Response
//	    krr      [9]  CertReqMessages,        --Key Recovery Request
//	    krp      [10] KeyRecRepContent,       --Key Recovery Response
//	    rr       [11] RevReqContent,          --Revocation Request
//	    rp       [12] RevRepContent,          --Revocation Response
//	    ccr      [13] CertReqMessages,        --Cross-Cert. Request
//	    ccp      [14] CertRepMessage,         --Cross-Cert. Response
//	    ckuann   [15] CAKeyUpdContent,        --CA Key Update Ann.
//	    cann     [16] CertAnnContent,         --Certificate Ann.
//	    rann     [17] RevAnnContent,          --Revocation Ann.
//	    crlann   [18] CRLAnnContent,          --CRL Announcement
//	    pkiconf  [19] PKIConfirmContent,      --Confirmation
//	    nested   [20] NestedMessageContent,   --Nested Message
//	    genm     [21] GenMsgContent,          --General Message
//	    genp     [22] GenRepContent,          --General Response
//	    error    [23] ErrorMsgContent,        --Error Message
//	    certConf [24] CertConfirmContent,     --Certificate Confirm
//	    pollReq  [25] PollReqContent,         --Polling Request
//	    pollRep  [26] PollRepContent          --Polling Response
//	}
//
// PKIBody handles the CHOICE elements by lazily parsing the underlying
// CHOICE variant. An PKIBody instance only ever represents a single CHOICE variant
// determined at parse time.
//
// PKIBody is not thread-safe. Concurrent access must be synchronized by the caller.
type PKIBody struct {
	// Type identifies which CMP body variant is present.
	Type  BodyType
	Raw   []byte // Raw DER of the CHOICE element (including context tag)
	dirty bool   // true when constructed or modified; marshal re-encodes instead of using Raw
	err   error

	// Lazy parsed fields (pointers to the decoded types)
	ir       *CertReqMessages
	ip       *CertRepMessage
	cr       *CertReqMessages
	cp       *CertRepMessage
	p10cr    *x509.CertificateRequest
	kur      *CertReqMessages
	kup      *CertRepMessage
	certConf *CertConfirmContent
	pkiConf  *PKIConfirmContent
	pollReq  *PollReqContent
	pollRep  *PollRepContent
	errorMsg *ErrorMsgContent
	nested   *PKIMessage
}

type BodyType cbasn1.Tag

const (
	classContextSpecific = 0x80 // bit 8 set
	classConstructed     = 0x20 // bit 6 set
)

const (
	BodyTypeIR       = BodyType(0 | classContextSpecific | classConstructed)
	BodyTypeIP       = BodyType(1 | classContextSpecific | classConstructed)
	BodyTypeCR       = BodyType(2 | classContextSpecific | classConstructed)
	BodyTypeCP       = BodyType(3 | classContextSpecific | classConstructed)
	BodyTypeP10CR    = BodyType(4 | classContextSpecific | classConstructed)
	BodyTypeKUR      = BodyType(7 | classContextSpecific | classConstructed)
	BodyTypeKUP      = BodyType(8 | classContextSpecific | classConstructed)
	BodyTypePKIConf  = BodyType(19 | classContextSpecific | classConstructed)
	BodyTypeNested   = BodyType(20 | classContextSpecific | classConstructed) // RFC 9810 §5.1.2: nested [20] NestedMessageContent
	BodyTypeError    = BodyType(23 | classContextSpecific | classConstructed)
	BodyTypeCertConf = BodyType(24 | classContextSpecific | classConstructed)
	BodyTypePollReq  = BodyType(25 | classContextSpecific | classConstructed)
	BodyTypePollRep  = BodyType(26 | classContextSpecific | classConstructed)
)

func (b *PKIBody) unmarshal(s *cryptobyte.String) error {
	b.Raw = []byte(*s)
	var content cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&content, &tag) {
		return &ParseError{Detail: "missing PKIBody tag"}
	}
	if tag.ContextSpecific() != tag {
		return &ParseError{Detail: fmt.Sprintf("invalid PKIBody tag: %d", tag)}
	}
	b.Type = BodyType(tag)
	return nil
}

func (b *PKIBody) marshal(mctx *MarshalContext, builder *cryptobyte.Builder) {
	if len(b.Raw) > 0 && !b.dirty {
		builder.AddBytes(b.Raw)
		return
	}

	builder.AddASN1(cbasn1.Tag(b.Type), func(builder *cryptobyte.Builder) {
		switch b.Type {
		case BodyTypeIR:
			b.ir.marshal(mctx, builder)
		case BodyTypeIP:
			b.ip.marshal(mctx, builder)
		case BodyTypeCR:
			b.cr.marshal(mctx, builder)
		case BodyTypeCP:
			b.cp.marshal(mctx, builder)
		case BodyTypeP10CR:
			builder.AddBytes(b.p10cr.Raw)
		case BodyTypeKUR:
			b.kur.marshal(mctx, builder)
		case BodyTypeKUP:
			b.kup.marshal(mctx, builder)
		case BodyTypeCertConf:
			b.certConf.marshal(mctx, builder)
		case BodyTypePKIConf:
			b.pkiConf.marshal(mctx, builder)
		case BodyTypePollReq:
			b.pollReq.marshal(mctx, builder)
		case BodyTypePollRep:
			b.pollRep.marshal(mctx, builder)
		case BodyTypeError:
			b.errorMsg.marshal(mctx, builder)
		case BodyTypeNested:
			// NestedMessageContent ::= PKIMessage (RFC 9810 §5.1.3.5)
			// The inner PKIMessage is encoded as a full DER SEQUENCE inside the [20] tag.
			der, err := b.nested.MarshalBinary()
			if err != nil {
				builder.SetError(err)
				return
			}
			builder.AddBytes(der)
		default:
			// Should not happen if correctly constructed
			builder.AddBytes(b.Raw)
		}
	})
}

// Getters

func (b *PKIBody) IR() (*CertReqMessages, error) {
	if b.Type != BodyTypeIR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not ir (type %d)", b.Type)}
	}
	if b.ir == nil && b.err == nil {
		b.ir = &CertReqMessages{}
		b.err = b.unmarshalBodyContent(b.ir)
	}
	return b.ir, b.err
}

func (b *PKIBody) CR() (*CertReqMessages, error) {
	if b.Type != BodyTypeCR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not cr (type %d)", b.Type)}
	}
	if b.cr == nil && b.err == nil {
		b.cr = &CertReqMessages{}
		b.err = b.unmarshalBodyContent(b.cr)
	}
	return b.cr, b.err
}

func (b *PKIBody) KUR() (*CertReqMessages, error) {
	if b.Type != BodyTypeKUR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not kur (type %d)", b.Type)}
	}
	if b.kur == nil && b.err == nil {
		b.kur = &CertReqMessages{}
		b.err = b.unmarshalBodyContent(b.kur)
	}
	return b.kur, b.err
}

// CertReqMessages returns the CertReqMessages for IR, CR, or KUR body types.
// This is a convenience method that dispatches to the appropriate getter.
func (b *PKIBody) CertReqMessages() (*CertReqMessages, error) {
	switch b.Type {
	case BodyTypeIR:
		return b.IR()
	case BodyTypeCR:
		return b.CR()
	case BodyTypeKUR:
		return b.KUR()
	default:
		return nil, &ParseError{Detail: fmt.Sprintf("body type %d is not a cert request", b.Type)}
	}
}

func (b *PKIBody) KUP() (*CertRepMessage, error) {
	if b.Type != BodyTypeKUP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not kup (type %d)", b.Type)}
	}
	if b.kup == nil && b.err == nil {
		b.kup = &CertRepMessage{}
		b.err = b.unmarshalBodyContent(b.kup)
	}
	return b.kup, b.err
}

func (b *PKIBody) P10CR() (*x509.CertificateRequest, error) {
	if b.Type != BodyTypeP10CR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not p10cr (type %d)", b.Type)}
	}
	if b.p10cr != nil || b.err != nil {
		return b.p10cr, b.err
	}

	if len(b.Raw) == 0 {
		var builder cryptobyte.Builder
		builder.AddASN1(cbasn1.Tag(BodyTypeP10CR), func(b2 *cryptobyte.Builder) {
			b2.AddBytes(b.p10cr.Raw)
		})
		var err error
		b.Raw, err = builder.Bytes()
		if err != nil {
			b.err = err
			return nil, err
		}
	}
	s := cryptobyte.String(b.Raw)
	var sub cryptobyte.String
	if !s.ReadASN1(&sub, cbasn1.Tag(BodyTypeP10CR)) {
		b.err = &ParseError{Detail: "invalid p10cr body"}
		return nil, b.err
	}
	b.p10cr, b.err = x509.ParseCertificateRequest(sub)
	return b.p10cr, b.err
}

func (b *PKIBody) CP() (*CertRepMessage, error) {
	if b.Type != BodyTypeCP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not cp (type %d)", b.Type)}
	}
	if b.cp == nil && b.err == nil {
		b.cp = &CertRepMessage{}
		b.err = b.unmarshalBodyContent(b.cp)
	}
	return b.cp, b.err
}

func (b *PKIBody) IP() (*CertRepMessage, error) {
	if b.Type != BodyTypeIP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not ip (type %d)", b.Type)}
	}
	if b.ip == nil && b.err == nil {
		b.ip = &CertRepMessage{}
		b.err = b.unmarshalBodyContent(b.ip)
	}
	return b.ip, b.err
}

func (b *PKIBody) CertConf() (*CertConfirmContent, error) {
	if b.Type != BodyTypeCertConf {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not certConf (type %d)", b.Type)}
	}
	if b.certConf == nil && b.err == nil {
		b.certConf = &CertConfirmContent{}
		b.err = b.unmarshalBodyContent(b.certConf)
	}
	return b.certConf, b.err
}

func (b *PKIBody) PKIConf() (*PKIConfirmContent, error) {
	if b.Type != BodyTypePKIConf {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not pkiconf (type %d)", b.Type)}
	}
	if b.pkiConf == nil && b.err == nil {
		b.pkiConf = &PKIConfirmContent{}
		b.err = b.unmarshalBodyContent(b.pkiConf)
	}
	return b.pkiConf, b.err
}

func (b *PKIBody) PollReq() (*PollReqContent, error) {
	if b.Type != BodyTypePollReq {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not pollReq (type %d)", b.Type)}
	}
	if b.pollReq == nil && b.err == nil {
		b.pollReq = &PollReqContent{}
		b.err = b.unmarshalBodyContent(b.pollReq)
	}
	return b.pollReq, b.err
}

func (b *PKIBody) PollRep() (*PollRepContent, error) {
	if b.Type != BodyTypePollRep {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not pollRep (type %d)", b.Type)}
	}
	if b.pollRep == nil && b.err == nil {
		b.pollRep = &PollRepContent{}
		b.err = b.unmarshalBodyContent(b.pollRep)
	}
	return b.pollRep, b.err
}

func (b *PKIBody) Error() (*ErrorMsgContent, error) {
	if b.Type != BodyTypeError {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not error (type %d)", b.Type)}
	}
	if b.errorMsg == nil && b.err == nil {
		b.errorMsg = &ErrorMsgContent{}
		b.err = b.unmarshalBodyContent(b.errorMsg)
	}
	return b.errorMsg, b.err
}

// Nested returns the inner PKIMessage from a nested [20] body.
// RFC 9810 §5.1.3.5: NestedMessageContent ::= PKIMessage.
func (b *PKIBody) Nested() (*PKIMessage, error) {
	if b.Type != BodyTypeNested {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not nested (type %d)", b.Type)}
	}
	if b.nested == nil && b.err == nil {
		// Parse the inner PKIMessage from the body content bytes.
		s := cryptobyte.String(b.Raw)
		var content cryptobyte.String
		if !s.ReadASN1(&content, cbasn1.Tag(b.Type)) {
			b.err = &ParseError{Detail: "invalid nested body content"}
			return nil, b.err
		}
		b.nested, b.err = ParsePKIMessage([]byte(content))
	}
	return b.nested, b.err
}

func (b *PKIBody) unmarshalBodyContent(p interface {
	unmarshal(s *cryptobyte.String) error
	marshal(mctx *MarshalContext, b *cryptobyte.Builder)
}) error {
	if len(b.Raw) == 0 {
		var builder cryptobyte.Builder
		// Use a temporary context for this internal marshaling
		p.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &builder)
		var err error
		b.Raw, err = builder.Bytes()
		if err != nil {
			return err
		}
	}
	s := cryptobyte.String(b.Raw)
	var sub cryptobyte.String
	if !s.ReadASN1(&sub, cbasn1.Tag(b.Type)) {
		return &ParseError{Detail: fmt.Sprintf("invalid body content for type %d", b.Type)}
	}
	return p.unmarshal(&sub)
}

// Constructors

func NewIRBody(req *CertReqMessages) *PKIBody {
	return &PKIBody{Type: BodyTypeIR, ir: req, dirty: true}
}

func NewCRBody(req *CertReqMessages) *PKIBody {
	return &PKIBody{Type: BodyTypeCR, cr: req, dirty: true}
}

func NewKURBody(req *CertReqMessages) *PKIBody {
	return &PKIBody{Type: BodyTypeKUR, kur: req, dirty: true}
}

func NewKUPBody(rep *CertRepMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeKUP, kup: rep, dirty: true}
}

func NewP10CRBody(csr *x509.CertificateRequest) *PKIBody {
	return &PKIBody{Type: BodyTypeP10CR, p10cr: csr, dirty: true}
}

func NewCPBody(rep *CertRepMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeCP, cp: rep, dirty: true}
}

func NewIPBody(rep *CertRepMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeIP, ip: rep, dirty: true}
}

func NewCertConfBody(conf *CertConfirmContent) *PKIBody {
	return &PKIBody{Type: BodyTypeCertConf, certConf: conf, dirty: true}
}

func NewPKIConfBody() *PKIBody {
	return &PKIBody{Type: BodyTypePKIConf, pkiConf: &PKIConfirmContent{}, dirty: true}
}

func NewPollReqBody(req *PollReqContent) *PKIBody {
	return &PKIBody{Type: BodyTypePollReq, pollReq: req, dirty: true}
}

func NewPollRepBody(rep *PollRepContent) *PKIBody {
	return &PKIBody{Type: BodyTypePollRep, pollRep: rep, dirty: true}
}

func NewErrorBody(err *ErrorMsgContent) *PKIBody {
	return &PKIBody{Type: BodyTypeError, errorMsg: err, dirty: true}
}

// NewNestedBody creates a nested [20] body wrapping a single inner PKIMessage.
// RFC 9810 §5.1.3.5: NestedMessageContent ::= PKIMessage.
func NewNestedBody(msg *PKIMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeNested, nested: msg, dirty: true}
}
