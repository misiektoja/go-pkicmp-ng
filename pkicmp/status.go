package pkicmp

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PKIStatus per RFC 9810 §5.2.3.
//
//	PKIStatus ::= INTEGER {
//	   accepted               (0),
//	   grantedWithMods        (1),
//	   rejection              (2),
//	   waiting                (3),
//	   revocationWarning      (4),
//	   revocationNotification (5),
//	   keyUpdateWarning       (6)
//	}
type PKIStatus int

const (
	StatusAccepted               PKIStatus = 0
	StatusGrantedWithMods        PKIStatus = 1
	StatusRejection              PKIStatus = 2
	StatusWaiting                PKIStatus = 3
	StatusRevocationWarning      PKIStatus = 4
	StatusRevocationNotification PKIStatus = 5
	StatusKeyUpdateWarning       PKIStatus = 6
)

func (s PKIStatus) String() string {
	switch s {
	case StatusAccepted:
		return "accepted"
	case StatusGrantedWithMods:
		return "grantedWithMods"
	case StatusRejection:
		return "rejection"
	case StatusWaiting:
		return "waiting"
	case StatusRevocationWarning:
		return "revocationWarning"
	case StatusRevocationNotification:
		return "revocationNotification"
	case StatusKeyUpdateWarning:
		return "keyUpdateWarning"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// PKIFailureInfo per RFC 9810 §5.2.3.
//
//	PKIFailureInfo ::= BIT STRING {
//	   badAlg                 (0),
//	   badMessageCheck        (1),
//	   badRequest             (2),
//	   badTime                (3),
//	   badCertId              (4),
//	   badDataFormat          (5),
//	   wrongAuthority         (6),
//	   incorrectData          (7),
//	   missingTimeStamp       (8),
//	   badPOP                 (9),
//	   certRevoked            (10),
//	   certConfirmed          (11),
//	   wrongIntegrity         (12),
//	   badRecipientNonce      (13),
//	   timeNotAvailable       (14),
//	   unacceptedPolicy       (15),
//	   unacceptedExtension    (16),
//	   addInfoNotAvailable    (17),
//	   badSenderNonce         (18),
//	   badCertTemplate        (19),
//	   signerNotTrusted       (20),
//	   transactionIdInUse     (21),
//	   unsupportedVersion     (22),
//	   notAuthorized          (23),
//	   systemUnavail          (24),
//	   systemFailure          (25),
//	   duplicateCertReq       (26)
//	}

// HasFailure returns true if the error is a *PKIStatusError (or wraps one)
// and the specified failure bit is set in its FailInfo field.
//
// Example:
//
//	if pkicmp.HasFailure(err, pkicmp.FailBadAlg) { ... }
func HasFailure(err error, info PKIFailureInfo) bool {
	var statusErr *PKIStatusError
	if errors.As(err, &statusErr) {
		return statusErr.FailInfo&info != 0
	}
	return false
}

// PKIFailureInfo gives machine-readable reason bits for non-success cases.
// It is a bitmask where each bit represents a specific failure condition
// defined in RFC 9810 §5.2.3.
//
// Callers can check for specific failure bits using HasFailure(err, bit)
// or by using bitwise AND on the FailInfo field of a PKIStatusError:
//
//	if err != nil {
//	    var statusErr *pkicmp.PKIStatusError
//	    if errors.As(err, &statusErr) {
//	        if statusErr.FailInfo & pkicmp.FailBadAlg != 0 {
//	            // Handle bad algorithm error
//	        }
//	    }
//	}
type PKIFailureInfo uint32

const (
	FailBadAlg              PKIFailureInfo = 1 << (31 - 0)
	FailBadMessageCheck     PKIFailureInfo = 1 << (31 - 1)
	FailBadRequest          PKIFailureInfo = 1 << (31 - 2)
	FailBadTime             PKIFailureInfo = 1 << (31 - 3)
	FailBadCertId           PKIFailureInfo = 1 << (31 - 4)
	FailBadDataFormat       PKIFailureInfo = 1 << (31 - 5)
	FailWrongAuthority      PKIFailureInfo = 1 << (31 - 6)
	FailIncorrectData       PKIFailureInfo = 1 << (31 - 7)
	FailMissingTimeStamp    PKIFailureInfo = 1 << (31 - 8)
	FailBadPOP              PKIFailureInfo = 1 << (31 - 9)
	FailCertRevoked         PKIFailureInfo = 1 << (31 - 10)
	FailCertConfirmed       PKIFailureInfo = 1 << (31 - 11)
	FailWrongIntegrity      PKIFailureInfo = 1 << (31 - 12)
	FailBadRecipientNonce   PKIFailureInfo = 1 << (31 - 13)
	FailTimeNotAvailable    PKIFailureInfo = 1 << (31 - 14)
	FailUnacceptedPolicy    PKIFailureInfo = 1 << (31 - 15)
	FailUnacceptedExtension PKIFailureInfo = 1 << (31 - 16)
	FailAddInfoNotAvailable PKIFailureInfo = 1 << (31 - 17)
	FailBadSenderNonce      PKIFailureInfo = 1 << (31 - 18)
	FailBadCertTemplate     PKIFailureInfo = 1 << (31 - 19)
	FailSignerNotTrusted    PKIFailureInfo = 1 << (31 - 20)
	FailTransactionIdInUse  PKIFailureInfo = 1 << (31 - 21)
	FailUnsupportedVersion  PKIFailureInfo = 1 << (31 - 22)
	FailNotAuthorized       PKIFailureInfo = 1 << (31 - 23)
	FailSystemUnavail       PKIFailureInfo = 1 << (31 - 24)
	FailSystemFailure       PKIFailureInfo = 1 << (31 - 25)
	FailDuplicateCertReq    PKIFailureInfo = 1 << (31 - 26)
)

var failureInfoNames = map[PKIFailureInfo]string{
	FailBadAlg:              "badAlg",
	FailBadMessageCheck:     "badMessageCheck",
	FailBadRequest:          "badRequest",
	FailBadTime:             "badTime",
	FailBadCertId:           "badCertId",
	FailBadDataFormat:       "badDataFormat",
	FailWrongAuthority:      "wrongAuthority",
	FailIncorrectData:       "incorrectData",
	FailMissingTimeStamp:    "missingTimeStamp",
	FailBadPOP:              "badPOP",
	FailCertRevoked:         "certRevoked",
	FailCertConfirmed:       "certConfirmed",
	FailWrongIntegrity:      "wrongIntegrity",
	FailBadRecipientNonce:   "badRecipientNonce",
	FailTimeNotAvailable:    "timeNotAvailable",
	FailUnacceptedPolicy:    "unacceptedPolicy",
	FailUnacceptedExtension: "unacceptedExtension",
	FailAddInfoNotAvailable: "addInfoNotAvailable",
	FailBadSenderNonce:      "badSenderNonce",
	FailBadCertTemplate:     "badCertTemplate",
	FailSignerNotTrusted:    "signerNotTrusted",
	FailTransactionIdInUse:  "transactionIdInUse",
	FailUnsupportedVersion:  "unsupportedVersion",
	FailNotAuthorized:       "notAuthorized",
	FailSystemUnavail:       "systemUnavail",
	FailSystemFailure:       "systemFailure",
	FailDuplicateCertReq:    "duplicateCertReq",
}

func (f PKIFailureInfo) String() string {
	var parts []string
	for i := uint(0); i <= 26; i++ {
		bit := PKIFailureInfo(1 << (31 - i))
		if f&bit != 0 {
			if name, ok := failureInfoNames[bit]; ok {
				parts = append(parts, name)
			} else {
				parts = append(parts, fmt.Sprintf("unknown(%d)", i))
			}
		}
	}
	return strings.Join(parts, ", ")
}

// PKIStatusInfo represents the ASN.1 structure defined in RFC 9810 §5.2.3.
// It is the raw data structure used for encoding and decoding CMP status
// information during network transmission.
//
//	PKIStatusInfo ::= SEQUENCE {
//	    status        PKIStatus,
//	    statusString  PKIFreeText     OPTIONAL,
//	    failInfo      PKIFailureInfo  OPTIONAL }
type PKIStatusInfo struct {
	// Status indicates accepted, waiting, rejection, or warning outcome.
	Status PKIStatus
	// StatusString carries server-provided explanatory messages.
	StatusString PKIFreeText
	// FailInfo gives machine-readable reason bits for non-success cases.
	FailInfo PKIFailureInfo
}

// PKIStatusError is a Go-idiomatic error type that wraps status information.
// While PKIStatusInfo is designed for the wire, PKIStatusError is designed
// for developer use, providing a single error string and implementing the
// error interface.
type PKIStatusError struct {
	// Status is the normalized status code derived from PKIStatusInfo.
	Status PKIStatus
	// StatusString is a flattened message string for Go error usage.
	StatusString string
	// FailInfo is a bitmask of machine-readable reason bits for the failure.
	// Callers can use bitwise AND with Fail* constants to check for specific conditions.
	FailInfo PKIFailureInfo
}

var ErrWaiting = errors.New("pkicmp: waiting")

// AsError converts the wire-format PKIStatusInfo into a Go PKIStatusError.
// It returns:
//   - nil: if the status is StatusAccepted or StatusGrantedWithMods.
//   - ErrWaiting: if the status is StatusWaiting.
//   - *PKIStatusError: for any other status (failures or warnings).
func (si PKIStatusInfo) AsError() error {
	switch si.Status {
	case StatusAccepted, StatusGrantedWithMods:
		return nil
	case StatusWaiting:
		return ErrWaiting
	default:
		return &PKIStatusError{
			Status:       si.Status,
			StatusString: strings.Join(si.StatusString, "; "),
			FailInfo:     si.FailInfo,
		}
	}
}

// Error implements the error interface for PKIStatusError, providing a human-readable error message.
func (e *PKIStatusError) Error() string {
	msg := fmt.Sprintf("pkicmp: status %s", e.Status)
	if e.FailInfo != 0 {
		msg += fmt.Sprintf(", failInfo: %s", e.FailInfo)
	}
	if e.StatusString != "" {
		msg += fmt.Sprintf(", details: %s", e.StatusString)
	}
	return msg
}

// ErrorMsgContent per RFC 9810 §5.3.21.
//
//	ErrorMsgContent ::= SEQUENCE {
//	    pKIStatusInfo          PKIStatusInfo,
//	    errorCode              INTEGER           OPTIONAL,
//	    -- implementation-specific error codes
//	    errorDetails           PKIFreeText       OPTIONAL
//	    -- implementation-specific error details
//	}
type ErrorMsgContent struct {
	// PKIStatusInfo gives the canonical CMP status for the failure.
	PKIStatusInfo PKIStatusInfo
	// ErrorCode carries an optional server-specific numeric code.
	ErrorCode int
	// ErrorDetails carries optional server-specific detail messages.
	ErrorDetails PKIFreeText
}

// ASN.1 Helpers

func (si *PKIStatusInfo) marshal(mctx *MarshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(si.Status))
		if len(si.StatusString) > 0 {
			si.StatusString.marshal(mctx, b)
		}
		if si.FailInfo != 0 {
			// PKIFailureInfo is a named bit list (RFC 9810 §5.2.3).
			// DER requires minimum encoding with trailing zero bits/bytes trimmed.
			b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
				trailing := bits.TrailingZeros32(uint32(si.FailInfo))
				n := 4 - trailing/8           // number of bytes needed
				unused := uint8(trailing % 8) // #nosec G115 -- trailing%8 is always 0-7
				b.AddUint8(unused)
				b.AddBytes([]byte{byte(si.FailInfo >> 24), byte(si.FailInfo >> 16), byte(si.FailInfo >> 8), byte(si.FailInfo)}[:n]) // #nosec G115 -- intentional byte extraction from uint32
			})
		}
	})
}

func (si *PKIStatusInfo) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid PKIStatusInfo sequence"}
	}
	var status int64
	if !seq.ReadASN1Integer(&status) {
		return &ParseError{Detail: "invalid PKIStatus"}
	}
	si.Status = PKIStatus(status)

	if !seq.Empty() {
		if seq.PeekASN1Tag(cbasn1.SEQUENCE) {
			if err := si.StatusString.unmarshal(&seq); err != nil {
				return err
			}
		}
		if seq.PeekASN1Tag(cbasn1.BIT_STRING) {
			var bitString cryptobyte.String
			if !seq.ReadASN1(&bitString, cbasn1.BIT_STRING) {
				return &ParseError{Detail: "invalid failInfo BIT STRING"}
			}
			var unused uint8
			if !bitString.ReadUint8(&unused) {
				return &ParseError{Detail: "invalid failInfo unused bits"}
			}
			var val uint32
			// Read up to 4 bytes
			for i := 0; i < 4 && !bitString.Empty(); i++ {
				var b uint8
				bitString.ReadUint8(&b)
				val |= uint32(b) << (8 * (3 - i))
			}
			si.FailInfo = PKIFailureInfo(val)
		}
	}
	return nil
}

func (e *ErrorMsgContent) marshal(mctx *MarshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		e.PKIStatusInfo.marshal(mctx, b)
		if e.ErrorCode != 0 {
			b.AddASN1Int64(int64(e.ErrorCode))
		}
		if len(e.ErrorDetails) > 0 {
			e.ErrorDetails.marshal(mctx, b)
		}
	})
}

func (e *ErrorMsgContent) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid ErrorMsgContent sequence"}
	}
	if err := e.PKIStatusInfo.unmarshal(&seq); err != nil {
		return err
	}
	if !seq.Empty() && seq.PeekASN1Tag(cbasn1.INTEGER) {
		var code int64
		if !seq.ReadASN1Integer(&code) {
			return &ParseError{Detail: "invalid errorCode"}
		}
		e.ErrorCode = int(code)
	}
	if !seq.Empty() && seq.PeekASN1Tag(cbasn1.SEQUENCE) {
		if err := e.ErrorDetails.unmarshal(&seq); err != nil {
			return err
		}
	}
	return nil
}
