// Package timestamp implements the Time-Stamp Protocol (TSP) as specified in
// RFC3161 (Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)).
package timestamp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"

	"github.com/digitorus/pkcs7"
)

// FailureInfo contains the result of an Time-Stamp request. See
// https://tools.ietf.org/html/rfc3161#section-2.4.2
type FailureInfo int

const (
	// BadAlgorithm defines an unrecognized or unsupported Algorithm Identifier
	BadAlgorithm FailureInfo = 0
	// BadRequest indicates that the transaction not permitted or supported
	BadRequest FailureInfo = 2
	// BadDataFormat means tha data submitted has the wrong format
	BadDataFormat FailureInfo = 5
	// TimeNotAvailable indicates that TSA's time source is not available
	TimeNotAvailable FailureInfo = 14
	// UnacceptedPolicy indicates that the requested TSA policy is not supported
	// by the TSA
	UnacceptedPolicy FailureInfo = 15
	// UnacceptedExtension indicates that the requested extension is not supported
	// by the TSA
	UnacceptedExtension FailureInfo = 16
	// AddInfoNotAvailable means that the information requested could not be
	// understood or is not available
	AddInfoNotAvailable FailureInfo = 17
	// SystemFailure indicates that the request cannot be handled due to system
	// failure
	SystemFailure FailureInfo = 25
)

func (f FailureInfo) String() string {
	switch f {
	case BadAlgorithm:
		return "unrecognized or unsupported Algorithm Identifier"
	case BadRequest:
		return "transaction not permitted or supported"
	case BadDataFormat:
		return "the data submitted has the wrong format"
	case TimeNotAvailable:
		return "the TSA's time source is not available"
	case UnacceptedPolicy:
		return "the requested TSA policy is not supported by the TSA"
	case UnacceptedExtension:
		return "the requested extension is not supported by the TSA"
	case AddInfoNotAvailable:
		return "the additional information requested could not be understood or is not available"
	case SystemFailure:
		return "the request cannot be handled due to system failure"
	default:
		return "unknown failure: " + strconv.Itoa(int(f))
	}
}

// ParseError results from an invalid Time-Stamp request or response.
type ParseError string

func (p ParseError) Error() string {
	return string(p)
}

// Request represents an Time-Stamp request. See
// https://tools.ietf.org/html/rfc3161#section-2.4.1
type Request struct {
	HashAlgorithm crypto.Hash
	HashedMessage []byte

	// Certificates indicates if the TSA needs to return the signing certificate
	// and optionally any other certificates of the chain as part of the response.
	Certificates bool

	// Extensions contains raw X.509 extensions from the Extensions field of the
	// Time-Stamp request. When parsing requests, this can be used to extract
	// non-critical extensions that are not parsed by this package. When
	// marshaling OCSP requests, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// OCSP response (in the singleExtensions field). Values override any
	// extensions that would otherwise be produced based on the other fields. The
	// ExtraExtensions field is not populated when parsing Time-Stamp requests,
	// see Extensions.
	ExtraExtensions []pkix.Extension
}

// ParseRequest parses an timestamp request in DER form.
func ParseRequest(bytes []byte) (*Request, error) {
	var err error
	var rest []byte
	var req request

	if rest, err = asn1.Unmarshal(bytes, &req); err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ParseError("trailing data in Time-Stamp request")
	}

	if len(req.MessageImprint.HashedMessage) == 0 {
		return nil, ParseError("Time-Stamp request contains no hashed message")
	}

	hashFunc := getHashAlgorithmFromOID(req.MessageImprint.HashAlgorithm.Algorithm)
	if hashFunc == crypto.Hash(0) {
		return nil, ParseError("Time-Stamp request uses unknown hash function")
	}

	return &Request{
		HashAlgorithm: hashFunc,
		HashedMessage: req.MessageImprint.HashedMessage,
		Certificates:  req.CertReq,
		Extensions:    req.Extensions,
	}, nil
}

// Marshal marshals the Time-Stamp request to ASN.1 DER encoded form.
func (req *Request) Marshal() ([]byte, error) {
	return asn1.Marshal(request{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: getOIDFromHashAlgorithm(req.HashAlgorithm),
				Parameters: asn1.RawValue{
					Tag: 5, /* ASN.1 NULL */
				},
			},
			HashedMessage: req.HashedMessage,
		},
		CertReq:    req.Certificates,
		Extensions: req.ExtraExtensions,
	})
}

// Timestamp represents an Time-Stamp. See:
// https://tools.ietf.org/html/rfc3161#section-2.4.1
type Timestamp struct {
	HashAlgorithm crypto.Hash
	HashedMessage []byte

	Time         time.Time
	Accuracy     time.Duration
	SerialNumber *big.Int

	Certificates []*x509.Certificate

	// Extensions contains raw X.509 extensions from the Extensions field of the
	// Time-Stamp. When parsing time-stamps, this can be used to extract
	// non-critical extensions that are not parsed by this package. When
	// marshaling time-stamps, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// Time-Stamp response. Values override any extensions that would otherwise
	// be produced based on the other fields. The ExtraExtensions field is not
	// populated when parsing Time-Stamp responses, see Extensions.
	ExtraExtensions []pkix.Extension
}

// ParseResponse parses an Time-Stamp response in DER form containing a
// TimeStampToken.
//
// Invalid signatures or parse failures will result in a ParseError. Error
// responses will result in a ResponseError.
func ParseResponse(bytes []byte) (*Timestamp, error) {
	var err error
	var rest []byte
	var resp response

	if rest, err = asn1.Unmarshal(bytes, &resp); err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ParseError("trailing data in Time-Stamp response")
	}

	if resp.Status.Status > 0 {
		return nil, ParseError(fmt.Sprintf("%s: %s",
			FailureInfo(resp.Status.FailInfo).String(), resp.Status.StatusString))
	}

	if len(resp.TimeStampToken.Bytes) == 0 {
		return nil, ParseError("no pkcs7 data in Time-Stamp response")
	}

	return Parse(resp.TimeStampToken.FullBytes)
}

// Parse parses an Time-Stamp in DER form. If the time-stamp contains a
// certificate then the signature over the response is checked.
//
// Invalid signatures or parse failures will result in a ParseError. Error
// responses will result in a ResponseError.
func Parse(bytes []byte) (*Timestamp, error) {
	p7, err := pkcs7.Parse(bytes)
	if err != nil {
		return nil, err
	}

	if len(p7.Certificates) > 0 {
		if err = p7.Verify(); err != nil {
			return nil, err
		}
	}

	var inf tstInfo
	if _, err = asn1.Unmarshal(p7.Content, &inf); err != nil {
		return nil, err
	}

	if len(inf.MessageImprint.HashedMessage) == 0 {
		return nil, ParseError("Time-Stamp response contains no hashed message")
	}

	ret := &Timestamp{
		HashedMessage: inf.MessageImprint.HashedMessage,
		SerialNumber:  inf.SerialNumber,
		Time:          inf.Time,
		Accuracy: time.Duration((time.Second * time.Duration(inf.Accuracy.Seconds)) +
			(time.Millisecond * time.Duration(inf.Accuracy.Milliseconds)) +
			(time.Microsecond * time.Duration(inf.Accuracy.Microseconds))),
		Certificates: p7.Certificates,

		Extensions: inf.Extensions,
	}

	ret.HashAlgorithm = getHashAlgorithmFromOID(inf.MessageImprint.HashAlgorithm.Algorithm)
	if ret.HashAlgorithm == crypto.Hash(0) {
		return nil, ParseError("Time-Stamp response uses unknown hash function")
	}

	return ret, nil
}

// RequestOptions contains options for constructing timestamp requests.
type RequestOptions struct {
	// Hash contains the hash function that should be used when
	// constructing the timestamp request. If zero, SHA-256 will be used.
	Hash crypto.Hash

	// Certificates sets Request.Certificates
	Certificates bool
}

func (opts *RequestOptions) hash() crypto.Hash {
	if opts == nil || opts.Hash == 0 {
		return crypto.SHA256
	}
	return opts.Hash
}

// CreateRequest returns a DER-encoded, timestamp request for the status of cert. If
// opts is nil then sensible defaults are used.
func CreateRequest(r io.Reader, opts *RequestOptions) ([]byte, error) {
	hashFunc := opts.hash()

	if !hashFunc.Available() {
		return nil, x509.ErrUnsupportedAlgorithm
	}
	h := opts.hash().New()

	b := make([]byte, 32)
	for {
		n, err := r.Read(b)
		if err == io.EOF {
			break
		}

		h.Write(b[:n])
	}

	req := &Request{
		HashAlgorithm: opts.hash(),
		HashedMessage: h.Sum(nil),
	}

	if opts != nil {
		req.Certificates = opts.Certificates
	}

	return req.Marshal()
}

// CreateResponse returns a DER-encoded timestamp response with the specified contents.
// The fields in the response are populated as follows:
//
// The responder cert is used to populate the responder's name field, and the
// certificate itself is provided alongside the timestamp response signature.
func CreateResponse(signingCert *x509.Certificate, priv crypto.Signer) ([]byte, error) {
	return nil, errors.New("CreateResponse not implemented")
}
