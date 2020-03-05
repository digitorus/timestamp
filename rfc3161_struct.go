package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// http://www.ietf.org/rfc/rfc3161.txt
// 2.4.1. Request Format
type request struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      tsaPolicyID      `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	CertReq        bool             `asn1:"optional,default:false"`
	Extensions     []pkix.Extension `asn1:"tag:0,optional"`
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type tsaPolicyID asn1.ObjectIdentifier

// 2.4.2. Response Format
type response struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue
}

type pkiStatusInfo struct {
	Status       int
	StatusString string `asn1:"optional"`
	FailInfo     int    `asn1:"optional"`
}

// eContent within SignedData is TSTInfo
type tstInfo struct {
	Version        int
	Policy         asn1.RawValue
	MessageImprint messageImprint
	SerialNumber   *big.Int
	Time           time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

// Accuracy within TSTInfo
type Accuracy struct {
	Seconds      int64 `asn1:"optional"`
	Milliseconds int64 `asn1:"tag:0,optional"`
	Microseconds int64 `asn1:"tag:1,optional"`
}

type qcStatement struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}
