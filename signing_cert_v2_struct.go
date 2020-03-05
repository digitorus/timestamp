package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	CertHash      []byte
	IssuerSerial  issuerAndSerial `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
}
