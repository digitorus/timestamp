package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

const openSSLsigningCertificateV2 = "MIGmMIGjMCIEIF3fpxB3ZHtqRQhp+yXouV/BC3Lq+qu2ZlzKK5gs5KNQMH0EIKVoZJ8s/3CtF6Uk5NktrvzvGhurqtFb8VjC3lYfPG09MFkwQaQ/MD0xGjAYBgNVBAMTEURpZ2l0b3J1cyBUZXN0IFIxMQswCQYDVQQGEwJOTDESMBAGA1UEChMJRGlnaXRvcnVzAhR5l9lohaINhjG85JxnRQJ+4ZzoIzANBgkqhkiG9w0BAQEFAASCAQBwz6D9nLivzryLlwvrWQhC9DgX6hh0h9swcqkcHdrQHzZSADcCLjJU+9eO/6yrY99e6uKwNyJiIdi39oQy/aWYcayHHyN+OO32LKJhupJrraDMFPTD7n5bhOCZOsXKIlKcm718WrVkNrle/GWabaS/fRqBFDoj8A+LBPtH6xGRz6ohUhtxpAzZoYW1KcnqHOpD40LRdA4i4jC5Y67h7//jYeA/B7Bf6KNC1TmFi388VeuVjU6FnADlB/9MkwbGunYmOlp6QY+QzJthf/1VCZlna9HKdcY5hEGCSH+ta0uXqU84ePLrvy6UvQRUNVTqIaSbLeL6MC1S636mbCjuJZ2C"

func TestOpenSSLSigningCertificateV2(t *testing.T) {
	v2bytes, err := base64.StdEncoding.DecodeString(openSSLsigningCertificateV2)
	if err != nil {
		t.Error(err)
		return
	}

	var scv2 signingCertificateV2
	if _, err = asn1.Unmarshal(v2bytes, &scv2); err != nil {
		t.Error(err)
		return
	}

	if len(scv2.Certs) != 2 {
		t.Error("Expected one essCertIDv2")
		return
	}

	// Check against the cert hash from openssl asn1parse
	if hex.EncodeToString(scv2.Certs[0].CertHash) != "5ddfa71077647b6a450869fb25e8b95fc10b72eafaabb6665cca2b982ce4a350" {
		t.Error("Unxpected certificate hash")
	}
	if hex.EncodeToString(scv2.Certs[1].CertHash) != "a568649f2cff70ad17a524e4d92daefcef1a1babaad15bf158c2de561f3c6d3d" {
		t.Error("Unxpected certificate hash")
	}
	if hex.EncodeToString(scv2.Certs[1].IssuerSerial.SerialNumber.Bytes()) != "7997d96885a20d8631bce49c6745027ee19ce823" {
		t.Error("Unxpected serial number")
	}

	// Check if we can parse the issuer name value
	var issuerRDN pkix.RDNSequence
	if rest, err := asn1.Unmarshal(scv2.Certs[1].IssuerSerial.IssuerName.Name.Bytes, &issuerRDN); err != nil {
		t.Error(err)
		return
	} else if len(rest) != 0 {
		t.Error("trailing data after issuer")
	}

	var issuer pkix.Name
	issuer.FillFromRDNSequence(&issuerRDN)
	if len(issuer.Organization) == 0 || issuer.Organization[0] != "Digitorus" {
		t.Error("Unexpected issuer organization")
	}
}
