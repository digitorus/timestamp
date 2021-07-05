package timestamp

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

var (
	// Random data, to create with OpenSSL:
	//   $ openssl rand -base64 32 > data.txt
	// Contents of our random date in tests below "RhT49MYCgJzWssTF+LXtFZbLD4pe94q4uezLWoTLzyM="
	//go:embed testdata/hashedMessage
	hashedMessage []byte

	// Time-Stamp request with nonce, to create with OpenSSL:
	//   $ openssl ts -query -data data.txt -cert -sha256 -out reqnonoce.tsq
	//go:embed testdata/reqNonce
	reqNonce []byte

	//go:embed testdata/respNonce
	respNonce []byte

	// Time-Stamp request without nonce, to create with OpenSSL:
	//   $ openssl ts -query -data data.txt -cert -sha256 -no_nonce -out reqnonoce.tsq
	//go:embed testdata/reqNoNonce
	reqNoNonce []byte

	//go:embed testdata/respNoNonce
	respNoNonce []byte

	// Time-Stamp request without certificate, to create with OpenSSL:
	//   $ openssl ts -query -data data.txt -sha256 -out reqnonoce.tsq
	//go:embed testdata/reqNoCert
	reqNoCert []byte

	//go:embed testdata/respNoCert
	respNoCert []byte

	// TimeStampToken excluding response struct
	//go:embed testdata/timeStampToken
	timeStampToken []byte
)

type testData struct {
	name          string
	request       []byte
	response      []byte
	certificates  bool
	nonce         *big.Int
	time          time.Time
	accuracy      time.Duration
	hashedMessage []byte
	hashAlgorithm crypto.Hash
}

var testCases = []testData{
	{
		name:          "Including nonce",
		request:       reqNonce,
		response:      respNonce,
		certificates:  true,
		nonce:         big.NewInt(0).SetBytes([]byte{0x9, 0x2e, 0xf1, 0x9f, 0xfb, 0x5d, 0x2a, 0xe8}),
		time:          time.Date(2017, 4, 19, 6, 29, 53, 0, time.UTC),
		accuracy:      time.Second,
		hashedMessage: hashedMessage,
		hashAlgorithm: crypto.SHA256,
	},
	{
		name:          "Containing no nonce",
		request:       reqNoNonce,
		response:      respNoNonce,
		certificates:  true,
		nonce:         nil,
		time:          time.Date(2017, 4, 19, 6, 28, 13, 0, time.UTC),
		accuracy:      time.Second,
		hashedMessage: hashedMessage,
		hashAlgorithm: crypto.SHA256,
	},
	{
		name:          "Containing no certificates",
		request:       reqNoCert,
		response:      respNoCert,
		certificates:  false,
		nonce:         big.NewInt(0).SetBytes([]byte{0xb1, 0xfc, 0x81, 0xde, 0xc9, 0x57, 0x49, 0xd9}),
		time:          time.Date(2017, 4, 19, 6, 32, 43, 0, time.UTC),
		accuracy:      time.Second,
		hashedMessage: hashedMessage,
		hashAlgorithm: crypto.SHA256,
	},
}

// Send the timestamp request to our timestamp server and save the response
//  $ curl --globoff -s -S -H Content-Type:application/timestamp-query -H Host:${HOST} --data-binary @request-sha256.tsq -o ts-output.tsr ${URL}

func TestParseRequest(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.request == nil {
				return
			}

			req, err := ParseRequest(tc.request)
			if err != nil {
				t.Errorf("failed to parse request: %s", err.Error())
				return
			}

			if !bytes.Equal(req.HashedMessage, tc.hashedMessage) {
				t.Errorf("req.HashedMessage: got %x, want %x", req.HashedMessage, tc.hashedMessage)
			}

			if (tc.nonce != nil && tc.nonce.CmpAbs(req.Nonce) != 0) || (req.Nonce != nil && tc.nonce == nil) {
				t.Errorf("req.Nonce: got %v, want %v", req.Nonce, tc.nonce)
			}

			if req.HashAlgorithm != tc.hashAlgorithm {
				t.Errorf("req.HashAlgorithm: got %v, want %v", req.HashAlgorithm, tc.hashAlgorithm)
			}

			if req.Certificates != tc.certificates {
				t.Errorf("req.Certificates: got %v, want %v", req.Certificates, tc.certificates)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.response == nil {
				return
			}

			resp, err := ParseResponse(tc.response)
			if err != nil {
				t.Errorf("failed to parse response: %s", err.Error())
				return
			}

			if !bytes.Equal(resp.HashedMessage, tc.hashedMessage) {
				t.Errorf("resp.HashedMessage: got %x, want %x", resp.HashedMessage, tc.hashedMessage)
			}

			if resp.HashAlgorithm != tc.hashAlgorithm {
				t.Errorf("resp.HashAlgorithm: got %v, want %v", resp.HashAlgorithm, tc.hashAlgorithm)
			}

			if !resp.Time.Equal(tc.time) {
				t.Errorf("resp.Time: got %v, want %v", resp.Time, tc.time)
			}

			if resp.Accuracy != tc.accuracy {
				t.Errorf("resp.Accuracy: got %v, want %v", resp.Accuracy, tc.accuracy)
			}

			if tc.certificates && len(resp.Certificates) == 0 {
				t.Errorf("resp.Certificates: got %v, want %v", len(resp.Certificates), tc.certificates)
			}

			/*
				if !(resp.Nonce == nil && tc.nonce == nil && resp.Nonce.Cmp(tc.nonce) != 0 {
					t.Errorf("resp.Nonce: got %v, want %v", resp.Nonce, tc.nonce)
				}
			*/
		})
	}
}

func TestParse(t *testing.T) {
	ts, err := Parse(timeStampToken)
	if err != nil {
		t.Errorf("failed to parse timeStampToken: %s", err.Error())
	}

	hashedMessage := []byte{0x2d, 0xa8, 0x2c, 0x15, 0x72, 0xff, 0x2, 0x5, 0x24, 0xe0, 0x50, 0x69, 0x21, 0x99, 0x75, 0xc9, 0xba, 0x90, 0x72, 0x3f, 0x1a, 0x4d, 0xd5, 0xb9, 0x72, 0x2a, 0xee, 0x8e, 0xc5, 0x47, 0xa2, 0xff}
	if !bytes.Equal(ts.HashedMessage, hashedMessage) {
		t.Errorf("ts.HashedMessage: got %x, want %x", ts.HashedMessage, hashedMessage)
	}

	tsTime := time.Date(2017, 2, 1, 15, 39, 50, 0, time.UTC)
	if !ts.Time.Equal(tsTime) {
		t.Errorf("ts.Time: got %v, want %v", ts.Time, tsTime)
	}

	if ts.Accuracy != time.Second {
		t.Errorf("ts.Accuracy: got %v, want %v", ts.Accuracy, time.Second)
	}
}

func TestMarshalRequest(t *testing.T) {
	req, err := ParseRequest(reqNoNonce)
	if err != nil {
		t.Fatal(err)
	}

	reqByes, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(reqByes, reqNoNonce) {
		t.Error("Marshalled response bytes are not the same as parsed")
	}
}

func TestCreateRequest(t *testing.T) {
	var testHashes = []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512}

	nonce := big.NewInt(0)
	nonce = nonce.SetBytes([]byte{0x1, 0x2, 0x3})

	for _, th := range testHashes {
		t.Run(fmt.Sprintf("%d", th), func(t *testing.T) {
			msg := "Content to by timestamped"

			h := th.New()
			_, err := h.Write([]byte(msg))
			if err != nil {
				t.Fatal(err)
			}
			hashedMsg := h.Sum(nil)

			req, err := CreateRequest(strings.NewReader(msg), &RequestOptions{
				Hash:         th,
				Nonce:        nonce,
				TSAPolicyOID: asn1.ObjectIdentifier{2, 5, 6, 7},
				Certificates: true,
			})
			if err != nil {
				t.Fatal(err)
			}

			if len(req) == 0 {
				t.Error("request contains no bytes")
			}

			reqCheck, err := ParseRequest(req)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(reqCheck.HashedMessage, hashedMsg) {
				t.Errorf("reqCheck.HashedMessage: got %x, want %x", reqCheck.HashedMessage, hashedMsg)
			}

			if reqCheck.Nonce.Cmp(nonce) != 0 {
				t.Errorf("reqCheck.Nonce: got %x, want %x", reqCheck.Nonce, nonce)
			}

			if reqCheck.Certificates != true {
				t.Errorf("reqCheck.Certificates: got %t, want %t", reqCheck.Certificates, true)
			}

			if !reqCheck.TSAPolicyOID.Equal(asn1.ObjectIdentifier{2, 5, 6, 7}) {
				t.Errorf("reqCheck.TSAPolicyOID: got %x, want %x", reqCheck.TSAPolicyOID, asn1.ObjectIdentifier{2, 5, 6, 7})
			}
		})
	}
}

func BenchmarkCreateRequest(b *testing.B) {
	reader := strings.NewReader("Content to be time-stamped")

	for n := 0; n < b.N; n++ {
		_, _ = CreateRequest(reader, nil)
	}
}

func BenchmarkParseRequest(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = ParseRequest(reqNonce)
	}
}

func BenchmarkParseResponse(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = ParseResponse(respNonce)
	}
}

// ExampleCreateRequest demonstrates how to create a new time-stamping request
// for an io.Reader.
func ExampleCreateRequest() {
	_, err := CreateRequest(strings.NewReader("Content to be time-stamped"), nil)
	if err != nil {
		panic(err)
	}
}

// ExampleCreateRequest_customHashingAlgorithm demonstrates how to create a new
// time-stamping request with options
func ExampleCreateRequest_customHashingAlgorithm() {
	_, err := CreateRequest(
		strings.NewReader("Content to be time-stamped"),
		&RequestOptions{
			Hash: crypto.SHA512,
		})
	if err != nil {
		panic(err)
	}
}

// ExampleParseRequest demonstrates how to parse a raw der time-stamping request
func ExampleParseRequest() {
	// CreateRequest returns the request in der bytes
	createdRequest, err := CreateRequest(strings.NewReader("Content to be time-stamped"), nil)
	if err != nil {
		panic(err)
	}

	// ParseRequest parses a request in der bytes
	parsedRequest, err := ParseRequest(createdRequest)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%x\n", parsedRequest.HashedMessage)
	// Output: 51a3620a3b62ffaff41a434e932223b31bc69e86490c365fa1186033904f1132
}

func TestCreateResponseWithIncludeTSACertificate(t *testing.T) {
	tsakey := getTSARSAKey()
	tsaCert := getTSACert()

	h := sha256.New()
	_, err := h.Write([]byte("Hello World"))
	if err != nil {
		t.Fatal(err)
	}

	genTime := time.Now().UTC()

	nonce := big.NewInt(0)
	nonce = nonce.SetBytes([]byte{0x1, 0x2, 0x3})

	duration, _ := time.ParseDuration("1s")

	timestamp := Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     h.Sum(nil),
		Time:              genTime,
		Nonce:             nonce,
		Policy:            asn1.ObjectIdentifier{2, 4, 5, 6},
		Ordering:          true,
		Accuracy:          duration,
		Qualified:         true,
		AddTSACertificate: true,
	}
	timestampBytes, err := timestamp.CreateResponse(tsaCert, tsakey)
	if err != nil {
		t.Errorf("unable to generate time stamp response: %s", err.Error())
	}

	// To verify the reponse using OpenSSL
	// openssl ts -reply -in timestamp.tsr -text
	// _ = ioutil.WriteFile("timestamp.tsr", timestampBytes, 0644)

	timestampRes, err := ParseResponse(timestampBytes)
	if err != nil {
		t.Errorf("unable to parse time stamp response: %s", err.Error())
	}

	if timestampRes.HashAlgorithm.HashFunc() != crypto.SHA256 {
		t.Errorf("expected hash algorithm is SHA256")
	}
	if len(timestampRes.HashedMessage) != 32 {
		t.Errorf("got %d: expected: %d", len(timestampRes.HashedMessage), 32)
	}

	if timestampRes.Accuracy != duration {
		t.Errorf("got accuracy %s: expected: %s", timestampRes.Accuracy, duration)
	}

	if !timestampRes.Qualified {
		t.Errorf("got %t: expected: %t", timestampRes.Qualified, true)
	}

	if !timestampRes.AddTSACertificate {
		t.Error("TSA certificate must be included in timestamp response")
	}
}

func TestCreateResponseWithNoTSACertificate(t *testing.T) {
	tsakey := getTSARSAKey()
	tsaCert := getTSACert()

	h := sha256.New()
	_, err := h.Write([]byte("Hello World"))
	if err != nil {
		t.Fatal(err)
	}

	genTime := time.Now().UTC()

	nonce := big.NewInt(0)
	nonce = nonce.SetBytes([]byte{0x1, 0x2, 0x3})

	duration, _ := time.ParseDuration("1s")

	timestamp := Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     h.Sum(nil),
		Time:              genTime,
		Nonce:             nonce,
		Policy:            asn1.ObjectIdentifier{2, 4, 5, 6},
		Ordering:          true,
		Accuracy:          duration,
		Qualified:         false,
		AddTSACertificate: false,
	}
	timestampBytes, err := timestamp.CreateResponse(tsaCert, tsakey)
	if err != nil {
		t.Errorf("unable to generate time stamp response: %s", err.Error())
	}
	timestampRes, err := ParseResponse(timestampBytes)
	if err != nil {
		t.Errorf("unable to parse time stamp response: %s", err.Error())
	}

	if timestampRes.HashAlgorithm.HashFunc() != crypto.SHA256 {
		t.Errorf("expected hash algorithm is SHA256")
	}
	if len(timestampRes.HashedMessage) != 32 {
		t.Errorf("got %d: expected: %d", len(timestampRes.HashedMessage), 32)
	}

	if timestampRes.Qualified {
		t.Errorf("got %t: expected: %t", timestampRes.Qualified, true)
	}

	if timestampRes.AddTSACertificate {
		t.Error("TSA certificate must not be included in timestamp response")
	}
}

func getTSARSAKey() *rsa.PrivateKey {
	tsaRSAKeyPEM := `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEApeencH+4Wo3Ry65t2/FdZkHLyQcizv8Xu+4NTEGF502fPV2y
May4/ZU+GXeVTPhwfJuFj1D8Id6skgZ1DlAz+cpIqQQoaUuVM6M5MMJ6Ycf27KAs
knQiEMI7BcyJBni1c/aspLMd3AwPn/4XVweX+KL8FtbNouakKOvKT9MH23hUqJuY
aKxyxRABtuRYaq3PrAvR55gb/f/zLHvPh57vALi4J3WSIePXNpNzpOpZIj+J+UMQ
NQVWVPzRW7Wf057o9cvSl/P/eChKWIeMAsYE5+7Rybj7MnRi5XqDFDCdPLmHaT6/
ZcE6ijHSjoETi/Ut9BMOyIUqpQAs0uZH39FFwwIDAQABAoIBADuncUh9VD+TUQWJ
Ac2dGzVioTD2lOiTRuh3L2blBI3oFkMNhr5f2eCsojisDA4yIthbX4np188h7zFO
ixaLdjTyLHBBo3pBCDQaE71ZoIG6UipBaeV7Rqh5/pkWM4sVKkG5R9is4ya1W4Tu
61uKynVHvZdEw4o4nnxsVEGhouih5q/fmETi7XTCYSCe4gljVDtRpvFQBOrrhye/
BT38SvrXQR2WmgLLpfo+1VR5zcm9bXJXrkOKYNXWDxl9kpY+hwXD0IhTXl4GkqEe
8CP4WFHtX5WA4s9qLATp/zT7fme2Ojh+NkIdU0FMI9lf4pNX+URxii+hn15vrtCi
UxaSVtECgYEA0FobH8XOw7SWjJRs9wfLoF/Wl3s4ET9neJwx047Xlop8QAwHYzo7
CiEH+aodgr/UC8KM62+3y4pZgn3Bmt3/p/WyKOsfG3TZXqvuSGqTXO9sn3T1Z552
jVT/1/3qapHODL4ct52FHxrr243Jp2vfeMciU0tLdsx5FIgRCScqm0sCgYEAy9h/
qnDAC1fI4eEDYgj+kIUDyQegeKbi79U3aF5QjYSgvYm1pev/Zac8+x9X/zQupObB
FmgbtPYrXTY5J38qG/ELjDu7aHfXqgHcVTda0MsGsaoSCmaJ3y19ewxsmK9pFaEl
BUTmFd2hywK34RG00dyYcrvmP6M4OP/Do1+WPGkCgYEAv9lYhIcl/rr4rXW2aDk7
XO8ir9V8KRWS91IL51vuU+YsxuTMoKfr2UXVDCWCivSMElAQZnI2cStxhGC7txiX
4lawuFDYEfYkebIi9Xd9PeQQxztxBPq6+yS7eG2MPpkHfGBKHSDkhWHKsB39Azan
TZU/nCcG09sv2qH33c+8wcUCgYEAli3TqKNWqUSsZ9WZ43ES8zA8ILAwxpLVILKq
Foddu1VaAyngnPQofiDe6XgnIYq1TqH+4V4kA4dVXV/kbbffMyS8SD19jbK1PbgP
Nu0ISEk7jkro7aarrrPZ/XyiyT56IghNuPsQtE1LtMA07mlYGUD3Q5gxQvMiKcQs
w0FZ8vkCgYA7wuwLs7d9LJ4KqMNmOe0eRvIxp+Y8psxykMd1wz3PjdPz30U03xe2
o40r2ZNTK/OGYPmAOcwma7SjenBQve19eVUaECUVREmbvaJqVzz0uSrfqXrUVIiJ
YyOfhPUI5XhkyUlunO5pSAd0CtRv7NVW1wKDjMbJvgV0MlbVvGraAg==
-----END RSA PRIVATE KEY-----
`

	tsaKeyPEMBlock, _ := pem.Decode([]byte(tsaRSAKeyPEM))
	pvtKey, _ := x509.ParsePKCS1PrivateKey(tsaKeyPEMBlock.Bytes)

	return pvtKey
}

func getTSACert() *x509.Certificate {
	tsaCertPEM := `
-----BEGIN CERTIFICATE-----
MIIDmzCCAoOgAwIBAgIUTrgB1p7WpwYXjwGs/uwfKJt4cFcwDQYJKoZIhvcNAQEL
BQAwXTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEWMBQGA1UEAwwNVGVzdCBSU0EgQ2Vy
dDAeFw0yMDAzMDQyMjA4MDVaFw00MDAyMjgyMjA4MDVaMF0xCzAJBgNVBAYTAkFV
MRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRz
IFB0eSBMdGQxFjAUBgNVBAMMDVRlc3QgUlNBIENlcnQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCl56dwf7hajdHLrm3b8V1mQcvJByLO/xe77g1MQYXn
TZ89XbIxrLj9lT4Zd5VM+HB8m4WPUPwh3qySBnUOUDP5ykipBChpS5Uzozkwwnph
x/bsoCySdCIQwjsFzIkGeLVz9qyksx3cDA+f/hdXB5f4ovwW1s2i5qQo68pP0wfb
eFSom5horHLFEAG25Fhqrc+sC9HnmBv9//Mse8+Hnu8AuLgndZIh49c2k3Ok6lki
P4n5QxA1BVZU/NFbtZ/Tnuj1y9KX8/94KEpYh4wCxgTn7tHJuPsydGLleoMUMJ08
uYdpPr9lwTqKMdKOgROL9S30Ew7IhSqlACzS5kff0UXDAgMBAAGjUzBRMB0GA1Ud
DgQWBBSI1Fk3y/DpAQwRXhoqRhjeQRsoCjAfBgNVHSMEGDAWgBSI1Fk3y/DpAQwR
XhoqRhjeQRsoCjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAP
+jK6M/zPFrO/hrXOXlfEntbKwxFWoil/BRVMkgMp6JO44wn9QS+oRIVKcMToTPe5
XaU4D8YgHPFiyhaTOQ95RDVZuy5VPf1li1oujPHXP6Y9Ps5RF9AKtLYdJa8ZBmRx
Cg3mHV4f6VJWziWz3s5n6DVQ5DDrSkQ0dIRs5Tu9W4+aHJUMwdkSP0klvBnlzPhq
kl++ygWDU5bJMbwD53eGieJyo5wL0SR08ijiGxCTmYOUuPl/C62MTPJU+oR8qRd3
I/rCr/gywfHmAbgupBo9ikC9rrYD5maaC59xr4NjjI1vSeS3nrO9qmd9KnGD98P8
wA4N9tN/F776b2RG2RZD
-----END CERTIFICATE-----
`
	certPEMBlock, _ := pem.Decode([]byte(tsaCertPEM))
	tsaCert, _ := x509.ParseCertificate(certPEMBlock.Bytes)

	return tsaCert
}
