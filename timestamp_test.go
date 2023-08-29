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

var respRejection = []byte{0x30, 0x35, 0x30, 0x33, 0x2, 0x1, 0x2, 0x30, 0x28, 0xc, 0x26, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x64, 0x75, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x20, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x20, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x3, 0x4, 0x6, 0x0, 0x0, 0x40}

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

func TestParseResponseRejection(t *testing.T) {
	_, err := ParseResponse(respRejection)
	if err == nil {
		t.Errorf("failed to parse response with rejection: %s", err.Error())
	}
	expected := "the request is rejected: Error during serial number generation. (the additional information requested could not be understood or is not available)"
	if err.Error() != expected {
		t.Errorf("unexpected error message:\n\t%s\nexpected:\n\t%s\n", err.Error(), expected)
	}
}

func TestCreateErrorResponse(t *testing.T) {
	resp, err := CreateErrorResponse(Rejection, TimeNotAvailable)
	if err != nil {
		t.Errorf("failed to create error: %s", err.Error())
	}

	expected := "the request is rejected:  (the TSA's time source is not available)"
	_, err = ParseResponse(resp)
	if err.Error() != expected {
		t.Errorf("unexpected error message:\n\t%s\nexpected:\n\t%s\n", err.Error(), expected)
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
		t.Fatalf("unable to parse time stamp response: %s", err.Error())
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
	// _ = os.WriteFile("timestamp.tsr", timestampBytes, 0644)

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

// Sign with TSU and do not embed certificates
func TestSignWithTSUNoCertificate(t *testing.T) {
	tsukey := getTSURSAKey()
	tsuCert := getTSUCert()

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
	timestampBytes, err := timestamp.CreateResponse(tsuCert, tsukey)
	if err != nil {
		t.Errorf("unable to generate time stamp response: %s", err.Error())
	}
	timestampRes, err := ParseResponse(timestampBytes)
	if err != nil {
		t.Fatalf("unable to parse time stamp response: %s", err.Error())
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
		t.Error("TSU certificate must not be included in timestamp response")
	}
}

// Sign with TSU and only embed TSU certificate
func TestSignWithTSUEmbedTSUCertificate(t *testing.T) {
	tsukey := getTSURSAKey()
	tsuCert := getTSUCert()

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
	timestampBytes, err := timestamp.CreateResponse(tsuCert, tsukey)
	if err != nil {
		t.Errorf("unable to generate time stamp response: %s", err.Error())
	}

	timestampRes, err := ParseResponse(timestampBytes)
	if err != nil {
		t.Fatalf("unable to parse time stamp response: %s", err.Error())
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
		t.Error("TSU certificate must be included in timestamp response")
	}
}

// Sign with TSU and include certificate chain
func TestSignWithTSUIncludeCertificateChain(t *testing.T) {
	tsuKey := getTSURSAKey()
	tsuCert := getTSUCert()
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
		Certificates:      []*x509.Certificate{tsaCert}, // add parent certificate
	}
	timestampBytes, err := timestamp.CreateResponse(tsuCert, tsuKey)
	if err != nil {
		t.Fatalf("unable to generate time stamp response: %s", err.Error())
	}

	timestampRes, err := ParseResponse(timestampBytes)
	if err != nil {
		t.Fatalf("unable to parse time stamp response: %s", err.Error())
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

	if !timestamp.Certificates[0].Equal(tsaCert) {
		t.Errorf("got certificate %X: expected: %X", timestamp.Certificates[0].SubjectKeyId, tsaCert.SubjectKeyId)
	}
}

func getTSURSAKey() *rsa.PrivateKey {
	tsuRSAKeyPEM := `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7FzZ2Uff6dPKEgJNgUi3EL21y3CzY3zGE3Wi2pTM1oGAMetP
ecEdFnMM2x76lnGuBk0VW04TdOMymXtW6L7X75Yr73/88b4Ycmrg2Xh/HqiCrtQZ
PrCwOn3V8UFulySqJItBUZ1ih6a0A1NNX6lMmQTbbuxLlyP4iz1HveFmOa/gkLh9
Y1I9yIRTb4Mlm6yISLQkDZn2YMXqlZUv4tyNUmFlSYrMu6lsIwBn2eaBKzQYPZM0
ExuTDD+d7RnrDr1tcfd5cNOq7XDNP2nIDE4rZSwRhOerDKPL9jqd60FKH40oX51/
WssiO1zVmi43uX8gr7iaJrzpkVNDN9m41zLheQIDAQABAoIBAQDA21odghnfjqGY
ZCydSpmknUaSgpi8mnh8NEX3F+azN+ND1/53F+0F/kYFHJfW3VbjaU39vA0AGMmW
lh7ptZ43rU6YEtRu427LHQ3uI/WFLHXE9ObMUhrY/wfr3DnCNXZmbwGS+FoG2SyU
cgn1/guz51Ssgz2CSyVnZ078Tce9VISolxGnxZVhEVcssFazEWLaOe/8t2rMg4e+
RRGiaTcIkTdNTFgk15JrkSRyvU/538vVwNJ67hAwlA011l3XDpVybwEQQ46bG09J
uSNOEm4XMNRxjPS6A2Fd+jtSiP4iYEwVoJU+/P7IRdoVvBjwcXnl7tX9i7o8xwhr
es+NzS8BAoGBAOxxSLk8QVYGoHn+H/I+SHBY8ipY/3mwCzH3shodfAejZ+eoMVI+
cWJl67QKhsFzlAfRj1YF92h5Hx8oXVR7te7KcjXVyStPlAUigls253GaczSnXjA0
0WxpFthES8TSbSfD1VTbU1JB6evUe8KkemEw+9vbl573U3FgEeu67LnxAoGBAP/p
4HNC2JTFGox7IJoEvO2qeJfxtlyJ5vb/RwlJu/kn7mAFzzjIE1xYFDbImKN8OYA4
BWXyZ+5WP+HZOBW16HXoYybT02ufFC3lp9p8xOSBs2DQKfrhqgJTOVjq7b4ovSj5
3DOnR1YojbiDHQpK2IVIj1Iz0DiIFqPhtB7CzdgJAoGANC3f7bkldhWqTqHNbQlf
tSN79eqEHtfB8LoIHQlKuOjP4mjU0aCkJyH0/VuhV4npLjyKFGLmsbChNKAU0LMo
eFVHFShj5+H8+ZEfEYAxXXnHWORiveK6IOGkP//6dKo3mqH2L27jmXCgbgILee4Q
b+h+fIuej19nk8quycYLvhECgYAwoJsyq6AF3NInoXnXalEQBBV4IcjaGqYVhvpT
jHw4YtsLye7PRk1PfbkRk9pVLlSqxXpZHc+b3S20V5ctoOw0A11b0mJZD9hAxGO5
w32SQgb4vXVMo7avTGsYN0PHn2waLigmdIG8oGYVimxpOUGdSeVZ5FiLdWh/6XJV
agS9KQKBgGn6Gfp9/67F0zgJ5gh5DsuY6At9VcGnSPmKaO//ME05KMazF6XW2gWs
/VmHEjBRBqXPylh3xmr5DMm95OeQm3QUsNf75aPFnkukRmgmeVIfICjx0twzls4O
vwxcYS6/uRJ1O1K0U2KZgqY9HGSg4Mm4Zs8mAe86evHEGX7g7N6y
-----END RSA PRIVATE KEY-----
`

	tsuKeyPEMBlock, _ := pem.Decode([]byte(tsuRSAKeyPEM))
	pvtKey, _ := x509.ParsePKCS1PrivateKey(tsuKeyPEMBlock.Bytes)

	return pvtKey
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
func getTSUCert() *x509.Certificate {
	tsaCertPEM := `
-----BEGIN CERTIFICATE-----
MIIDrTCCApWgAwIBAgITHtUKVw2T5tfI4jk7zfJvKj39MDANBgkqhkiG9w0BAQsF
ADBdMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRYwFAYDVQQDDA1UZXN0IFJTQSBDZXJ0
MB4XDTIyMTAxODA2MzYxNloXDTQyMTAxODA2MzYxNlowYzELMAkGA1UEBhMCQVUx
EzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAsTGEludGVybmV0IFdpZGdpdHMg
UHR5IEx0ZDEcMBoGA1UEAxMTVGVzdCBSU0EgQ2hpbGQgQ2VydDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAOxc2dlH3+nTyhICTYFItxC9tctws2N8xhN1
otqUzNaBgDHrT3nBHRZzDNse+pZxrgZNFVtOE3TjMpl7Vui+1++WK+9//PG+GHJq
4Nl4fx6ogq7UGT6wsDp91fFBbpckqiSLQVGdYoemtANTTV+pTJkE227sS5cj+Is9
R73hZjmv4JC4fWNSPciEU2+DJZusiEi0JA2Z9mDF6pWVL+LcjVJhZUmKzLupbCMA
Z9nmgSs0GD2TNBMbkww/ne0Z6w69bXH3eXDTqu1wzT9pyAxOK2UsEYTnqwyjy/Y6
netBSh+NKF+df1rLIjtc1ZouN7l/IK+4mia86ZFTQzfZuNcy4XkCAwEAAaNgMF4w
DgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCFNxjsFpw4I
5p+o62/J17zDEa8FMB8GA1UdIwQYMBaAFIjUWTfL8OkBDBFeGipGGN5BGygKMA0G
CSqGSIb3DQEBCwUAA4IBAQCYdgikay21S2fYz+mk3dnhUPLnXI9Gg6U9ox2js+Yf
dYOMXX5RlG2HKOEnVI7mOPEaEiSAuvE8x6mQ52xVOw4FWjPO7S5pCBO8YPyyZCer
5bOFhz/zbv7xpZISvTTPfOXqSM1MvkcX9kfPDRagGfB6viVQwhWMQK4Sd0d5wSf2
FHsUAuq+EauBDgTe4bdCMS/AQSF/xhFL1KUwvkI8HjDE+JGu7hexWtlxwD/dnvpD
6ZrUnRLuSF3jebNb2DwIXb05ub+YJoBx/0I/zYe3vWISDtO/onNAZz9hnmAzL32f
69EW22PQaOUDtTbfT2PD09uTUfmA+zZggjPgaWjbw+gf
-----END CERTIFICATE-----
`
	certPEMBlock, _ := pem.Decode([]byte(tsaCertPEM))
	tsaCert, _ := x509.ParseCertificate(certPEMBlock.Bytes)

	return tsaCert
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
