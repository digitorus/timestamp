package timestamp_test

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/digitorus/timestamp"
)

// ExampleCreateRequest_ParseResponse demonstrates the creation of a time-stamp request, sending
// it to the server and parsing the response.
// nolint: govet
func ExampleCreateRequest_ParseResponse() {
	tsq, err := timestamp.CreateRequest(strings.NewReader("ExampleCreateRequestParseResponse"), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	tsr, err := http.Post("https://freetsa.org/tsr", "application/timestamp-query", bytes.NewReader(tsq))
	if err != nil {
		log.Fatal(err)
	}

	if tsr.StatusCode > 200 {
		log.Fatal(tsr.Status)
	}

	resp, err := io.ReadAll(tsr.Body)
	if err != nil {
		log.Fatal(err)
	}

	tsResp, err := timestamp.ParseResponse(resp)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(tsResp.HashedMessage)
	fmt.Println(tsResp.Policy)
	for _, c := range tsResp.Certificates {
		fmt.Println(c.Subject.Organization, c.Subject.OrganizationalUnit)
	}

	// Output:
	// [140 222 43 143 28 80 96 97 4 176 145 205 188 119 197 142 149 101 26 96 188 163 178 64 230 162 199 171 176 178 173 128]
	// 1.2.3.4.1
	// [Free TSA] [TSA]
	// [Free TSA] [Root CA]

}
