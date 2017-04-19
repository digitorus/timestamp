package timestamp

import (
	"fmt"
	"strings"
)

// ExampleCreateRequest demonstrates how to create a new time-stamping request
// for an io.Reader.
func ExampleCreateRequest() {
	_, err := CreateRequest(strings.NewReader("Content to by time-stamped"), nil)
	if err != nil {
		panic(err)
	}
}

// ExampleParseRequest demonstrates how to parse a raw der time-stamping request
func ExampleParseRequest() {
	// CreateRequest returns the request in der bytes
	createdRequest, err := CreateRequest(strings.NewReader("Content to by time-stamped"), nil)
	if err != nil {
		panic(err)
	}

	// ParseRequest parses a request in der bytes
	parsedRequest, err := ParseRequest(createdRequest)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%x\n", parsedRequest.HashedMessage)
	// Output: b4f6bd939c616808842180e3d5d466f86df2dcd209f14a1337b88d39ce4c021f
}
