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
	// Output: 62633c3232115454963ce641e5095c48a85dbec913a08332ad38586b910a3b27
}
