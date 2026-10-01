package contract

import "testing"

func TestParseYAML(t *testing.T) {
	document, err := Parse([]byte(`openapi: 3.1.0
paths:
  /guesses:
    get:
      operationId: listGuesses
    post:
      operationId: createGuess
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if document.Version != "3.1.0" || len(document.Endpoints) != 2 {
		t.Fatalf("unexpected document: %#v", document)
	}
}

func TestValidateSourceURLRejectsLoopback(t *testing.T) {
	if _, err := ValidateSourceURL("http://127.0.0.1/openapi.json", false); err == nil {
		t.Fatal("expected loopback URL to be rejected")
	}
}
