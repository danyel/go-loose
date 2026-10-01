package key

import (
	"bytes"
	"testing"
)

func TestGenerate(t *testing.T) {
	plain, prefix, hash, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if err := ValidateFormat(plain); err != nil {
		t.Fatalf("generated key is invalid: %v", err)
	}
	if prefix != plain[:11] {
		t.Fatalf("prefix = %q", prefix)
	}
	if !bytes.Equal(hash, Hash(plain)) {
		t.Fatal("hash mismatch")
	}
}
