package secretbox

import "testing"

func TestRoundTrip(t *testing.T) {
	ciphertext, err := Encrypt("01234567890123456789012345678901", "client-secret")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	plaintext, err := Decrypt("01234567890123456789012345678901", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if plaintext != "client-secret" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if _, err := Decrypt("different-master-secret-value-0000", ciphertext); err == nil {
		t.Fatal("expected wrong key to fail")
	}
}
