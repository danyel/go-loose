package password

import "testing"

func TestHashAndVerify(t *testing.T) {
	encoded, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !Verify(encoded, "correct horse battery staple") {
		t.Fatal("expected password to verify")
	}
	if Verify(encoded, "incorrect password") {
		t.Fatal("expected incorrect password to fail")
	}
}

func TestHashRejectsShortPassword(t *testing.T) {
	if _, err := Hash("too-short"); err == nil {
		t.Fatal("expected short password to fail")
	}
}
