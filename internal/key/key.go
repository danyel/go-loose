package key

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const Prefix = "gl_"

func Generate() (plain, displayPrefix string, hash []byte, err error) {
	return GenerateToken(Prefix)
}

func GenerateToken(prefix string) (plain, displayPrefix string, hash []byte, err error) {
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return "", "", nil, err
	}
	plain = prefix + base64.RawURLEncoding.EncodeToString(random)
	displayPrefix = plain[:min(len(plain), 11)]
	hash = Hash(plain)
	return plain, displayPrefix, hash, nil
}

func Hash(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

func ValidateFormat(plain string) error {
	if !strings.HasPrefix(plain, Prefix) || len(plain) < 40 {
		return errors.New("invalid API key format")
	}
	return nil
}
