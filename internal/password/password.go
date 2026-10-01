package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memory      = 64 * 1024
	iterations  = 3
	parallelism = 2
	saltLength  = 16
	keyLength   = 32
)

func Hash(value string) (string, error) {
	if len(value) < 12 {
		return "", errors.New("password must contain at least 12 characters")
	}
	return hash(value)
}

// HashDemo hashes intentionally weak, local-only seed credentials.
func HashDemo(value string) (string, error) {
	if value == "" {
		return "", errors.New("demo password is empty")
	}
	return hash(value)
}

func hash(value string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(value), salt, iterations, memory, parallelism, keyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func Verify(encoded, value string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var parsedMemory uint64
	var parsedIterations uint64
	var parsedParallelism uint64
	for _, setting := range strings.Split(parts[3], ",") {
		keyValue := strings.SplitN(setting, "=", 2)
		if len(keyValue) != 2 {
			return false
		}
		number, err := strconv.ParseUint(keyValue[1], 10, 32)
		if err != nil {
			return false
		}
		switch keyValue[0] {
		case "m":
			parsedMemory = number
		case "t":
			parsedIterations = number
		case "p":
			parsedParallelism = number
		}
	}
	if parsedMemory == 0 || parsedMemory > 256*1024 || parsedIterations == 0 || parsedIterations > 10 || parsedParallelism == 0 || parsedParallelism > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 {
		return false
	}
	actual := argon2.IDKey([]byte(value), salt, uint32(parsedIterations), uint32(parsedMemory), uint8(parsedParallelism), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
