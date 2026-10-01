package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

func Encrypt(master, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(master))
	if err != nil {
		return nil, fmt.Errorf("create secret cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create secret AEAD: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate secret nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, []byte(plaintext), []byte("go-loose-oidc-v1")), nil
}

func Decrypt(master string, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(deriveKey(master))
	if err != nil {
		return "", fmt.Errorf("create secret cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create secret AEAD: %w", err)
	}
	if len(ciphertext) < aead.NonceSize() {
		return "", errors.New("encrypted secret is truncated")
	}
	nonce, sealed := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, []byte("go-loose-oidc-v1"))
	if err != nil {
		return "", errors.New("encrypted secret cannot be opened")
	}
	return string(plaintext), nil
}

func deriveKey(master string) []byte {
	sum := sha256.Sum256([]byte("go-loose/oidc/" + master))
	return sum[:]
}
