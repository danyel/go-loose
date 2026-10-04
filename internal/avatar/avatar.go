// Package avatar validates and addresses profile pictures stored in PostgreSQL.
//
// Images are kept as their uploaded bytes. Go Loose never re-encodes them; it
// sniffs the format, bounds the decoded dimensions to reject decompression
// bombs, and serves the bytes back with the sniffed content type behind an
// unguessable key so that other applications can embed the picture with a plain
// image tag.
package avatar

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"
)

const (
	// MaxBytes bounds an uploaded picture. Base64 inflates it by 4/3, so a
	// request carrying an avatar must allow roughly MaxBytes*4/3 bytes.
	MaxBytes = 2 << 20
	// MaxDimension bounds decoded pixels so that a small upload cannot expand
	// into an unreasonable image when a client renders it.
	MaxDimension = 4096
)

var (
	ErrEmpty       = errors.New("the picture is empty")
	ErrTooLarge    = fmt.Errorf("the picture must be %d KiB or smaller", MaxBytes/1024)
	ErrUnsupported = errors.New("the picture must be a JPEG, PNG, or GIF image")
	ErrDimensions  = fmt.Errorf("the picture must not exceed %d by %d pixels", MaxDimension, MaxDimension)
	ErrEncoding    = errors.New("the picture is not valid base64")
)

// allowed maps the format names reported by image.DecodeConfig to content types.
// Only the decoders registered above are accepted, so an unsupported upload
// fails validation instead of being stored and served.
var allowed = map[string]string{
	"jpeg": "image/jpeg",
	"png":  "image/png",
	"gif":  "image/gif",
}

// Parse decodes a base64 payload, with or without a data URL prefix, and
// returns the image bytes together with the sniffed content type.
func Parse(value string) ([]byte, string, error) {
	payload, declared := trimDataURL(value)
	if payload == "" {
		return nil, "", ErrEmpty
	}
	if base64.StdEncoding.DecodedLen(len(payload)) > MaxBytes {
		return nil, "", ErrTooLarge
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, "", ErrEncoding
	}
	contentType, err := Inspect(data)
	if err != nil {
		return nil, "", err
	}
	if declared != "" && !strings.EqualFold(declared, contentType) {
		return nil, "", ErrUnsupported
	}
	return data, contentType, nil
}

// Inspect validates raw image bytes and returns their content type.
func Inspect(data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrEmpty
	}
	if len(data) > MaxBytes {
		return "", ErrTooLarge
	}
	decoded, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "", ErrUnsupported
	}
	contentType, known := allowed[format]
	if !known {
		return "", ErrUnsupported
	}
	if decoded.Width > MaxDimension || decoded.Height > MaxDimension {
		return "", ErrDimensions
	}
	return contentType, nil
}

// NewKey returns an unguessable locator for a stored picture. The key is a
// capability-free random value: it authorizes reading a picture that is
// intended to be public, not access to anything else about the user.
func NewKey() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate avatar key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// ValidKey reports whether a key has the shape produced by NewKey, which keeps
// obviously malformed lookups out of the database.
func ValidKey(key string) bool {
	if len(key) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(key)
	return err == nil
}

// ETag returns a strong validator derived from the stored bytes so that clients
// and proxies can cache the picture and revalidate cheaply.
func ETag(data []byte) string {
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func trimDataURL(value string) (payload, mediaType string) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(value), "data:") {
		return value, ""
	}
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return "", ""
	}
	header := value[len("data:"):comma]
	parameters := strings.Split(header, ";")
	mediaType = strings.ToLower(strings.TrimSpace(parameters[0]))
	for _, parameter := range parameters[1:] {
		if strings.EqualFold(strings.TrimSpace(parameter), "base64") {
			return strings.TrimSpace(value[comma+1:]), mediaType
		}
	}
	return "", ""
}
