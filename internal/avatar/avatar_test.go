package avatar

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

func samplePNG(t *testing.T, width, height int) []byte {
	t.Helper()
	canvas := image.NewRGBA(image.Rect(0, 0, width, height))
	canvas.Set(0, 0, color.RGBA{R: 125, G: 207, B: 255, A: 255})
	buffer := &bytes.Buffer{}
	if err := png.Encode(buffer, canvas); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buffer.Bytes()
}

func encode(t *testing.T, format string, width, height int) []byte {
	t.Helper()
	canvas := image.NewRGBA(image.Rect(0, 0, width, height))
	buffer := &bytes.Buffer{}
	var err error
	switch format {
	case "jpeg":
		err = jpeg.Encode(buffer, canvas, nil)
	case "gif":
		err = gif.Encode(buffer, canvas, nil)
	default:
		err = png.Encode(buffer, canvas)
	}
	if err != nil {
		t.Fatalf("encode %s: %v", format, err)
	}
	return buffer.Bytes()
}

func TestParseAcceptsSupportedFormats(t *testing.T) {
	for _, format := range []string{"png", "jpeg", "gif"} {
		t.Run(format, func(t *testing.T) {
			raw := encode(t, format, 8, 8)
			data, contentType, err := Parse(base64.StdEncoding.EncodeToString(raw))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !bytes.Equal(data, raw) {
				t.Fatal("Parse() did not return the uploaded bytes")
			}
			if contentType != "image/"+map[string]string{"png": "png", "jpeg": "jpeg", "gif": "gif"}[format] {
				t.Fatalf("content type = %q", contentType)
			}
		})
	}
}

func TestParseAcceptsDataURL(t *testing.T) {
	raw := samplePNG(t, 4, 4)
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw)
	data, contentType, err := Parse(dataURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(data) != len(raw) || contentType != "image/png" {
		t.Fatalf("Parse() = %d bytes of %q", len(data), contentType)
	}
}

func TestParseRejectsMismatchedDataURLMediaType(t *testing.T) {
	raw := samplePNG(t, 4, 4)
	dataURL := "data:image/gif;base64," + base64.StdEncoding.EncodeToString(raw)
	if _, _, err := Parse(dataURL); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupported)
	}
}

func TestParseRejectsNonBase64DataURL(t *testing.T) {
	raw := samplePNG(t, 4, 4)
	dataURL := "data:image/png," + base64.StdEncoding.EncodeToString(raw)
	if _, _, err := Parse(dataURL); !errors.Is(err, ErrEmpty) {
		t.Fatalf("error = %v, want %v", err, ErrEmpty)
	}
}

func TestParseRejectsMalformedAndUnsupportedInput(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  error
	}{
		{name: "empty", value: "   ", want: ErrEmpty},
		{name: "not base64", value: "!!!not base64!!!", want: ErrEncoding},
		{name: "plain text", value: base64.StdEncoding.EncodeToString([]byte("hello world, not an image")), want: ErrUnsupported},
		{name: "svg", value: base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)), want: ErrUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := Parse(test.value); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseRejectsOversizedUploads(t *testing.T) {
	huge := base64.StdEncoding.EncodeToString(make([]byte, MaxBytes+1))
	if _, _, err := Parse(huge); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want %v", err, ErrTooLarge)
	}
}

func TestInspectRejectsDecompressionBombs(t *testing.T) {
	oversized := samplePNG(t, 1, MaxDimension+1)
	if _, err := Inspect(oversized); !errors.Is(err, ErrDimensions) {
		t.Fatalf("error = %v, want %v", err, ErrDimensions)
	}
	raw := samplePNG(t, MaxDimension, MaxDimension)
	if _, err := Inspect(raw); err != nil {
		t.Fatalf("Inspect() rejected the maximum size: %v", err)
	}
}

func TestInspectRejectsEmptyBytes(t *testing.T) {
	if _, err := Inspect(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("error = %v, want %v", err, ErrEmpty)
	}
}

func TestNewKeyIsUnguessableAndValid(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		key, err := NewKey()
		if err != nil {
			t.Fatalf("NewKey() error = %v", err)
		}
		if !ValidKey(key) {
			t.Fatalf("NewKey() produced an invalid key %q", key)
		}
		if seen[key] {
			t.Fatal("NewKey() repeated a key")
		}
		seen[key] = true
	}
}

func TestValidKeyRejectsMalformedLocators(t *testing.T) {
	tests := []string{"", "short", "../etc/passwd", string(bytes.Repeat([]byte("a"), 44)), "a/b+c="}
	for _, test := range tests {
		if ValidKey(test) {
			t.Fatalf("ValidKey(%q) = true", test)
		}
	}
}

func TestETagIsStableAndContentDerived(t *testing.T) {
	first, second := samplePNG(t, 4, 4), samplePNG(t, 5, 5)
	if ETag(first) != ETag(first) {
		t.Fatal("ETag is not stable for identical content")
	}
	if ETag(first) == ETag(second) {
		t.Fatal("ETag must change when the content changes")
	}
	if tag := ETag(first); len(tag) < 3 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		t.Fatalf("ETag = %q, want a quoted validator", tag)
	}
}
