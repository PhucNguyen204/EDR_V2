package matcher

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestStringModifiersBasic(t *testing.T) {
	reg := map[string]ModifierFn{}
	RegisterStringModifiers(reg)

	lower := reg["lowercase"]
	got, _ := lower("HELLO")
	if got != "hello" {
		t.Fatalf("lowercase: want hello, got %q", got)
	}

	trim := reg["trim"]
	got, _ = trim("  hello  ")
	if got != "hello" {
		t.Fatalf("trim: want hello, got %q", got)
	}
}

func TestEncodingModifiers(t *testing.T) {
	reg := map[string]ModifierFn{}
	RegisterEncodingModifiers(reg)

	urlDec := reg["url_decode"]
	got, err := urlDec("hello%20world")
	if err != nil {
		t.Fatalf("url_decode err: %v", err)
	}
	if got != "hello world" { // Go thực hiện decode đúng
		t.Fatalf("url_decode: want 'hello world', got %q", got)
	}

	base64Dec := reg["base64_decode"]
	out, err := base64Dec("aGVsbG8=")
	if err != nil || out != "hello" {
		t.Fatalf("base64 decode failed: out=%q err=%v", out, err)
	}
}

func TestFormatModifiers(t *testing.T) {
	reg := map[string]ModifierFn{}
	RegisterFormatModifiers(reg)

	hexEnc := reg["hex_encode"]
	enc, _ := hexEnc("hello")
	if enc != "68656c6c6f" {
		t.Fatalf("hex encode: want 68656c6c6f, got %q", enc)
	}

	hexDec := reg["hex_decode"]
	dec, err := hexDec(enc)
	if err != nil || dec != "hello" {
		t.Fatalf("hex decode roundtrip failed: dec=%q err=%v", dec, err)
	}

	jsonNorm := reg["json_normalize"]
	norm, _ := jsonNorm("{\n\t\"a\": 1  }")
	if strings.Contains(norm, "\n") || strings.Contains(norm, "\t") {
		t.Fatalf("json_normalize did not strip whitespace: %q", norm)
	}
}

func TestAdvancedModifiers(t *testing.T) {
	reg := map[string]ModifierFn{}
	RegisterAdvancedModifiers(reg)

	md5f := reg["md5"]
	md5sum, _ := md5f("hello")
	if md5sum != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("md5 mismatch: %q", md5sum)
	}

	sha1f := reg["sha1"]
	sha1sum, _ := sha1f("hello")
	if sha1sum != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" {
		t.Fatalf("sha1 mismatch: %q", sha1sum)
	}

	sha256f := reg["sha256"]
	sha256sum, _ := sha256f("hello")
	if sha256sum != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha256 mismatch: %q", sha256sum)
	}

	// gzip_decode: test “lenient” – nếu không phải gzip, trả về nguyên văn
	gzipDec := reg["gzip_decode"]
	out, err := gzipDec("not-gzip")
	if err != nil || out != "not-gzip" {
		t.Fatalf("gzip_decode lenient failed: out=%q err=%v", out, err)
	}
}

func TestComprehensiveRegistration(t *testing.T) {
	reg := map[string]ModifierFn{}
	RegisterComprehensiveModifiers(reg)

	// Spot-check một số key quan trọng
	keys := []string{
		"base64_decode", "url_decode", "html_decode",
		"hex_encode", "hex_decode",
		"uppercase", "lowercase", "trim",
		"normalize_path",
		"to_int", "md5", "sha256",
	}
	for _, k := range keys {
		if _, ok := reg[k]; !ok {
			t.Fatalf("missing modifier: %s", k)
		}
	}
	if len(reg) < 20 {
		t.Fatalf("expected many modifiers, got %d", len(reg))
	}
}

func TestBase64OffsetDecode(t *testing.T) {
	reg := map[string]ModifierFn{}
	RegisterEncodingModifiers(reg)
	f := reg["base64offset_decode"]

	// Thêm một ký tự offset trước base64 (ví dụ 'x')
	orig := "hello"
	enc := base64.StdEncoding.EncodeToString([]byte(orig))
	withOffset := "x" + enc

	out, err := f(withOffset)
	if err != nil || out != orig {
		t.Fatalf("base64offset failed: out=%q err=%v (enc=%q)", out, err, withOffset)
	}
}

func TestStringTransformationHelpers(t *testing.T) {
	reg := map[string]ModifierFn{}
	RegisterStringModifiers(reg)

	upper := reg["uppercase"]
	lower := reg["lowercase"]
	trim := reg["trim"]

	if x, _ := upper("abc"); x != "ABC" {
		t.Fatalf("uppercase mismatch: %q", x)
	}
	if x, _ := lower("ABC"); x != "abc" {
		t.Fatalf("lowercase mismatch: %q", x)
	}
	if x, _ := trim("  x "); x != "x" {
		t.Fatalf("trim mismatch: %q", x)
	}
}
