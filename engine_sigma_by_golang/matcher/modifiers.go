package matcher

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// Đăng ký đầy đủ tất cả modifiers vào registry.
func RegisterComprehensiveModifiers(reg map[string]ModifierFn) {
	RegisterEncodingModifiers(reg)
	RegisterStringModifiers(reg)
	RegisterFormatModifiers(reg)
	RegisterNumericModifiers(reg)
	RegisterAdvancedModifiers(reg)
}

// --- Encoding / Decoding ---

func RegisterEncodingModifiers(reg map[string]ModifierFn) {
	reg["base64_decode"] = createBase64Decode()
	reg["base64"] = reg["base64_decode"] // alias

	reg["base64offset_decode"] = createBase64OffsetDecode()

	reg["url_decode"] = createURLDecode()
	reg["url_encode"] = createURLEncode()

	reg["html_decode"] = createHTMLDecode()

	reg["utf16_decode"] = createUTF16Decode()
	reg["utf16le_decode"] = createUTF16LEDecode()
	reg["utf16be_decode"] = createUTF16BEDecode()

	reg["wide_decode"] = createWideDecode()
}

func createBase64Decode() ModifierFn {
	return func(input string) (string, error) {
		b, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("base64 decode failed: %w", err)
		}
		return string(b), nil
	}
}

func createBase64OffsetDecode() ModifierFn {
	return func(input string) (string, error) {
		for offset := 0; offset < 4; offset++ {
			if offset > len(input) {
				break
			}
			part := input[offset:]
			if b, err := base64.StdEncoding.DecodeString(part); err == nil {
				return string(b), nil
			}
		}
		return "", errors.New("base64 offset decode failed")
	}
}

func createURLDecode() ModifierFn {
	return func(input string) (string, error) {
		// Không giả định query vs path; thử cả hai.
		if s, err := url.QueryUnescape(input); err == nil {
			return s, nil
		}
		// Fallback nhẹ: thay %xx thủ công
		var out strings.Builder
		for i := 0; i < len(input); i++ {
			if input[i] == '%' && i+2 < len(input) {
				if v, err := strconv.ParseUint(input[i+1:i+3], 16, 8); err == nil {
					out.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			out.WriteByte(input[i])
		}
		return out.String(), nil
	}
}

func createURLEncode() ModifierFn {
	return func(input string) (string, error) {
		// Encode theo RFC3986 cho path segment-ish
		var out strings.Builder
		for _, r := range input {
			if (r >= 'A' && r <= 'Z') ||
				(r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9') ||
				strings.ContainsRune("-_.~", r) {
				out.WriteRune(r)
			} else {
				// encode theo UTF-8
				var buf [4]byte
				n := copy(buf[:], []byte(string(r)))
				for i := 0; i < n; i++ {
					out.WriteString(fmt.Sprintf("%%%02X", buf[i]))
				}
			}
		}
		return out.String(), nil
	}
}

func createHTMLDecode() ModifierFn {
	return func(input string) (string, error) {
		return html.UnescapeString(input), nil
	}
}

func createUTF16Decode() ModifierFn   { return func(s string) (string, error) { return s, nil } }
func createUTF16LEDecode() ModifierFn { return func(s string) (string, error) { return s, nil } }
func createUTF16BEDecode() ModifierFn { return func(s string) (string, error) { return s, nil } }

func createWideDecode() ModifierFn {
	return func(input string) (string, error) {
		// Loại bỏ các '\x00' theo kiểu wide-char đơn giản
		return strings.ReplaceAll(input, "\x00", ""), nil
	}
}

// --- String transforms ---

func RegisterStringModifiers(reg map[string]ModifierFn) {
	reg["lowercase"] = func(s string) (string, error) { return strings.ToLower(s), nil }
	reg["uppercase"] = func(s string) (string, error) { return strings.ToUpper(s), nil }
	reg["trim"] = func(s string) (string, error) { return strings.TrimSpace(s), nil }

	reg["reverse"] = func(s string) (string, error) {
		runes := []rune(s)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes), nil
	}
	reg["normalize_whitespace"] = func(s string) (string, error) {
		return strings.Join(strings.Fields(s), " "), nil
	}
	reg["remove_whitespace"] = func(s string) (string, error) {
		var b strings.Builder
		for _, r := range s {
			if !isWhitespace(r) {
				b.WriteRune(r)
			}
		}
		return b.String(), nil
	}

	reg["normalize_path"] = func(s string) (string, error) {
		// Đơn giản: đổi backslash sang slash và rút gọn // -> /
		s = strings.ReplaceAll(s, "\\", "/")
		for strings.Contains(s, "//") {
			s = strings.ReplaceAll(s, "//", "/")
		}
		return s, nil
	}
	reg["basename"] = func(s string) (string, error) {
		// Dùng filepath.Base nhưng chuyển \ -> / trước cho đồng nhất
		n := strings.ReplaceAll(s, "\\", "/")
		return filepath.Base(n), nil
	}
	reg["dirname"] = func(s string) (string, error) {
		n := strings.ReplaceAll(s, "\\", "/")
		if idx := strings.LastIndex(n, "/"); idx >= 0 {
			if idx == 0 {
				return "/", nil
			}
			return n[:idx], nil
		}
		return ".", nil
	}
}

func isWhitespace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }

// --- Data formats ---

func RegisterFormatModifiers(reg map[string]ModifierFn) {
	reg["hex_decode"] = createHexDecode()
	reg["hex_encode"] = createHexEncode()

	reg["json_extract"] = func(s string) (string, error) { return s, nil } // placeholder
	reg["json_normalize"] = func(s string) (string, error) {
		// rất đơn giản: bỏ \n \t và co cụm khoảng trắng đôi
		out := strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\t", "")
		for strings.Contains(out, "  ") {
			out = strings.ReplaceAll(out, "  ", " ")
		}
		return out, nil
	}

	reg["xml_extract"] = func(s string) (string, error) { return s, nil } // placeholder

	reg["csv_extract"] = func(s string) (string, error) {
		// Lấy field đầu tiên, lược bỏ quote ngoài
		parts := strings.Split(s, ",")
		if len(parts) == 0 {
			return "", nil
		}
		return strings.Trim(parts[0], `"`), nil
	}
}

func createHexDecode() ModifierFn {
	return func(input string) (string, error) {
		clean := strings.ReplaceAll(strings.ReplaceAll(input, " ", ""), "-", "")
		if len(clean)%2 != 0 {
			return "", errors.New("invalid hex string length")
		}
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("hex decode failed: %w", err)
		}
		return string(b), nil
	}
}

func createHexEncode() ModifierFn {
	return func(input string) (string, error) {
		return hex.EncodeToString([]byte(input)), nil
	}
}

// --- Numeric ---

func RegisterNumericModifiers(reg map[string]ModifierFn) {
	reg["to_int"] = func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return "", fmt.Errorf("integer conversion failed: %w", err)
		}
		return s, nil
	}
	reg["to_float"] = func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			return "", fmt.Errorf("float conversion failed: %w", err)
		}
		return s, nil
	}
	// Placeholders – để bạn thay thế bằng chuyển đổi thực sự nếu cần
	reg["unix_timestamp"] = func(s string) (string, error) { return s, nil }
	reg["iso_timestamp"] = func(s string) (string, error)  { return s, nil }
}

// --- Advanced ---

func RegisterAdvancedModifiers(reg map[string]ModifierFn) {
	reg["md5"] = func(s string) (string, error) {
		sum := md5.Sum([]byte(s))
		return hex.EncodeToString(sum[:]), nil
	}
	reg["sha1"] = func(s string) (string, error) {
		sum := sha1.Sum([]byte(s))
		return hex.EncodeToString(sum[:]), nil
	}
	reg["sha256"] = func(s string) (string, error) {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:]), nil
	}

	reg["gzip_decode"] = func(s string) (string, error) {
		// Nếu chuỗi là gzip bytes ở dạng base64, bạn có thể decode 2 bước
		// Ở đây thử giải nén trực tiếp bytes (nếu input không phải bytes raw, sẽ fail và ta trả nguyên văn)
		br := bytes.NewReader([]byte(s))
		gr, err := gzip.NewReader(br)
		if err != nil {
			// giữ hành vi “nhẹ” như Rust placeholder: trả nguyên văn nếu không hợp lệ
			return s, nil
		}
		defer gr.Close()
		out, err := io.ReadAll(gr)
		if err != nil {
			return "", err
		}
		return string(out), nil
	}

	// alias nhẹ cho test linh hoạt (Rust test có khi tìm "gzip")
	reg["gzip"] = reg["gzip_decode"]

	reg["regex_extract"] = func(s string) (string, error) { return s, nil } // placeholder
}
