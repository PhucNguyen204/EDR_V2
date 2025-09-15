package matcher

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// MatchFn và ModifierFn đã có trong matcher/types.go:
// type MatchFn func(fieldValue string, values []string, modifiers []string) (bool, error)
// type ModifierFn func(input string) (string, error)

// -------- Exact / Contains / StartsWith / EndsWith --------

func createExactMatch() MatchFn {
	return func(fieldValue string, values []string, modifiers []string) (bool, error) {
		caseSensitive := containsString(modifiers, "case_sensitive")
		for _, v := range values {
			var matches bool
			if caseSensitive {
				matches = fieldValue == v
			} else {
				matches = strings.EqualFold(fieldValue, v)
			}
			if matches {
				return true, nil
			}
		}
		return false, nil
	}
}

func createContainsMatch() MatchFn {
	return func(fieldValue string, values []string, modifiers []string) (bool, error) {
		caseSensitive := containsString(modifiers, "case_sensitive")
		f := fieldValue
		if !caseSensitive {
			f = strings.ToLower(f)
		}
		for _, v := range values {
			sub := v
			if !caseSensitive {
				sub = strings.ToLower(sub)
			}
			if strings.Contains(f, sub) {
				return true, nil
			}
		}
		return false, nil
	}
}

func createStartswithMatch() MatchFn {
	return func(fieldValue string, values []string, modifiers []string) (bool, error) {
		caseSensitive := containsString(modifiers, "case_sensitive")
		f := fieldValue
		if !caseSensitive {
			f = strings.ToLower(f)
		}
		for _, v := range values {
			prefix := v
			if !caseSensitive {
				prefix = strings.ToLower(prefix)
			}
			if strings.HasPrefix(f, prefix) {
				return true, nil
			}
		}
		return false, nil
	}
}

func createEndswithMatch() MatchFn {
	return func(fieldValue string, values []string, modifiers []string) (bool, error) {
		caseSensitive := containsString(modifiers, "case_sensitive")
		f := fieldValue
		if !caseSensitive {
			f = strings.ToLower(f)
		}
		for _, v := range values {
			suffix := v
			if !caseSensitive {
				suffix = strings.ToLower(suffix)
			}
			if strings.HasSuffix(f, suffix) {
				return true, nil
			}
		}
		return false, nil
	}
}

// -------------------- Regex (with cache) --------------------

var regexCache sync.Map // map[string]*regexp.Regexp

func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	if r, ok := regexCache.Load(pattern); ok {
		return r.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

func createRegexMatch() MatchFn {
	return func(fieldValue string, values []string, _ []string) (bool, error) {
		for _, pattern := range values {
			re, err := getCachedRegex(pattern)
			if err != nil {
				return false, err
			}
			if re.MatchString(fieldValue) {
				return true, nil
			}
		}
		return false, nil
	}
}

// ---------------------- Modifiers ----------------------

// func createBase64Decode() ModifierFn {
// 	return func(input string) (string, error) {
// 		decoded, err := base64.StdEncoding.DecodeString(input)
// 		if err != nil {
// 			return "", fmt.Errorf("Base64 decode failed: %v", err)
// 		}
// 		return string(decoded), nil
// 	}
// }

// // Đơn giản hóa UTF-16 decode (để giữ hành vi giống bản Rust demo)
// func createUTF16Decode() ModifierFn {
// 	return func(input string) (string, error) {
// 		return input, nil
// 	}
// }

// ---------------- CIDR / Range / Fuzzy ----------------

func createCIDRMatch() MatchFn {
	return func(fieldValue string, values []string, _ []string) (bool, error) {
		ip := net.ParseIP(strings.TrimSpace(fieldValue))
		if ip == nil {
			return false, fmt.Errorf("InvalidIP: %s", fieldValue)
		}
		for _, cidr := range values {
			_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				return false, fmt.Errorf("InvalidCIDR: %s", cidr)
			}
			if ipNet.Contains(ip) {
				return true, nil
			}
		}
		return false, nil
	}
}

func createRangeMatch() MatchFn {
	return func(fieldValue string, values []string, _ []string) (bool, error) {
		fv := strings.TrimSpace(fieldValue)
		fieldNum, err := strconv.ParseFloat(fv, 64)
		if err != nil {
			return false, fmt.Errorf("InvalidNumber: %s", fieldValue)
		}

		for _, rs := range values {
			r := strings.TrimSpace(rs)
			parts := strings.SplitN(r, "-", 2)
			if len(parts) != 2 {
				return false, fmt.Errorf("InvalidRange: %s", rs)
			}
			min, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			max, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 != nil || err2 != nil {
				return false, fmt.Errorf("InvalidRange: %s", rs)
			}
			if fieldNum >= min && fieldNum <= max {
				return true, nil
			}
		}
		return false, nil
	}
}

func createFuzzyMatch() MatchFn {
	return func(fieldValue string, values []string, modifiers []string) (bool, error) {
		threshold := 0.8
		for _, m := range modifiers {
			if strings.HasPrefix(m, "threshold:") {
				num := strings.TrimPrefix(m, "threshold:")
				t, err := strconv.ParseFloat(num, 64)
				if err != nil {
					return false, fmt.Errorf("InvalidThreshold: %s", num)
				}
				threshold = t
			}
		}
		for _, v := range values {
			if calculateSimilarity(fieldValue, v) >= threshold {
				return true, nil
			}
		}
		return false, nil
	}
}

// ---------------- Similarity helpers ----------------

func calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		if len(a) == 0 && len(b) == 0 {
			return 1.0
		}
		return 0.0
	}
	maxLen := max(len([]rune(a)), len([]rune(b)))
	dist := levenshteinDistance(a, b)
	return 1.0 - float64(dist)/float64(maxLen)
}

func levenshteinDistance(a, b string) int {
	ar := []rune(a)
	br := []rune(b)
	alen := len(ar)
	blen := len(br)
	if alen == 0 {
		return blen
	}
	if blen == 0 {
		return alen
	}
	mat := make([][]int, alen+1)
	for i := range mat {
		mat[i] = make([]int, blen+1)
	}
	for i := 0; i <= alen; i++ {
		mat[i][0] = i
	}
	for j := 0; j <= blen; j++ {
		mat[0][j] = j
	}
	for i := 1; i <= alen; i++ {
		for j := 1; j <= blen; j++ {
			cost := 0
			if ar[i-1] != br[j-1] {
				cost = 1
			}
			mat[i][j] = min3(
				mat[i-1][j]+1,
				mat[i][j-1]+1,
				mat[i-1][j-1]+cost,
			)
		}
	}
	return mat[alen][blen]
}

// ---------------- Registry helpers ----------------

func RegisterDefaults(matchRegistry map[string]MatchFn, modifierRegistry map[string]ModifierFn) {
	// Basic
	matchRegistry["equals"] = createExactMatch()
	matchRegistry["contains"] = createContainsMatch()
	matchRegistry["startswith"] = createStartswithMatch()
	matchRegistry["endswith"] = createEndswithMatch()
	matchRegistry["regex"] = createRegexMatch()

	// Advanced
	matchRegistry["cidr"] = createCIDRMatch()
	matchRegistry["range"] = createRangeMatch()
	matchRegistry["fuzzy"] = createFuzzyMatch()

	// Modifiers
	modifierRegistry["base64_decode"] = createBase64Decode()
	modifierRegistry["utf16_decode"] = createUTF16Decode()
}

func RegisterDefaultsWithComprehensiveModifiers(matchRegistry map[string]MatchFn, modifierRegistry map[string]ModifierFn) {
	RegisterDefaults(matchRegistry, modifierRegistry)
	// Nếu có subpackage modifiers với hàng loạt modifier nâng cao, gọi thêm ở đây:
	// modifiers.RegisterComprehensiveModifiers(modifierRegistry)
}

// ---------------- small utils ----------------

func containsString(arr []string, target string) bool {
	for _, s := range arr {
		if s == target {
			return true
		}
	}
	return false
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
