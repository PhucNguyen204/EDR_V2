package engine

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)

func getValue(event map[string]any, dotted string) (any, bool) {
	cur := any(event)
	for _, part := range strings.Split(dotted, ".") {
		m, ok := cur.(map[string]any)
		if !ok { return nil, false }
		v, ok := m[part]
		if !ok { return nil, false }
		cur = v
	}
	return cur, true
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func normCase(s string, cased bool) string {
	if cased { return s }
	return strings.ToLower(s)
}

func normalizeWindash(s string) string {
	// Chuẩn hoá các dấu / -- – — … về '-' cho so khớp flags Windows
	r := strings.NewReplacer("—", "-", "–", "-", "―", "-", "/", "-")
	return r.Replace(s)
}

// --- base64/wide helpers ---

func toUTF16LEBytes(s string) []byte {
	// đơn giản: chèn 0x00 sau mỗi byte ASCII (đủ dùng cho pattern ASCII)
	// (nếu cần unicode chuẩn, dùng encoding/binary + utf16.Encode)
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0x00)
	}
	return out
}

func encodeBase64Offsets(b []byte) []string {
	// trả 3 biến thể encode từ offset 0..2 (độ lệch byte)
	if len(b) == 0 { return []string{""} }
	var out []string
	for off := 0; off < 3 && off < len(b); off++ {
		out = append(out, base64.StdEncoding.EncodeToString(b[off:]))
	}
	return out
}

func patternsWithEncoding(pattern string, mods sigma.PredicateModifiers) []string {
	// Nếu không có base64/offset/wide thì trả về nguyên mẫu
	if !mods.Base64 && !mods.Base64Offset && !mods.Wide && !mods.UTF16LE {
		return []string{pattern}
	}
	// wide/utf16 → bytes
	var raw []byte
	if mods.Wide || mods.UTF16LE {
		raw = toUTF16LEBytes(pattern)
	} else {
		raw = []byte(pattern)
	}
	// base64
	if mods.Base64Offset {
		return encodeBase64Offsets(raw)
	}
	if mods.Base64 {
		return []string{base64.StdEncoding.EncodeToString(raw)}
	}
	// chỉ wide/utf16 (không base64) → cho phép so khớp chứa trực tiếp chuỗi wide (hiếm)
	return []string{string(raw)}
}

// --- core matching ---

func matchStringWithOp(val, patt string, op sigma.Operator, mods sigma.PredicateModifiers) bool {
	a, b := val, patt

	// windash normalize nếu cần
	if mods.Windash {
		a = normalizeWindash(a)
		b = normalizeWindash(b)
	}

	// case
	aa := normCase(a, mods.CaseSensitive)
	bb := normCase(b, mods.CaseSensitive)

	switch op {
	case sigma.OpEq:
		return aa == bb
	case sigma.OpNeq:
		return aa != bb
	case sigma.OpContains:
		return strings.Contains(aa, bb)
	case sigma.OpStartsWith:
		return strings.HasPrefix(aa, bb)
	case sigma.OpEndsWith:
		return strings.HasSuffix(aa, bb)
	case sigma.OpRegex:
		pat := b
		if !mods.CaseSensitive && !strings.HasPrefix(pat, "(?i)") {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil { return false }
		return re.MatchString(a)
	default:
		return false
	}
}

func parseFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int: return float64(t), true
	case int64: return float64(t), true
	case float64: return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func matchPredicate(event map[string]any, p sigma.SelectionPredicate, fm sigma.FieldMapping) bool {
	field := fm.Resolve(p.Field)

	// exists: đặc biệt (không cần lấy giá trị)
	if p.Op == sigma.OpExists {
		want := true
		if p.Value != nil {
			if b, ok := p.Value.(bool); ok { want = b }
		}
		_, ok := getValue(event, field)
		return ok == want
	}

	// Lấy giá trị field (string/number/bool/list)
	v, ok := getValue(event, field)
	if !ok {
		return false
	}

	// OpAll: field list, mọi phần tử chứa needle
	if p.Op == sigma.OpAll {
		needle := toString(p.Value)
		list, ok := v.([]any)
		if !ok || len(list) == 0 { return false }
		for _, it := range list {
			if !strings.Contains(normCase(toString(it), p.Modifiers.CaseSensitive), normCase(needle, p.Modifiers.CaseSensitive)) {
				return false
			}
		}
		return true
	}

	// CIDR
	if p.Op == sigma.OpCidr {
		vals := []string{toString(p.Value)}
		if arr, ok := p.Value.([]any); ok {
			vals = vals[:0]
			for _, it := range arr { vals = append(vals, toString(it)) }
		}
		ipStr := toString(v)
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil { return false }
		for _, c := range vals {
			_, netw, err := net.ParseCIDR(strings.TrimSpace(c))
			if err == nil && netw.Contains(ip) { return true }
		}
		return false
	}

	// Numeric compares
	if p.Op == sigma.OpLt || p.Op == sigma.OpLte || p.Op == sigma.OpGt || p.Op == sigma.OpGte {
		lhs, ok1 := parseFloat(v)
		rhs, ok2 := parseFloat(p.Value)
		if !ok1 || !ok2 { return false }
		switch p.Op {
		case sigma.OpLt:  return lhs < rhs
		case sigma.OpLte: return lhs <= rhs
		case sigma.OpGt:  return lhs > rhs
		case sigma.OpGte: return lhs >= rhs
		}
	}

	// FieldRef: so với giá trị của field khác
	if p.Modifiers.FieldRef {
		otherPath := toString(p.Value)
		ov, ok := getValue(event, fm.Resolve(otherPath))
		if !ok { return false }
		return matchStringWithOp(toString(v), toString(ov), p.Op, p.Modifiers)
	}

	// List values: any-of (hoặc all-of nếu RequireAllVals)
	if arr, ok := p.Value.([]any); ok {
		// hỗ trợ encoding modifiers (wide/base64/offset) trên từng pattern
		valS := toString(v)
		if p.Modifiers.RequireAllVals {
			for _, it := range arr {
				pattern := toString(it)
				for _, enc := range patternsWithEncoding(pattern, p.Modifiers) {
					if matchStringWithOp(valS, enc, p.Op, p.Modifiers) {
						goto matchedOne // enc khớp cho item này
					}
				}
				return false // item này không khớp bằng bất kỳ enc nào
			matchedOne:
			}
			return true
		}
		// any-of
		for _, it := range arr {
			pattern := toString(it)
			for _, enc := range patternsWithEncoding(pattern, p.Modifiers) {
				if matchStringWithOp(valS, enc, p.Op, p.Modifiers) { return true }
			}
		}
		return false
	}

	// Scalar value (string/number/bool) + encoding modifiers
	valS := toString(v)
	for _, enc := range patternsWithEncoding(toString(p.Value), p.Modifiers) {
		if matchStringWithOp(valS, enc, p.Op, p.Modifiers) {
			return true
		}
	}
	return false
}

// Selection: OR-of-AND
func evalSelection(event map[string]any, sel sigma.Selection, fm sigma.FieldMapping) bool {
	for _, g := range sel.Groups { // OR
		ok := true
		for _, p := range g.Predicates { // AND
			if !matchPredicate(event, p, fm) { ok = false; break }
		}
		if ok { return true }
	}
	return false
}
