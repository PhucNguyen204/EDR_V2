package engine

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

type tok struct{ kind, val string } // id|op|lpar|rpar

var (
	reThem = regexp.MustCompile(`^(?i)(\d+|all)\s+of\s+them$`)
	reOf   = regexp.MustCompile(`^(?i)(\d+|all)\s+of\s+([A-Za-z_][A-Za-z0-9_\-\*]*)$`)
)

func EvalCondition(condition string, ctx map[string]bool) (bool, error) {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return false, errors.New("empty condition")
	}

	// 1) N/all of them
	if m := reThem.FindStringSubmatch(condition); m != nil {
		q := strings.ToLower(m[1])
		vals := make([]bool, 0, len(ctx))
		for _, v := range ctx { vals = append(vals, v) }
		if q == "all" {
			if len(vals) == 0 { return false, nil }
			for _, b := range vals { if !b { return false, nil } }
			return true, nil
		}
		n, err := strconv.Atoi(q); if err != nil { return false, err }
		c := 0; for _, b := range vals { if b { c++ } }
		return c >= n, nil
	}

	// 2) N/all of prefix* (hoặc exact id khi không có *)
	if m := reOf.FindStringSubmatch(condition); m != nil {
		q, pat := strings.ToLower(m[1]), m[2]
		var vals []bool
		if strings.HasSuffix(pat, "*") {
			prefix := strings.TrimSuffix(pat, "*")
			for k, v := range ctx {
				if strings.HasPrefix(strings.ToLower(k), strings.ToLower(prefix)) {
					vals = append(vals, v)
				}
			}
		} else {
			vals = []bool{ctx[pat]}
		}
		if q == "all" {
			if len(vals) == 0 { return false, nil }
			for _, b := range vals { if !b { return false, nil } }
			return true, nil
		}
		n, err := strconv.Atoi(q); if err != nil { return false, errors.New("invalid N") }
		c := 0; for _, b := range vals { if b { c++ } }
		return c >= n, nil
	}

	// 3) boolean parser: tokenize → shunting-yard → RPN → eval
	toks := tokenize(condition)
	rpn, err := toRPN(toks)
	if err != nil { return false, err }
	return evalRPN(rpn, ctx)
}

func tokenize(s string) []tok {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	parts := strings.Fields(s)
	out := make([]tok, 0, len(parts))
	for _, p := range parts {
		switch strings.ToLower(p) {
		case "and", "or", "not":
			out = append(out, tok{kind: "op", val: strings.ToLower(p)})
		case "(":
			out = append(out, tok{kind: "lpar"})
		case ")":
			out = append(out, tok{kind: "rpar"})
		default:
			out = append(out, tok{kind: "id", val: p})
		}
	}
	return out
}

func prec(op string) int {
	switch op {
	case "not":
		return 3
	case "and":
		return 2
	case "or":
		return 1
	default:
		return 0
	}
}

func toRPN(ts []tok) ([]tok, error) {
	var out, st []tok
	for _, t := range ts {
		switch t.kind {
		case "id":
			out = append(out, t)
		case "op":
			for len(st) > 0 && st[len(st)-1].kind == "op" && prec(st[len(st)-1].val) >= prec(t.val) {
				out = append(out, st[len(st)-1]); st = st[:len(st)-1]
			}
			st = append(st, t)
		case "lpar":
			st = append(st, t)
		case "rpar":
			for len(st) > 0 && st[len(st)-1].kind != "lpar" {
				out = append(out, st[len(st)-1]); st = st[:len(st)-1]
			}
			if len(st) == 0 { return nil, errors.New("unbalanced )") }
			st = st[:len(st)-1]
		}
	}
	for len(st) > 0 {
		if st[len(st)-1].kind == "lpar" { return nil, errors.New("unbalanced (") }
		out = append(out, st[len(st)-1]); st = st[:len(st)-1]
	}
	return out, nil
}

func evalRPN(rpn []tok, ctx map[string]bool) (bool, error) {
	var st []bool
	pop := func() bool { v := st[len(st)-1]; st = st[:len(st)-1]; return v }
	for _, t := range rpn {
		switch t.kind {
		case "id":
			st = append(st, ctx[strings.TrimSpace(t.val)])
		case "op":
			switch t.val {
			case "not":
				if len(st) < 1 { return false, errors.New("stack underflow: not") }
				a := pop(); st = append(st, !a)
			case "and":
				if len(st) < 2 { return false, errors.New("stack underflow: and") }
				b, a := pop(), pop(); st = append(st, a && b)
			case "or":
				if len(st) < 2 { return false, errors.New("stack underflow: or") }
				b, a := pop(), pop(); st = append(st, a || b)
			}
		}
	}
	if len(st) != 1 { return false, errors.New("eval error") }
	return st[0], nil
}
