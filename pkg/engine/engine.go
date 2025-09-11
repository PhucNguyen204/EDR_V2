package engine

import (
	"strings"

	"github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)

type CompiledRule struct {
	IR sigma.RuleIR
}

type Engine struct {
	fm sigma.FieldMapping

	// prefilter
	ac          *AhoCorasick
	litToRules  map[string]map[string]struct{} // literal -> set(ruleID)
	rulesNoLits map[string]CompiledRule        // rule không có literal => luôn evaluate

	// full set
	rules map[string]CompiledRule
}

// Compile: build prefilter trên toàn bộ rules
func Compile(rules []sigma.RuleIR, fm sigma.FieldMapping) *Engine {
	e := &Engine{
		fm:          fm,
		litToRules:  map[string]map[string]struct{}{},
		rulesNoLits: map[string]CompiledRule{},
		rules:       map[string]CompiledRule{},
	}
	// gom literals duy nhất
	var pats []string
	seen := map[string]struct{}{}
	for _, r := range rules {
		cr := CompiledRule{IR: r}
		e.rules[r.ID] = cr
		if len(r.Literals) == 0 {
			e.rulesNoLits[r.ID] = cr
			continue
		}
		for lit := range r.Literals {
			ll := strings.ToLower(lit)
			if _, ok := e.litToRules[ll]; !ok {
				e.litToRules[ll] = map[string]struct{}{}
			}
			e.litToRules[ll][r.ID] = struct{}{}
			if _, ok := seen[ll]; !ok {
				pats = append(pats, ll)
				seen[ll] = struct{}{}
			}
		}
	}
	if len(pats) > 0 {
		e.ac = NewAC(pats)
	}
	return e
}

// Flatten tất cả giá trị chuỗi trong event (đơn giản, đủ cho prefilter)
func flattenStrings(v any, sb *strings.Builder) {
	switch t := v.(type) {
	case map[string]any:
		for _, vv := range t {
			flattenStrings(vv, sb)
		}
	case []any:
		for _, vv := range t {
			flattenStrings(vv, sb)
		}
	case string:
		sb.WriteString(t)
		sb.WriteByte(' ')
	default:
		// số/bool -> bỏ qua ở prefilter
	}
}

// Prefilter: trả về danh sách ruleID có thể match
func (e *Engine) candidates(event map[string]any) map[string]struct{} {
	cands := map[string]struct{}{}
	// luôn thêm rules không có literal
	for id := range e.rulesNoLits {
		cands[id] = struct{}{}
	}
	// nếu không có AC => tất cả rule là candidate
	if e.ac == nil {
		for id := range e.rules { cands[id] = struct{}{} }
		return cands
	}
	// gom text
	var sb strings.Builder
	flattenStrings(event, &sb)
	hits := e.ac.FindAny(sb.String())
	if len(hits) == 0 {
		return cands
	}
	// map patternID -> literal -> rules
	// e.ac.patterns thứ tự trùng với patterns khi build
	for pid := range hits {
		lit := e.ac.patterns[pid]
		for rid := range e.litToRules[lit] {
			cands[rid] = struct{}{}
		}
	}
	return cands
}

// Evaluate: trả về các ruleID match đối với event (đã có loader/selection/condition)
func (e *Engine) Evaluate(event map[string]any) ([]string, error) {
	cands := e.candidates(event)
	out := make([]string, 0, len(cands))
	for rid := range cands {
		r := e.rules[rid].IR
		// build ctx: evaluate từng selection
		ctx := map[string]bool{}
		for name, sel := range r.Selections {
			ctx[name] = evalSelection(event, sel, e.fm)
		}
		ok, err := EvalCondition(r.Condition, ctx)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, rid)
		}
	}
	return out, nil
}
