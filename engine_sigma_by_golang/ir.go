package engine_sigma_by_golang

import (
	"encoding/json"
)

// Alias ID giống Rust (u32)
type PrimitiveId = uint32
type RuleId = uint32

// Primitive: mảnh điều kiện của SIGMA
type Primitive struct {
	Field     string   `json:"field"`
	MatchType string   `json:"match_type"`
	Values    []string `json:"values"`
	Modifiers []string `json:"modifiers"`
}

// Tạo Primitive, đồng thời copy slice để tránh aliasing
func NewPrimitive(field, matchType string, values, modifiers []string) Primitive {
	return Primitive{
		Field:     field,
		MatchType: matchType,
		Values:    append([]string(nil), values...),
		Modifiers: append([]string(nil), modifiers...),
	}
}

// API tương đương với bản Rust (giữ lại cho đủ mặt)
func NewPrimitiveStatic(field, matchType string, values, modifiers []string) Primitive {
	return NewPrimitive(field, matchType, values, modifiers)
}

func PrimitiveFromStrs(field, matchType string, values, modifiers []string) Primitive {
	return NewPrimitive(field, matchType, values, modifiers)
}

// Clone deep-copy để tương đương derive(Clone) của Rust
func (p Primitive) Clone() Primitive {
	return Primitive{
		Field:     p.Field,
		MatchType: p.MatchType,
		Values:    append([]string(nil), p.Values...),
		Modifiers: append([]string(nil), p.Modifiers...),
	}
}

// Key tạo khóa ổn định theo NỘI DUNG để dùng làm key của map (mô phỏng Eq+Hash trong Rust)
func (p Primitive) Key() string {
	type view struct {
		Field     string   `json:"field"`
		MatchType string   `json:"match_type"`
		Values    []string `json:"values"`
		Modifiers []string `json:"modifiers"`
	}
	b, _ := json.Marshal(view{
		Field:     p.Field,
		MatchType: p.MatchType,
		Values:    p.Values,
		Modifiers: p.Modifiers,
	})
	return string(b)
}

// CompiledRule: 1 rule đã biên dịch
type CompiledRule struct {
	RuleId     RuleId                   `json:"rule_id"`
	Selections map[string][]PrimitiveId `json:"selections"` // selection name -> primitive IDs
	Condition  string                   `json:"condition"`  // raw condition string
}

// Clone deep-copy selections
func (r CompiledRule) Clone() CompiledRule {
	cp := CompiledRule{
		RuleId:     r.RuleId,
		Selections: make(map[string][]PrimitiveId, len(r.Selections)),
		Condition:  r.Condition,
	}
	for k, v := range r.Selections {
		cp.Selections[k] = append([]PrimitiveId(nil), v...)
	}
	return cp
}

// CompiledRuleset: tập hợp primitives + rules
type CompiledRuleset struct {
	PrimitiveMap map[string]PrimitiveId `json:"primitive_map"` // key = Primitive.Key()
	Primitives   []Primitive            `json:"primitives"`
	Rules        []CompiledRule         `json:"rules"`
}

// Constructor (tương đương new()/default() bên Rust)
func NewCompiledRuleset() *CompiledRuleset {
	return &CompiledRuleset{
		PrimitiveMap: make(map[string]PrimitiveId),
		Primitives:   make([]Primitive, 0),
		Rules:        make([]CompiledRule, 0),
	}
}

// Số lượng primitives hiện có
func (c *CompiledRuleset) PrimitiveCount() int {
	return len(c.Primitives)
}

// Lấy primitive theo id (index)
func (c *CompiledRuleset) GetPrimitive(id PrimitiveId) (Primitive, bool) {
	idx := int(id)
	if idx < 0 || idx >= len(c.Primitives) {
		var zero Primitive
		return zero, false
	}
	return c.Primitives[idx], true
}

// InternPrimitive: chèn primitive nếu chưa tồn tại, trả về PrimitiveId ổn định
func (c *CompiledRuleset) InternPrimitive(p Primitive) PrimitiveId {
	if c.PrimitiveMap == nil {
		c.PrimitiveMap = make(map[string]PrimitiveId)
	}
	key := p.Key()
	if id, ok := c.PrimitiveMap[key]; ok {
		return id
	}
	id := PrimitiveId(len(c.Primitives))
	c.Primitives = append(c.Primitives, p.Clone()) // clone để tách backing array
	c.PrimitiveMap[key] = id
	return id
}

// AddRule: thêm rule và trả về RuleId (theo index)
func (c *CompiledRuleset) AddRule(r CompiledRule) RuleId {
	id := RuleId(len(c.Rules))
	// clone để cô lập dữ liệu selections
	cp := r.Clone()
	cp.RuleId = id
	c.Rules = append(c.Rules, cp)
	return id
}

// Clone toàn bộ ruleset (deep copy map/slice)
func (c *CompiledRuleset) Clone() *CompiledRuleset {
	if c == nil {
		return nil
	}
	cp := &CompiledRuleset{
		PrimitiveMap: make(map[string]PrimitiveId, len(c.PrimitiveMap)),
		Primitives:   make([]Primitive, len(c.Primitives)),
		Rules:        make([]CompiledRule, len(c.Rules)),
	}
	// copy map
	for k, v := range c.PrimitiveMap {
		cp.PrimitiveMap[k] = v
	}
	// clone primitives
	for i, p := range c.Primitives {
		cp.Primitives[i] = p.Clone()
	}
	// clone rules
	for i, r := range c.Rules {
		cp.Rules[i] = r.Clone()
	}
	return cp
}
