package engine_sigma_by_golang

import (
	"encoding/json"
)

type PrimitiveId = uint32
type RuleId = uint32

type Primitive struct {
	Field     string   `json:"field"`
	MatchType string   `json:"match_type"`
	Values    []string `json:"values"`
	Modifiers []string `json:"modifiers"`
}

func NewPrimitive(field, matchType string, values, modifiers []string) Primitive {
	return Primitive{
		Field:     field,
		MatchType: matchType,
		Values:    append([]string(nil), values...),
		Modifiers: append([]string(nil), modifiers...),
	}
}

func NewPrimitiveStatic(field, matchType string, values, modifiers []string) Primitive {
	return NewPrimitive(field, matchType, values, modifiers)
}

func PrimitiveFromStrs(field, matchType string, values, modifiers []string) Primitive {
	return NewPrimitive(field, matchType, values, modifiers)
}

func (p Primitive) Clone() Primitive {
	return Primitive{
		Field:     p.Field,
		MatchType: p.MatchType,
		Values:    append([]string(nil), p.Values...),
		Modifiers: append([]string(nil), p.Modifiers...),
	}
}

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

type CompiledRule struct {
    RuleId     RuleId                   `json:"rule_id"`
    Selections map[string][]PrimitiveId `json:"selections"` // selection name -> primitive IDs
    Condition  string                   `json:"condition"`  // raw condition string
    // Disjunctions: selection name -> các nhóm OR; mỗi nhóm là AND các primitive trong một map con.
    Disjunctions map[string][][]PrimitiveId `json:"disjunctions,omitempty"`
    Title       string `json:"title,omitempty"`
    Description string `json:"description,omitempty"`
    Level       string `json:"level,omitempty"`
    RuleUID     string `json:"rule_uid,omitempty"`
}
func (r CompiledRule) Clone() CompiledRule {
    cp := CompiledRule{
        RuleId:       r.RuleId,
        Selections:   make(map[string][]PrimitiveId, len(r.Selections)),
        Condition:    r.Condition,
        Disjunctions: make(map[string][][]PrimitiveId, len(r.Disjunctions)),
        Title:        r.Title,
        Description:  r.Description,
        Level:        r.Level,
        RuleUID:      r.RuleUID,
    }
    for k, v := range r.Selections {
        cp.Selections[k] = append([]PrimitiveId(nil), v...)
    }
    for k, groups := range r.Disjunctions {
        outGroups := make([][]PrimitiveId, 0, len(groups))
        for _, g := range groups {
            outGroups = append(outGroups, append([]PrimitiveId(nil), g...))
        }
        cp.Disjunctions[k] = outGroups
    }
    return cp
}


type CompiledRuleset struct {
	PrimitiveMap map[string]PrimitiveId `json:"primitive_map"` // key = Primitive.Key()
	Primitives   []Primitive            `json:"primitives"`
	Rules        []CompiledRule         `json:"rules"`
}

func NewCompiledRuleset() *CompiledRuleset {
	return &CompiledRuleset{
		PrimitiveMap: make(map[string]PrimitiveId),
		Primitives:   make([]Primitive, 0),
		Rules:        make([]CompiledRule, 0),
	}
}

func (c *CompiledRuleset) PrimitiveCount() int {
	return len(c.Primitives)
}

func (c *CompiledRuleset) GetPrimitive(id PrimitiveId) (Primitive, bool) {
	idx := int(id)
	if idx < 0 || idx >= len(c.Primitives) {
		var zero Primitive
		return zero, false
	}
	return c.Primitives[idx], true
}

func (c *CompiledRuleset) InternPrimitive(p Primitive) PrimitiveId {
	if c.PrimitiveMap == nil {
		c.PrimitiveMap = make(map[string]PrimitiveId)
	}
	key := p.Key()
	if id, ok := c.PrimitiveMap[key]; ok {
		return id
	}
	id := PrimitiveId(len(c.Primitives))
	c.Primitives = append(c.Primitives, p.Clone())
	c.PrimitiveMap[key] = id
	return id
}

func (c *CompiledRuleset) AddRule(r CompiledRule) RuleId {
	id := RuleId(len(c.Rules))
	cp := r.Clone()
	cp.RuleId = id
	c.Rules = append(c.Rules, cp)
	return id
}

func (c *CompiledRuleset) Clone() *CompiledRuleset {
	if c == nil {
		return nil
	}
	cp := &CompiledRuleset{
		PrimitiveMap: make(map[string]PrimitiveId, len(c.PrimitiveMap)),
		Primitives:   make([]Primitive, len(c.Primitives)),
		Rules:        make([]CompiledRule, len(c.Rules)),
	}
	for k, v := range c.PrimitiveMap {
		cp.PrimitiveMap[k] = v
	}
	for i, p := range c.Primitives {
		cp.Primitives[i] = p.Clone()
	}
	for i, r := range c.Rules {
		cp.Rules[i] = r.Clone()
	}
	return cp
}
