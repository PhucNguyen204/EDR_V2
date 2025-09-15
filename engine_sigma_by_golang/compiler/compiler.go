package compiler

import (
    "fmt"
    "strconv"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
    yaml "gopkg.in/yaml.v3"
)

// Compiler compiles SIGMA YAML rules into IR CompiledRuleset with field mapping.
type Compiler struct {
    primitiveMap        map[string]ir.PrimitiveId
    primitives          []ir.Primitive
    nextPrimitiveId     ir.PrimitiveId
    currentSelectionMap map[string][]ir.PrimitiveId
    fieldMapping        FieldMapping
    nextRuleId          ir.RuleId
    compiledRules       []ir.CompiledRule
}

// New returns a new Compiler with default field mapping.
func New() *Compiler {
    return &Compiler{
        primitiveMap:        make(map[string]ir.PrimitiveId),
        primitives:          make([]ir.Primitive, 0),
        nextPrimitiveId:     0,
        currentSelectionMap: make(map[string][]ir.PrimitiveId),
        fieldMapping:        NewFieldMapping(),
        nextRuleId:          0,
        compiledRules:       make([]ir.CompiledRule, 0),
    }
}

// WithFieldMapping creates a new Compiler with custom mapping.
func WithFieldMapping(fm FieldMapping) *Compiler {
    c := New()
    c.fieldMapping = fm
    return c
}

func (c *Compiler) FieldMapping() *FieldMapping { return &c.fieldMapping }

func (c *Compiler) Primitives() []ir.Primitive { return append([]ir.Primitive(nil), c.primitives...) }

// CompileRule compiles a single YAML rule and appends to internal state.
func (c *Compiler) CompileRule(ruleYAML string) (ir.RuleId, error) {
    c.currentSelectionMap = make(map[string][]ir.PrimitiveId)

    var doc map[string]any
    if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil {
        return 0, fmt.Errorf("YAMLError: %v", err)
    }

    // rule id
    rid := c.extractRuleId(doc)

    // detection section
    detRaw, ok := doc["detection"]
    if !ok {
        return 0, fmt.Errorf("CompilationError: Missing detection section")
    }

    det, ok := detRaw.(map[string]any)
    if !ok {
        return 0, fmt.Errorf("CompilationError: detection must be a mapping")
    }

    // process all selections except condition
    for key, val := range det {
        if key == "condition" {
            continue
        }
        if err := c.processSelectionFromYAML(key, val); err != nil {
            return 0, err
        }
    }

    // extract condition string
    cond := ""
    if v, ok := det["condition"]; ok {
        if s, ok := v.(string); ok {
            cond = s
        } else {
            return 0, fmt.Errorf("CompilationError: Condition must be a string")
        }
    } else {
        return 0, fmt.Errorf("CompilationError: Missing detection.condition")
    }

    // record compiled rule
    c.compiledRules = append(c.compiledRules, ir.CompiledRule{
        RuleId:     rid,
        Selections: copySelMap(c.currentSelectionMap),
        Condition:  cond,
    })

    return rid, nil
}

// CompileRuleset compiles multiple rules; returns a CompiledRuleset.
func (c *Compiler) CompileRuleset(ruleYAMLs []string) (*ir.CompiledRuleset, error) {
    for _, r := range ruleYAMLs {
        if _, err := c.CompileRule(r); err != nil {
            return nil, err
        }
    }
    return c.IntoRuleset(), nil
}

// IntoRuleset finalizes the compiled ruleset.
func (c *Compiler) IntoRuleset() *ir.CompiledRuleset {
    rs := ir.NewCompiledRuleset()
    // carry over primitives and primitive map
    rs.PrimitiveMap = make(map[string]ir.PrimitiveId, len(c.primitiveMap))
    for k, v := range c.primitiveMap { rs.PrimitiveMap[k] = v }
    rs.Primitives = append(rs.Primitives, c.primitives...)
    // add rules; AddRule will assign RuleId by index; but we keep same RuleId numbers
    rs.Rules = make([]ir.CompiledRule, len(c.compiledRules))
    copy(rs.Rules, c.compiledRules)
    return rs
}

// ---------- internals ----------

func (c *Compiler) extractRuleId(doc map[string]any) ir.RuleId {
    if v, ok := doc["id"]; ok {
        switch t := v.(type) {
        case int:
            return ir.RuleId(t)
        case int64:
            return ir.RuleId(t)
        case float64:
            return ir.RuleId(int64(t))
        case string:
            if n, err := strconv.ParseUint(t, 10, 32); err == nil {
                return ir.RuleId(n)
            }
        }
    }
    rid := c.nextRuleId
    c.nextRuleId++
    return rid
}

func (c *Compiler) processSelectionFromYAML(selectionName string, selectionValue any) error {
    m, ok := selectionValue.(map[string]any)
    if !ok {
        // allow empty or wrong types to be ignored gracefully
        return nil
    }

    ids := make([]ir.PrimitiveId, 0)
    for fieldKey, fieldVal := range m {
        baseField, matchType, modifiers := parseFieldWithModifiers(fieldKey)
        normalized := c.fieldMapping.NormalizeField(baseField)

        switch v := fieldVal.(type) {
        case string:
            pid := c.getOrCreatePrimitive(ir.NewPrimitive(normalized, matchType, []string{v}, modifiers))
            ids = append(ids, pid)
        case int, int32, int64, uint, uint32, uint64, float32, float64, bool:
            s := fmt.Sprint(v)
            pid := c.getOrCreatePrimitive(ir.NewPrimitive(normalized, matchType, []string{s}, modifiers))
            ids = append(ids, pid)
        case []any:
            vals := make([]string, 0, len(v))
            for _, it := range v {
                switch tv := it.(type) {
                case string:
                    vals = append(vals, tv)
                case int, int32, int64, uint, uint32, uint64, float32, float64, bool:
                    vals = append(vals, fmt.Sprint(tv))
                }
            }
            if len(vals) > 0 {
                pid := c.getOrCreatePrimitive(ir.NewPrimitive(normalized, matchType, vals, modifiers))
                ids = append(ids, pid)
            }
        default:
            return fmt.Errorf("CompilationError: Unsupported field value type for '%s'", fieldKey)
        }
    }

    c.currentSelectionMap[selectionName] = ids
    return nil
}

func (c *Compiler) getOrCreatePrimitive(p ir.Primitive) ir.PrimitiveId {
    key := p.Key()
    if id, ok := c.primitiveMap[key]; ok {
        return id
    }
    id := c.nextPrimitiveId
    c.nextPrimitiveId++
    c.primitiveMap[key] = id
    c.primitives = append(c.primitives, p)
    return id
}

// parseFieldWithModifiers implements SIGMA field|modifier list into (field, matchType, modifiers).
func parseFieldWithModifiers(fieldSpec string) (string, string, []string) {
    parts := splitBy(fieldSpec, '|')
    if len(parts) == 0 {
        return fieldSpec, "equals", nil
    }
    if len(parts) == 1 {
        return parts[0], "equals", nil
    }

    field := parts[0]
    matchType := "equals"
    mods := make([]string, 0, len(parts)-1)
    for _, mod := range parts[1:] {
        switch mod {
        case "contains":
            matchType = "contains"
        case "startswith":
            matchType = "startswith"
        case "endswith":
            matchType = "endswith"
        case "re":
            matchType = "regex"
        case "range":
            matchType = "range"
        case "cidr":
            matchType = "cidr"
        case "fuzzy":
            matchType = "fuzzy"
        case "cased":
            mods = append(mods, "case_sensitive")
        case "base64":
            mods = append(mods, "base64_decode")
        case "base64offset":
            mods = append(mods, "base64_offset_decode")
        case "utf16":
            mods = append(mods, "utf16_decode")
        case "utf16le":
            mods = append(mods, "utf16le_decode")
        case "utf16be":
            mods = append(mods, "utf16be_decode")
        case "wide":
            mods = append(mods, "wide_decode")
        default:
            mods = append(mods, mod)
        }
    }
    return field, matchType, mods
}

func splitBy(s string, sep rune) []string {
    out := make([]string, 0, 4)
    start := 0
    for i, r := range s {
        if r == sep {
            out = append(out, s[start:i])
            start = i + 1
        }
    }
    out = append(out, s[start:])
    return out
}

func copySelMap(m map[string][]ir.PrimitiveId) map[string][]ir.PrimitiveId {
    out := make(map[string][]ir.PrimitiveId, len(m))
    for k, v := range m {
        out[k] = append([]ir.PrimitiveId(nil), v...)
    }
    return out
}

