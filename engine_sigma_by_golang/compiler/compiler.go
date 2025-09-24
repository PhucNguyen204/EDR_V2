package compiler

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
	yaml "gopkg.in/yaml.v3"
)

// Compiler compiles SIGMA YAML rules into IR CompiledRuleset with field mapping.
type Compiler struct {
	primitiveMap         map[string]ir.PrimitiveId
	primitives           []ir.Primitive
	nextPrimitiveId      ir.PrimitiveId
	currentSelectionMap  map[string][]ir.PrimitiveId
	currentSelectionOr   map[string][][]ir.PrimitiveId
	fieldMapping         FieldMapping
	nextRuleId           ir.RuleId
	compiledRules        []ir.CompiledRule
	compiledCorrelations []ir.CompiledCorrelationRule
}

// New returns a new Compiler with default field mapping.
func New() *Compiler {
	return &Compiler{
		primitiveMap:         make(map[string]ir.PrimitiveId),
		primitives:           make([]ir.Primitive, 0),
		nextPrimitiveId:      0,
		currentSelectionMap:  make(map[string][]ir.PrimitiveId),
		currentSelectionOr:   make(map[string][][]ir.PrimitiveId),
		fieldMapping:         NewFieldMapping(),
		nextRuleId:           0,
		compiledRules:        make([]ir.CompiledRule, 0),
		compiledCorrelations: make([]ir.CompiledCorrelationRule, 0),
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
	dec := yaml.NewDecoder(strings.NewReader(ruleYAML))
	var lastRid ir.RuleId
	anyDoc := false
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("YAMLError: %v", err)
		}
		if doc == nil || len(doc) == 0 {
			continue
		}
		anyDoc = true
		// Detection rule document
		if detRaw, ok := doc["detection"]; ok {
			c.currentSelectionMap = make(map[string][]ir.PrimitiveId)
			c.currentSelectionOr = make(map[string][][]ir.PrimitiveId)

			rid := c.extractRuleId(doc)
			det, ok := detRaw.(map[string]any)
			if !ok {
				return 0, fmt.Errorf("CompilationError: detection must be a mapping")
			}
			// process all selections except condition
			for key, val := range det {
				if key == "condition" {
					continue
				}
				switch tv := val.(type) {
				case map[string]any:
					if err := c.processSelectionFromYAML(key, tv); err != nil {
						return 0, err
					}
				case []any:
					if err := c.processSelectionListOfMaps(key, tv); err != nil {
						return 0, err
					}
				default:
				}
			}
			// condition
			cond := ""
			if v, ok := det["condition"].(string); ok {
				cond = v
			} else {
				return 0, fmt.Errorf("CompilationError: Missing or invalid detection.condition")
			}

			if lsRaw, ok := doc["logsource"].(map[string]any); ok {
				trimmed := strings.TrimSpace(cond)
				lowered := strings.ToLower(trimmed)
				if strings.HasPrefix(lowered, "not ") || lowered == "not" || strings.HasPrefix(lowered, "not(") {
					gateName := "__logsource_gate"
					gateIDs := make([]ir.PrimitiveId, 0, 3)
					if v, ok := lsRaw["product"].(string); ok && v != "" {
						pid := c.getOrCreatePrimitive(ir.NewPrimitive("event.product", "equals", []string{v}, nil))
						gateIDs = append(gateIDs, pid)
					}
					if v, ok := lsRaw["category"].(string); ok && v != "" {
						pid := c.getOrCreatePrimitive(ir.NewPrimitive("event.category", "equals", []string{v}, nil))
						gateIDs = append(gateIDs, pid)
					}
					if v, ok := lsRaw["service"].(string); ok && v != "" {
						pid := c.getOrCreatePrimitive(ir.NewPrimitive("event.service", "equals", []string{v}, nil))
						gateIDs = append(gateIDs, pid)
					}
					if len(gateIDs) > 0 {
						c.currentSelectionMap[gateName] = gateIDs
						cond = gateName + " and (" + cond + ")"
					}
				}
			}

			cr := ir.CompiledRule{
				RuleId:       rid,
				Selections:   copySelMap(c.currentSelectionMap),
				Disjunctions: copyOrMap(c.currentSelectionOr),
				Condition:    cond,
			}
			if v, ok := doc["name"].(string); ok {
				cr.RuleName = v
			}
			if v, ok := doc["title"].(string); ok {
				cr.Title = v
			}
			if v, ok := doc["description"].(string); ok {
				cr.Description = v
			}
			if v, ok := doc["level"].(string); ok {
				cr.Level = v
			}
			if v, ok := doc["id"]; ok {
				cr.RuleUID = fmt.Sprint(v)
			}
			c.compiledRules = append(c.compiledRules, cr)
			lastRid = rid
			continue
		}

		// Correlation rule document
		if corrRaw, ok := doc["correlation"]; ok {
			cm, ok := corrRaw.(map[string]any)
			if !ok {
				return 0, fmt.Errorf("CompilationError: correlation must be a mapping")
			}
			var corr ir.CompiledCorrelationRule
			if v, ok := doc["name"].(string); ok {
				corr.Name = v
			}
			if v, ok := doc["title"].(string); ok {
				corr.Title = v
			}
			if v, ok := doc["description"].(string); ok {
				corr.Description = v
			}
			if v, ok := doc["level"].(string); ok {
				corr.Level = v
			}
			if v, ok := doc["id"]; ok {
				corr.RuleUID = fmt.Sprint(v)
			}
			if v, ok := cm["type"].(string); ok {
				corr.Type = v
			} else {
				return 0, fmt.Errorf("CompilationError: correlation.type is required")
			}
			if arr, ok := cm["rules"].([]any); ok {
				for _, it := range arr {
					if s, ok := it.(string); ok && s != "" {
						corr.Rules = append(corr.Rules, s)
					}
				}
			}
			if arr, ok := cm["group-by"].([]any); ok {
				for _, it := range arr {
					if s, ok := it.(string); ok && s != "" {
						corr.GroupBy = append(corr.GroupBy, s)
					}
				}
			} else if arr, ok := cm["group_by"].([]any); ok {
				for _, it := range arr {
					if s, ok := it.(string); ok && s != "" {
						corr.GroupBy = append(corr.GroupBy, s)
					}
				}
			}
			if v, ok := cm["timespan"].(string); ok && v != "" {
				d, err := parseDurationLoose(v)
				if err != nil {
					return 0, fmt.Errorf("CompilationError: invalid correlation.timespan: %v", err)
				}
				corr.Timespan = d
			}
			if condRaw, ok := cm["condition"].(map[string]any); ok {
				if strings.EqualFold(corr.Type, "value_count") {
					var vc ir.ValueCountCondition
					if v, ok := condRaw["field"].(string); ok {
						vc.Field = v
					}
					if v, ok := condRaw["gte"]; ok {
						vc.Gte = toInt(v)
					}
					corr.ValueCount = &vc
				}
			}
			c.compiledCorrelations = append(c.compiledCorrelations, corr)
			continue
		}
		// Unknown doc: ignore
	}
	if !anyDoc {
		return 0, fmt.Errorf("CompilationError: empty YAML")
	}
	return lastRid, nil
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
	for k, v := range c.primitiveMap {
		rs.PrimitiveMap[k] = v
	}
	rs.Primitives = append(rs.Primitives, c.primitives...)
	// add rules; AddRule will assign RuleId by index; but we keep same RuleId numbers
	rs.Rules = make([]ir.CompiledRule, len(c.compiledRules))
	copy(rs.Rules, c.compiledRules)
	if len(c.compiledCorrelations) > 0 {
		rs.Correlations = make([]ir.CompiledCorrelationRule, len(c.compiledCorrelations))
		copy(rs.Correlations, c.compiledCorrelations)
		for i := range rs.Correlations {
			rs.Correlations[i].CorrelationId = uint32(i)
		}
	}
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
	ids, err := c.compileSelectionMap(m)
	if err != nil {
		return err
	}
	c.currentSelectionMap[selectionName] = ids
	return nil
}

// processSelectionListOfMaps handles selection value as []map[string]any (OR giữa các map con)
func (c *Compiler) processSelectionListOfMaps(selectionName string, arr []any) error {
	groups := make([][]ir.PrimitiveId, 0)
	handled := false
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if ok {
			ids, err := c.compileSelectionMap(m)
			if err != nil {
				return err
			}
			if len(ids) > 0 {
				groups = append(groups, ids)
				handled = true
			}
			continue
		}

		switch tv := it.(type) {
		case string:
			pid := c.getOrCreatePrimitive(ir.NewPrimitive(ir.AnyFieldSentinel, "equals", []string{tv}, nil))
			groups = append(groups, []ir.PrimitiveId{pid})
			handled = true
		case int, int32, int64, uint, uint32, uint64, float32, float64, bool:
			val := fmt.Sprint(tv)
			pid := c.getOrCreatePrimitive(ir.NewPrimitive(ir.AnyFieldSentinel, "equals", []string{val}, nil))
			groups = append(groups, []ir.PrimitiveId{pid})
			handled = true
		}
	}
	if handled {
		if _, ok := c.currentSelectionMap[selectionName]; !ok {
			c.currentSelectionMap[selectionName] = []ir.PrimitiveId{}
		}
	}
	if len(groups) > 0 {
		c.currentSelectionOr[selectionName] = append(c.currentSelectionOr[selectionName], groups...)
	}
	return nil
}

// compileSelectionMap compiles one mapping of field->value(s) into a slice of primitive IDs (AND semantics)
func (c *Compiler) compileSelectionMap(m map[string]any) ([]ir.PrimitiveId, error) {
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
			return nil, fmt.Errorf("CompilationError: Unsupported field value type for '%s'", fieldKey)
		}
	}
	return ids, nil
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

func copyOrMap(m map[string][][]ir.PrimitiveId) map[string][][]ir.PrimitiveId {
	out := make(map[string][][]ir.PrimitiveId, len(m))
	for k, groups := range m {
		cpGroups := make([][]ir.PrimitiveId, 0, len(groups))
		for _, g := range groups {
			cpGroups = append(cpGroups, append([]ir.PrimitiveId(nil), g...))
		}
		out[k] = cpGroups
	}
	return out
}

// parseDurationLoose parses durations like "30m", "1h", or minutes as int (e.g., "30").
func parseDurationLoose(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	// try to treat as minutes
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Minute, nil
	}
	return 0, fmt.Errorf("invalid duration: %q", s)
}

func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case uint:
		return int(t)
	case uint32:
		return int(t)
	case uint64:
		return int(t)
	case float32:
		return int(t)
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(t); err == nil {
			return n
		}
	}
	return 0
}
