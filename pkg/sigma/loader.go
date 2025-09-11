package sigma

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type rawRule struct {
	Title     string         `yaml:"title"`
	ID        string         `yaml:"id"`
	Logsource map[string]any `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
}

func LoadRuleYAML(b []byte) (RuleIR, error) {
	var rr rawRule
	if err := yaml.Unmarshal(b, &rr); err != nil {
		return RuleIR{}, err
	}
	if rr.Detection == nil {
		return RuleIR{}, errors.New("missing detection block")
	}

	selections := map[string]Selection{}
	for name, node := range rr.Detection {
		if name == "condition" { continue }

		switch v := node.(type) {
		case map[string]any:
			preds, err := parsePredicateMap(v)
			if err != nil { return RuleIR{}, fmt.Errorf("selection %s: %w", name, err) }
			selections[name] = Selection{
				Name: name,
				Groups: []SelectionGroup{
					{Predicates: preds},
				},
			}

		case []any:
			var groups []SelectionGroup
			for i, item := range v {
				m, ok := item.(map[string]any)
				if !ok { return RuleIR{}, fmt.Errorf("selection %s item %d not a mapping", name, i) }
				preds, err := parsePredicateMap(m)
				if err != nil { return RuleIR{}, fmt.Errorf("selection %s item %d: %w", name, i, err) }
				groups = append(groups, SelectionGroup{Predicates: preds})
			}
			selections[name] = Selection{Name: name, Groups: groups}

		default:
			return RuleIR{}, fmt.Errorf("selection %s must be mapping or list", name)
		}
	}

	cond, _ := rr.Detection["condition"].(string)
	id := strings.TrimSpace(rr.ID)
	if id == "" { id = rr.Title }

	return RuleIR{
		ID:         id,
		Title:      rr.Title,
		Logsource:  rr.Logsource,
		Selections: selections,
		Condition:  strings.TrimSpace(cond),
		Literals:   collectLiterals(selections),
	}, nil
}

func parsePredicateMap(mp map[string]any) ([]SelectionPredicate, error) {
	out := make([]SelectionPredicate, 0, len(mp))
	for rawKey, val := range mp {
		field, op, mods, err := parseFieldKey(rawKey)
		if err != nil { return nil, err }

		// Nếu modifier "all" xuất hiện trên list values => RequireAllVals=true.
		if arr, ok := val.([]any); ok && mods.RequireAllVals {
			out = append(out, SelectionPredicate{
				Field: field, Op: op, Value: arr, Modifiers: mods,
			})
			continue
		}
		out = append(out, SelectionPredicate{
			Field: field, Op: op, Value: val, Modifiers: mods,
		})
	}
	return out, nil
}

// Field|mod1|mod2 → (field, op, modifiers)
func parseFieldKey(s string) (field string, op Operator, mods PredicateModifiers, err error) {
	parts := strings.Split(s, "|")
	field = parts[0]
	op = OpEq

	for _, m := range parts[1:] {
		switch strings.ToLower(strings.TrimSpace(m)) {
		// operators
		case "contains":
			op = OpContains
		case "startswith":
			op = OpStartsWith
		case "endswith":
			op = OpEndsWith
		case "re", "regex":
			op = OpRegex
		case "exists":
			op = OpExists
		case "cidr":
			op = OpCidr
		case "lt":
			op = OpLt
		case "lte":
			op = OpLte
		case "gt":
			op = OpGt
		case "gte":
			op = OpGte
		case "all":
			// áp dụng trên list values (require all match)
			mods.RequireAllVals = true

		// modifiers
		case "cased":
			mods.CaseSensitive = true
		case "wide", "utf16", "utf16le":
			mods.UTF16LE, mods.Wide = true, true
		case "base64":
			mods.Base64 = true
		case "base64offset":
			mods.Base64Offset = true
		case "windash":
			mods.Windash = true
		case "fieldref":
			mods.FieldRef = true

		case "":
			// bỏ qua
		default:
			// không fail cứng để tương thích (modifier hiếm), có thể log ở caller
		}
	}
	return
}

// gom literal cho prefilter (bỏ regex/existence/numeric/cidr)
func collectLiterals(selections map[string]Selection) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(s string) {
		if len(s) >= 3 { out[s] = struct{}{} }
	}
	for _, sel := range selections {
		for _, grp := range sel.Groups {
			for _, p := range grp.Predicates {
				switch p.Op {
				case OpRegex, OpExists, OpCidr, OpLt, OpLte, OpGt, OpGte:
					continue
				}
				switch v := p.Value.(type) {
				case string:
					add(v)
				case []any:
					for _, it := range v {
						if s, ok := it.(string); ok { add(s) }
					}
				}
			}
		}
	}
	return out
}
