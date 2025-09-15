package compiler

import (
    "testing"
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func TestCompileRuleBasic(t *testing.T) {
    c := New()
    rule := `
title: Test Rule
detection:
  selection:
    EventID: 4624
  condition: selection
`
    rid, err := c.CompileRule(rule)
    if err != nil { t.Fatalf("CompileRule err: %v", err) }
    if rid != 0 { t.Fatalf("want rule id 0, got %d", rid) }
    if len(c.Primitives()) == 0 { t.Fatalf("expected primitives > 0") }

    rs := c.IntoRuleset()
    if rs.PrimitiveCount() == 0 { t.Fatalf("ruleset primitive count should be > 0") }
}

func TestCompileRuleset(t *testing.T) {
    c := New()
    r1 := `
title: Rule 1
detection:
  selection:
    EventID: 4624
  condition: selection
`
    r2 := `
title: Rule 2
detection:
  selection:
    EventID: 4625
  condition: selection
`
    rs, err := c.CompileRuleset([]string{r1, r2})
    if err != nil { t.Fatalf("CompileRuleset err: %v", err) }
    if rs.PrimitiveCount() == 0 { t.Fatalf("expected primitives") }
    if len(rs.PrimitiveMap) == 0 { t.Fatalf("expected primitive map not empty") }
}

func TestFieldMappingNormalize(t *testing.T) {
    fm := NewFieldMapping()
    fm.AddMapping("Event_ID", "EventID")
    c := WithFieldMapping(fm)
    rule := `
title: Test Rule
detection:
  selection:
    Event_ID: 4624
  condition: selection
`
    if _, err := c.CompileRule(rule); err != nil { t.Fatalf("err: %v", err) }
    prims := c.Primitives()
    found := false
    for _, p := range prims {
        if p.Field == "EventID" { found = true; break }
    }
    if !found { t.Fatalf("expected normalized field 'EventID' in primitives: %#v", prims) }
}

func TestParseFieldWithModifiers(t *testing.T) {
    f, mt, mods := parseFieldWithModifiers("Image")
    if f != "Image" || mt != "equals" || len(mods) != 0 { t.Fatalf("simple parse bad: %s %s %v", f, mt, mods) }

    f, mt, mods = parseFieldWithModifiers("CommandLine|contains")
    if f != "CommandLine" || mt != "contains" || len(mods) != 0 { t.Fatalf("contains bad: %s %s %v", f, mt, mods) }

    f, mt, mods = parseFieldWithModifiers("Image|startswith")
    if mt != "startswith" { t.Fatalf("startswith bad: %s", mt) }
    f, mt, mods = parseFieldWithModifiers("Image|endswith")
    if mt != "endswith" { t.Fatalf("endswith bad: %s", mt) }
    f, mt, mods = parseFieldWithModifiers("Hash|re")
    if mt != "regex" { t.Fatalf("regex bad: %s", mt) }

    f, mt, mods = parseFieldWithModifiers("User|cased")
    if mt != "equals" || len(mods) != 1 || mods[0] != "case_sensitive" { t.Fatalf("cased bad: %s %v", mt, mods) }

    f, mt, mods = parseFieldWithModifiers("Data|base64offset")
    if len(mods) != 1 || mods[0] != "base64_offset_decode" { t.Fatalf("base64offset bad: %v", mods) }

    f, mt, mods = parseFieldWithModifiers("Data|utf16|utf16le|utf16be|wide")
    want := []string{"utf16_decode","utf16le_decode","utf16be_decode","wide_decode"}
    if len(mods) != len(want) { t.Fatalf("utf16 variants len: %v", mods) }
    for i := range mods { if mods[i] != want[i] { t.Fatalf("utf16 variants mismatch: %v", mods) } }
}

func TestUnsupportedFieldValueType(t *testing.T) {
    c := New()
    rule := `
title: Test
detection:
  selection:
    Obj: { nested: true }
  condition: selection
`
    if _, err := c.CompileRule(rule); err == nil {
        t.Fatalf("expected error for unsupported nested object value")
    }
}

func TestIntoRulesetStructure(t *testing.T) {
    c := New()
    _ , _ = c.CompileRule(`
title: R
detection:
  sel1:
    A: 1
  sel2:
    B: ["x", "y"]
  condition: sel1 and sel2
`)
    rs := c.IntoRuleset()
    if len(rs.Rules) != 1 { t.Fatalf("rules len") }
    r := rs.Rules[0]
    if r.Condition == "" { t.Fatalf("empty condition") }
    if len(r.Selections) != 2 { t.Fatalf("selections len") }
}

// Sanity check with DAG builder integration
func TestCompilerToDag(t *testing.T) {
    c := New()
    _, err := c.CompileRule(`
title: Test
detection:
  selection:
    EventID: 4624
  condition: selection
`)
    if err != nil { t.Fatalf("compile rule: %v", err) }
    rs := c.IntoRuleset()
    if rs.PrimitiveCount() == 0 { t.Fatalf("no primitives") }
    // ensure rule ids are usable
    if _, ok := rs.GetPrimitive(ir.PrimitiveId(0)); !ok { t.Fatalf("primitive 0 missing") }
}

