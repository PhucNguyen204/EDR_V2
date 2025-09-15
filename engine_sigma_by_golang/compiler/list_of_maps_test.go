package compiler

import (
    "testing"
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// Test that a selection defined as a list of maps compiles into Disjunctions (OR-of-AND groups)
func TestCompileSelectionListOfMaps_WMIC(t *testing.T) {
    yamlRule := `
title: Suspicious WMIC Execution Via Office Process
id: e1693bc8-7168-4eab-8718-cdcaa68a1738
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
  selection_wmic_img:
    - Image|endswith: '\\wbem\\WMIC.exe'
    - OriginalFileName: 'wmic.exe'
  selection_wmic_cli:
    CommandLine|contains|all:
      - 'process'
      - 'create'
      - 'call'
    CommandLine|contains:
      - 'regsvr32'
      - 'mshta'
  condition: all of selection_*
`

    comp := New()
    rs, err := comp.CompileRuleset([]string{yamlRule})
    if err != nil { t.Fatalf("CompileRuleset error: %v", err) }
    if len(rs.Rules) != 1 { t.Fatalf("expected 1 rule, got %d", len(rs.Rules)) }
    r := rs.Rules[0]

    // selection_wmic_img must be present in Disjunctions with two groups
    groups, ok := r.Disjunctions["selection_wmic_img"]
    if !ok { t.Fatalf("selection_wmic_img disjunctions missing") }
    if len(groups) != 2 { t.Fatalf("expected 2 disjunction groups, got %d", len(groups)) }

    // Each group should have exactly one primitive id
    for i, g := range groups {
        if len(g) != 1 { t.Fatalf("group %d expected 1 primitive, got %d", i, len(g)) }
    }

    // Validate primitives refer to Image|endswith '\\wbem\\WMIC.exe' and OriginalFileName == 'wmic.exe'
    // We don't assume order; check both.
    var seenEndswith, seenExact bool
    for _, g := range groups {
        pid := g[0]
        prim, ok := rs.GetPrimitive(ir.PrimitiveId(pid))
        if !ok { t.Fatalf("primitive %d not found", pid) }
        switch prim.Field {
        case "Image":
            if prim.MatchType != "endswith" { t.Fatalf("Image match type want endswith, got %s", prim.MatchType) }
            if len(prim.Values) != 1 { t.Fatalf("unexpected Image values len: %v", prim.Values) }
            v := prim.Values[0]
            if !(len(v) > 0 && (v == "\\wbem\\WMIC.exe" || v == "\\\\wbem\\\\WMIC.exe")) {
                t.Fatalf("unexpected Image value: %v", prim.Values)
            }
            seenEndswith = true
        case "OriginalFileName":
            if prim.MatchType != "equals" { t.Fatalf("OriginalFileName match type want equals, got %s", prim.MatchType) }
            if len(prim.Values) != 1 || prim.Values[0] != "wmic.exe" { t.Fatalf("unexpected OriginalFileName value: %v", prim.Values) }
            seenExact = true
        default:
            t.Fatalf("unexpected field in disjunction primitive: %s", prim.Field)
        }
    }
    if !seenEndswith || !seenExact { t.Fatalf("expected both endswith(Image) and equals(OriginalFileName) in disjunctions") }

    // Also ensure normal selections are still present
    if _, ok := r.Selections["selection_parent"]; !ok {
        t.Fatalf("selection_parent missing in Selections")
    }
    if _, ok := r.Selections["selection_wmic_cli"]; !ok {
        t.Fatalf("selection_wmic_cli missing in Selections")
    }
}
