package tests

import (
    "testing"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

// Mirrors sigma-engine/tests/integration_test.rs::test_crate_structure_compiles
func TestCrateStructureCompiles(t *testing.T) {
    _ = compiler.New()
    _ = ir.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
}

// Mirrors test_basic_dag_execution (sanity of empty ruleset)
func TestBasicDagExecution(t *testing.T) {
    c := compiler.New()
    rs := c.IntoRuleset()
    if rs.PrimitiveCount() != 0 {
        t.Fatalf("expected 0 primitives, got %d", rs.PrimitiveCount())
    }
}

// Mirrors test_compiler_basic_functionality
func TestCompilerBasicFunctionality(t *testing.T) {
    c := compiler.New()
    rs := c.IntoRuleset()
    if rs.PrimitiveCount() != 0 {
        t.Fatalf("expected empty ruleset primitives=0, got %d", rs.PrimitiveCount())
    }
}

// Mirrors test_primitive_equality_and_hashing (adapted to Go using Primitive.Key())
func TestPrimitiveEqualityAndHashing(t *testing.T) {
    p1 := ir.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
    p2 := ir.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
    p3 := ir.NewPrimitiveStatic("EventID", "equals", []string{"4625"}, nil)

    if p1.Key() != p2.Key() {
        t.Fatalf("expected p1 == p2 by key")
    }
    if p1.Key() == p3.Key() {
        t.Fatalf("expected p1 != p3 by key")
    }

    // Hash map by key
    m := map[string]int{}
    m[p1.Key()] = 0
    m[p3.Key()] = 1
    if m[p2.Key()] != 0 || len(m) != 2 {
        t.Fatalf("hashing by key failed: %#v", m)
    }
}

// Mirrors test_rule_id_collision_bug: ensure unique rule results in DAG
func TestRuleIdCollisionBug(t *testing.T) {
    c := compiler.New()
    rule1 := `
title: Test Rule 1
id: rule-001
detection:
  selection:
    EventID: 4688
  condition: selection
`
    rule2 := `
title: Test Rule 2
id: rule-002
detection:
  selection:
    EventID: 4689
  condition: selection
`
    rs, err := c.CompileRuleset([]string{rule1, rule2})
    if err != nil { t.Fatalf("compile ruleset: %v", err) }

    d, err := dag.NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("build dag: %v", err) }
    if len(d.RuleResults) != 2 {
        t.Fatalf("expected 2 rule results, got %d", len(d.RuleResults))
    }
}

// --- Helpers for building + evaluating rules ---

func compileRulesToDag(t *testing.T, fm compiler.FieldMapping, rules []string) (*dag.CompiledDag, map[uint32]*matcher.CompiledPrimitive) {
    t.Helper()
    c := compiler.WithFieldMapping(fm)
    rs, err := c.CompileRuleset(rules)
    if err != nil { t.Fatalf("CompileRuleset: %v", err) }
    d, err := dag.NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("Build DAG: %v", err) }
    prims := make(map[uint32]*matcher.CompiledPrimitive, len(rs.Primitives))
    for i := range rs.Primitives {
        cp, err := matcher.FromPrimitive(rs.Primitives[i])
        if err != nil { t.Fatalf("compile primitive %d: %v", i, err) }
        prims[uint32(i)] = cp
    }
    return d, prims
}

func evalRules(t *testing.T, fm compiler.FieldMapping, rules []string, event map[string]any) int {
    t.Helper()
    d, prims := compileRulesToDag(t, fm, rules)
    ev := dag.WithPrimitives(d, prims)
    res, err := ev.Evaluate(event)
    if err != nil { t.Fatalf("Evaluate: %v", err) }
    return len(res.MatchedRules)
}

// Mirrors test_multiple_rules_compilation_bug (DAG uniqueness of rule results)
func TestMultipleRulesCompilationBug_DagRuleResults(t *testing.T) {
    fm := compiler.NewFieldMapping()
    fm.AddMapping("ProcessImage", "Image")
    fm.AddMapping("ProcessCommandLine", "CommandLine")

    rule1 := `
title: Test Rule 1
id: rule-001
detection:
  selection:
    ProcessImage|endswith: '\notepad.exe'
  condition: selection
`
    rule2 := `
title: Test Rule 2
id: rule-002
detection:
  selection:
    ProcessCommandLine|contains: 'test'
  condition: selection
`

    c := compiler.New()
    rs, err := c.CompileRuleset([]string{rule1, rule2})
    if err != nil { t.Fatalf("CompileRuleset: %v", err) }
    d, err := dag.NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("Build DAG: %v", err) }
    if len(d.RuleResults) != 2 {
        t.Fatalf("expected 2 rule results, got %d", len(d.RuleResults))
    }
}

// Mirrors test_multiple_rules_different_fields
func TestMultipleRulesDifferentFields(t *testing.T) {
    fm := compiler.NewFieldMapping()
    fm.AddMapping("ProcessImage", "Image")
    fm.AddMapping("ProcessCommandLine", "CommandLine")
    fm.AddMapping("EventID", "EventID")

    rule1 := `
title: EventID Rule
id: rule-eventid
detection:
  selection:
    EventID: 4688
  condition: selection
`
    rule2 := `
title: Image Rule
id: rule-image
detection:
  selection:
    ProcessImage|endswith: '\cmd.exe'
  condition: selection
`
    rule3 := `
title: CommandLine Rule
id: rule-cmdline
detection:
  selection:
    ProcessCommandLine|contains: 'whoami'
  condition: selection
`

    event := map[string]any{
        "EventID": 4688,
        "Image":    "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
    }

    // Individually each should match
    if n := evalRules(t, fm, []string{rule1}, event); n == 0 { t.Fatalf("EventID rule should match individually") }
    if n := evalRules(t, fm, []string{rule2}, event); n == 0 { t.Fatalf("Image rule should match individually") }
    if n := evalRules(t, fm, []string{rule3}, event); n == 0 { t.Fatalf("CMD rule should match individually") }

    // Together, all three should match
    if n := evalRules(t, fm, []string{rule1, rule2, rule3}, event); n != 3 {
        t.Fatalf("expected 3 matches together, got %d", n)
    }
}

// Mirrors test_multiple_rules_and_conditions
func TestMultipleRulesAndConditions(t *testing.T) {
    fm := compiler.NewFieldMapping()
    fm.AddMapping("ProcessImage", "Image")
    fm.AddMapping("ProcessCommandLine", "CommandLine")

    rule1 := `
title: AND Rule 1
id: rule-and-1
detection:
  selection_image:
    ProcessImage|endswith: '\powershell.exe'
  selection_cmdline:
    ProcessCommandLine|contains: 'Invoke'
  condition: selection_image and selection_cmdline
`
    rule2 := `
title: AND Rule 2
id: rule-and-2
detection:
  selection_image:
    ProcessImage|endswith: '\cmd.exe'
  selection_cmdline:
    ProcessCommandLine|contains: 'echo'
  condition: selection_image and selection_cmdline
`

    event1 := map[string]any{
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -Command Invoke-WebRequest",
    }
    event2 := map[string]any{
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c echo hello",
    }
    event3 := map[string]any{
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe test.txt",
    }

    if n := evalRules(t, fm, []string{rule1, rule2}, event1); n != 1 {
        t.Fatalf("event1 expected 1 match, got %d", n)
    }
    if n := evalRules(t, fm, []string{rule1, rule2}, event2); n != 1 {
        t.Fatalf("event2 expected 1 match, got %d", n)
    }
    if n := evalRules(t, fm, []string{rule1, rule2}, event3); n != 0 {
        t.Fatalf("event3 expected 0 match, got %d", n)
    }
}

// Mirrors test_multiple_rules_or_conditions
func TestMultipleRulesOrConditions(t *testing.T) {
    fm := compiler.NewFieldMapping()
    fm.AddMapping("ProcessImage", "Image")
    fm.AddMapping("ProcessCommandLine", "CommandLine")

    rule1 := `
title: OR Rule 1
id: rule-or-1
detection:
  selection_image:
    ProcessImage|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
  condition: selection_image
`
    rule2 := `
title: OR Rule 2
id: rule-or-2
detection:
  selection_cmdline:
    ProcessCommandLine|contains:
      - 'test'
      - 'debug'
  condition: selection_cmdline
`

    eventBoth := map[string]any{
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c test.bat",
    }
    eventRule1 := map[string]any{
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -Command Get-Process",
    }
    eventRule2 := map[string]any{
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe debug.log",
    }

    if n := evalRules(t, fm, []string{rule1, rule2}, eventBoth); n != 2 {
        t.Fatalf("eventBoth expected 2 matches, got %d", n)
    }
    if n := evalRules(t, fm, []string{rule1, rule2}, eventRule1); n != 1 {
        t.Fatalf("eventRule1 expected 1 match, got %d", n)
    }
    if n := evalRules(t, fm, []string{rule1, rule2}, eventRule2); n != 1 {
        t.Fatalf("eventRule2 expected 1 match, got %d", n)
    }
}

// Mirrors test_multiple_rules_shared_primitives
func TestMultipleRulesSharedPrimitives(t *testing.T) {
    fm := compiler.NewFieldMapping()
    fm.AddMapping("EventID", "EventID")
    fm.AddMapping("ProcessImage", "Image")

    rule1 := `
title: Shared Primitive Rule 1
id: rule-shared-1
detection:
  selection:
    EventID: 4688
    ProcessImage|endswith: '\notepad.exe'
  condition: selection
`
    rule2 := `
title: Shared Primitive Rule 2
id: rule-shared-2
detection:
  selection:
    EventID: 4688
    ProcessImage|endswith: '\calc.exe'
  condition: selection
`

    event1 := map[string]any{"EventID": 4688, "Image": "C:\\Windows\\System32\\notepad.exe"}
    event2 := map[string]any{"EventID": 4688, "Image": "C:\\Windows\\System32\\calc.exe"}
    event3 := map[string]any{"EventID": 4689, "Image": "C:\\Windows\\System32\\notepad.exe"}

    if n := evalRules(t, fm, []string{rule1, rule2}, event1); n != 1 {
        t.Fatalf("event1 expected 1 match, got %d", n)
    }
    if n := evalRules(t, fm, []string{rule1, rule2}, event2); n != 1 {
        t.Fatalf("event2 expected 1 match, got %d", n)
    }
    if n := evalRules(t, fm, []string{rule1, rule2}, event3); n != 0 {
        t.Fatalf("event3 expected 0 match, got %d", n)
    }
}

// Mirrors test_multiple_rules_complex_conditions
func TestMultipleRulesComplexConditions(t *testing.T) {
    fm := compiler.NewFieldMapping()
    fm.AddMapping("ProcessImage", "Image")
    fm.AddMapping("ProcessCommandLine", "CommandLine")
    fm.AddMapping("ParentProcessImage", "ParentImage")

    rule1 := `
title: Complex Rule 1
id: rule-complex-1
detection:
  selection_process:
    ProcessImage|endswith: '\powershell.exe'
  selection_parent:
    ParentProcessImage|endswith: '\cmd.exe'
  selection_cmdline:
    ProcessCommandLine|contains: 'Invoke'
  condition: selection_process and (selection_parent or selection_cmdline)
`
    rule2 := `
title: Complex Rule 2
id: rule-complex-2
detection:
  selection_process:
    ProcessImage|endswith: '\cmd.exe'
  selection_cmdline:
    ProcessCommandLine|contains: 'echo'
  condition: selection_process and selection_cmdline
`

    event1 := map[string]any{
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -Command Invoke-WebRequest",
        "ParentImage": "C:\\Windows\\System32\\explorer.exe",
    }
    event2 := map[string]any{
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c echo test",
        "ParentImage": "C:\\Windows\\System32\\explorer.exe",
    }

    if n := evalRules(t, fm, []string{rule1, rule2}, event1); n != 1 {
        t.Fatalf("event1 expected 1 match, got %d", n)
    }
    if n := evalRules(t, fm, []string{rule1, rule2}, event2); n != 1 {
        t.Fatalf("event2 expected 1 match, got %d", n)
    }
}
