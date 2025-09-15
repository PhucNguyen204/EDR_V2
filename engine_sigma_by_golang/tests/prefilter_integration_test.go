

package tests

import (
    "testing"

    engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

// Mirrors sigma-engine/tests/prefilter_integration_test.rs::test_prefilter_integration
func TestPrefilterIntegration(t *testing.T) {
    // primitives: EventID == 4624, ProcessName contains powershell.exe
    primsIR := []engine.Primitive{
        engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
        engine.NewPrimitiveStatic("ProcessName", "contains", []string{"powershell.exe"}, nil),
    }

    // Build DAG with just primitives (no rules needed for this integration test)
    d := dag.NewDagBuilder().FromPrimitives(primsIR)
    compiledDag, err := d.Build()
    if err != nil { t.Fatalf("build dag: %v", err) }

    // Compile primitives
    primMap := make(map[uint32]*matcher.CompiledPrimitive, len(primsIR))
    for i := range primsIR {
        cp, err := matcher.FromPrimitive(primsIR[i])
        if err != nil { t.Fatalf("compile primitive %d: %v", i, err) }
        primMap[uint32(i)] = cp
    }

    // Build prefilter
    pf := dag.PrefilterFromPrimitives(primsIR)

    // Evaluator with prefilter
    ev := dag.WithPrimitivesAndPrefilter(compiledDag, primMap, &pf)

    // Non-matching event should yield no matches and short-circuit due to prefilter
    nonMatching := map[string]any{
        "EventID":     "9999",
        "ProcessName": "notepad.exe",
        "CommandLine": "notepad.exe test.txt",
    }
    res1, err := ev.Evaluate(nonMatching)
    if err != nil { t.Fatalf("evaluate non-matching: %v", err) }
    if len(res1.MatchedRules) != 0 {
        t.Fatalf("expected 0 matches, got %d", len(res1.MatchedRules))
    }

    // Matching event shouldn't panic; rule set is empty so matches may be 0
    matching := map[string]any{
        "EventID":     "4624",
        "ProcessName": "powershell.exe",
        "CommandLine": "powershell.exe -Command Test",
    }
    if _, err := ev.Evaluate(matching); err != nil {
        t.Fatalf("evaluate matching: %v", err)
    }
}

// Mirrors sigma-engine/tests/prefilter_integration_test.rs::test_prefilter_vs_no_prefilter
func TestPrefilterVsNoPrefilter(t *testing.T) {
    // Single primitive: EventID == 4624
    primsIR := []engine.Primitive{
        engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
    }

    // Build DAG and compiled primitives
    d := dag.NewDagBuilder().FromPrimitives(primsIR)
    compiledDag, err := d.Build()
    if err != nil { t.Fatalf("build dag: %v", err) }

    primMap := make(map[uint32]*matcher.CompiledPrimitive, len(primsIR))
    for i := range primsIR {
        cp, err := matcher.FromPrimitive(primsIR[i])
        if err != nil { t.Fatalf("compile primitive %d: %v", i, err) }
        primMap[uint32(i)] = cp
    }

    // With prefilter
    pf := dag.PrefilterFromPrimitives(primsIR)
    withPF := dag.WithPrimitivesAndPrefilter(compiledDag, primMap, &pf)

    // Without prefilter
    withoutPF := dag.WithPrimitives(compiledDag, primMap)

    nonMatching := map[string]any{
        "EventID":     "9999",
        "ProcessName": "notepad.exe",
    }

    r1, err := withPF.Evaluate(nonMatching)
    if err != nil { t.Fatalf("evaluate with prefilter: %v", err) }
    r2, err := withoutPF.Evaluate(nonMatching)
    if err != nil { t.Fatalf("evaluate without prefilter: %v", err) }

    if len(r1.MatchedRules) != 0 || len(r2.MatchedRules) != 0 {
        t.Fatalf("expected zero matches from both evaluators")
    }

    if !(r1.PrimitiveEvaluations <= r2.PrimitiveEvaluations) {
        t.Fatalf("expected prefilter to reduce primitive evaluations: with=%d without=%d", r1.PrimitiveEvaluations, r2.PrimitiveEvaluations)
    }
}

