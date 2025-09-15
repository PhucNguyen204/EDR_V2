package dag

import (
    "testing"
    compiler "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func makeRulesetForBuilder() *ir.CompiledRuleset {
    rs := ir.NewCompiledRuleset()
    // primitives
    p0 := ir.NewPrimitive("EventID", "equals", []string{"4624"}, nil)
    p1 := ir.NewPrimitive("Image", "contains", []string{"powershell"}, nil)
    id0 := rs.InternPrimitive(p0)
    id1 := rs.InternPrimitive(p1)
    // rule selections
    sels := map[string][]ir.PrimitiveId{
        "sel1": {id0},
        "sel2": {id1},
    }
    r := ir.CompiledRule{
        RuleId:    1,
        Selections: sels,
        Condition:  "sel1 and sel2",
    }
    rs.AddRule(r)
    return rs
}

func TestDagBuilderFromRuleset_BasicAnd(t *testing.T) {
    rs := makeRulesetForBuilder()
    b := NewDagBuilder()
    dag, err := b.FromRuleset(rs).Build()
    if err != nil { t.Fatalf("build err: %v", err) }
    if dag.NodeCount() == 0 { t.Fatalf("empty dag") }
    // expect at least 4 nodes: p0, p1, AND, RESULT
    if dag.NodeCount() < 4 { t.Fatalf("expected >=4 nodes, got %d", dag.NodeCount()) }
}

func TestDagBuilderSelectionOneOfThem(t *testing.T) {
    rs := ir.NewCompiledRuleset()
    // 3 primitives
    id0 := rs.InternPrimitive(ir.NewPrimitive("f1","equals",[]string{"a"},nil))
    id1 := rs.InternPrimitive(ir.NewPrimitive("f2","equals",[]string{"b"},nil))
    id2 := rs.InternPrimitive(ir.NewPrimitive("f3","equals",[]string{"c"},nil))
    sels := map[string][]ir.PrimitiveId{
        "s1": {id0},
        "s2": {id1},
        "s3": {id2},
    }
    r := ir.CompiledRule{RuleId: 0, Selections: sels, Condition: "1 of them"}
    rs.AddRule(r)
    dag, err := NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("err: %v", err) }
    if len(dag.RuleResults) != 1 { t.Fatalf("expected 1 rule result, got %d", len(dag.RuleResults)) }
}

func TestDagBuilderAllOfThem(t *testing.T) {
    rs := ir.NewCompiledRuleset()
    id0 := rs.InternPrimitive(ir.NewPrimitive("f1","equals",[]string{"a"},nil))
    id1 := rs.InternPrimitive(ir.NewPrimitive("f2","equals",[]string{"b"},nil))
    sels := map[string][]ir.PrimitiveId{"s1": {id0}, "s2": {id1}}
    r := ir.CompiledRule{RuleId: 0, Selections: sels, Condition: "all of them"}
    rs.AddRule(r)
    dag, err := NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("err: %v", err) }
    if len(dag.RuleResults) != 1 { t.Fatalf("expected 1 result, got %d", len(dag.RuleResults)) }
}

func TestDagBuilderAllOfPattern(t *testing.T) {
    rs := ir.NewCompiledRuleset()
    id0 := rs.InternPrimitive(ir.NewPrimitive("f1","equals",[]string{"a"},nil))
    id1 := rs.InternPrimitive(ir.NewPrimitive("f2","equals",[]string{"b"},nil))
    sels := map[string][]ir.PrimitiveId{"selA": {id0}, "x_selA_y": {id1}}
    r := ir.CompiledRule{RuleId: 0, Selections: sels, Condition: "all of selA*"}
    rs.AddRule(r)
    dag, err := NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("err: %v", err) }
    if len(dag.RuleResults) != 1 { t.Fatalf("expected 1 result, got %d", len(dag.RuleResults)) }
}

func TestDagBuilderCountOfPattern(t *testing.T) {
    rs := ir.NewCompiledRuleset()
    id0 := rs.InternPrimitive(ir.NewPrimitive("f1","equals",[]string{"a"},nil))
    id1 := rs.InternPrimitive(ir.NewPrimitive("f2","equals",[]string{"b"},nil))
    id2 := rs.InternPrimitive(ir.NewPrimitive("f3","equals",[]string{"c"},nil))
    sels := map[string][]ir.PrimitiveId{"sel1": {id0}, "sel2": {id1}, "other": {id2}}
    r := ir.CompiledRule{RuleId: 0, Selections: sels, Condition: "2 of sel*"}
    rs.AddRule(r)
    dag, err := NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("err: %v", err) }
    if len(dag.RuleResults) != 1 { t.Fatalf("expected 1 result, got %d", len(dag.RuleResults)) }
}

func TestDagBuilderFromPrimitivesOnly(t *testing.T) {
    prims := []ir.Primitive{
        ir.NewPrimitive("f1","equals",[]string{"a"},nil),
        ir.NewPrimitive("f2","equals",[]string{"b"},nil),
    }
    dag, err := NewDagBuilder().FromPrimitives(prims).Build()
    if err == nil && dag.NodeCount() == 0 { t.Fatalf("expected nodes for primitives") }
}

func TestDagBuilderTopologicalOrder(t *testing.T) {
    rs := makeRulesetForBuilder()
    b := NewDagBuilder()
    dag, err := b.FromRuleset(rs).Build()
    if err != nil { t.Fatalf("err: %v", err) }
    // verify execution order includes all nodes
    if len(dag.ExecutionOrder) != dag.NodeCount() {
        t.Fatalf("order length mismatch: %d vs %d", len(dag.ExecutionOrder), dag.NodeCount())
    }
}

func TestDagBuilderParserIntegration(t *testing.T) {
    // sanity-check tokenizer and parser with builder
    toks, err := compiler.TokenizeCondition("(sel1 and sel2) or not sel3")
    if err != nil || len(toks) == 0 { t.Fatalf("tokenize err: %v", err) }
}
