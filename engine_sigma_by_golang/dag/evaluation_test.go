package dag

import (
    "testing"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

// --- Helpers ---

func createEvalDag(t *testing.T) *CompiledDag {
    t.Helper()
    dag := NewCompiledDag()

    prim := NewDagNode(0, PrimitiveType(ir.PrimitiveId(0)))
    dag.AddNode(prim)

    log := NewDagNode(1, LogicalType(LogicalAnd))
    log.AddDependency(0)
    dag.AddNode(log)

    dag.ExecutionOrder = []NodeId{0, 1}
    dag.RuleResults[ir.RuleId(1)] = 1
    dag.PrimitiveMap[ir.PrimitiveId(0)] = 0

    if err := dag.Validate(); err != nil {
        t.Fatalf("test dag validation failed: %v", err)
    }
    return dag
}

func createEvalPrimitives(t *testing.T) map[uint32]*matcher.CompiledPrimitive {
    t.Helper()
    p := ir.NewPrimitive("field1", "equals", []string{"value1"}, nil)
    cp, err := matcher.FromPrimitive(p)
    if err != nil {
        t.Fatalf("compile primitive: %v", err)
    }
    return map[uint32]*matcher.CompiledPrimitive{0: cp}
}

// --- Tests mirrored from Rust evaluator.rs ---

func TestDagEvaluationResultDefault(t *testing.T) {
    var r DagEvaluationResult
    if len(r.MatchedRules) != 0 {
        t.Fatalf("matched_rules len = %d, want 0", len(r.MatchedRules))
    }
    if r.NodesEvaluated != 0 {
        t.Fatalf("nodes_evaluated = %d, want 0", r.NodesEvaluated)
    }
    if r.PrimitiveEvaluations != 0 {
        t.Fatalf("primitive_evaluations = %d, want 0", r.PrimitiveEvaluations)
    }
}

func TestDagEvaluatorCreation(t *testing.T) {
    dag := createEvalDag(t)
    prims := createEvalPrimitives(t)
    e := WithPrimitives(dag, prims)

    if len(e.fastResults) != len(dag.Nodes) {
        t.Fatalf("fastResults len = %d, want %d", len(e.fastResults), len(dag.Nodes))
    }
    if e.nodesEvaluated != 0 {
        t.Fatalf("nodesEvaluated = %d, want 0", e.nodesEvaluated)
    }
    if e.primitiveEvaluations != 0 {
        t.Fatalf("primitiveEvaluations = %d, want 0", e.primitiveEvaluations)
    }
}

func TestStrategySelection(t *testing.T) {
    dag := createEvalDag(t)
    prims := createEvalPrimitives(t)
    e := WithPrimitives(dag, prims)

    if got := e.selectStrategy(1); got != EvalSingle {
        t.Fatalf("selectStrategy(1) = %v, want EvalSingle", got)
    }
    if got := e.selectStrategy(10); got != EvalBatch {
        t.Fatalf("selectStrategy(10) = %v, want EvalBatch", got)
    }
}

func TestBatchMemoryPool(t *testing.T) {
    pool := newBatchMemoryPool()
    pool.ResizeFor(10, 5, 3)
    if len(pool.PrimitiveResults) != 3 {
        t.Fatalf("primitive_results len = %d, want 3", len(pool.PrimitiveResults))
    }
    if len(pool.NodeResults) != 5 {
        t.Fatalf("node_results len = %d, want 5", len(pool.NodeResults))
    }

    pool.Reset()
    for i, buf := range pool.PrimitiveResults {
        for j, v := range buf {
            if v {
                t.Fatalf("primitive_results[%d][%d] not reset to false", i, j)
            }
        }
    }
}

func TestLogicalOperationsVec(t *testing.T) {
    dag := createEvalDag(t)
    prims := createEvalPrimitives(t)
    e := WithPrimitives(dag, prims)

    e.fastResults = make([]bool, len(dag.Nodes))

    // AND: true && true
    e.fastResults[0] = true
    e.fastResults[1] = true
    if ok, err := e.evaluateLogicalOperationWithVec(LogicalAnd, []NodeId{0, 1}); err != nil || !ok {
        t.Fatalf("AND eval got (%v,%v), want (true,nil)", ok, err)
    }

    // OR: false || true
    e.fastResults[0] = false
    e.fastResults[1] = true
    if ok, err := e.evaluateLogicalOperationWithVec(LogicalOr, []NodeId{0, 1}); err != nil || !ok {
        t.Fatalf("OR eval got (%v,%v), want (true,nil)", ok, err)
    }

    // NOT: !false => true
    e.fastResults[0] = false
    if ok, err := e.evaluateLogicalOperationWithVec(LogicalNot, []NodeId{0}); err != nil || !ok {
        t.Fatalf("NOT eval got (%v,%v), want (true,nil)", ok, err)
    }
}

func TestEmptyBatchEvaluation(t *testing.T) {
    dag := createEvalDag(t)
    prims := createEvalPrimitives(t)
    e := WithPrimitives(dag, prims)

    results, err := e.EvaluateBatch([]any{})
    if err != nil {
        t.Fatalf("EvaluateBatch([]) error: %v", err)
    }
    if len(results) != 0 {
        t.Fatalf("results len = %d, want 0", len(results))
    }
}

func TestSingleEventEvaluation(t *testing.T) {
    dag := createEvalDag(t)
    prims := createEvalPrimitives(t)
    e := WithPrimitives(dag, prims)

    event := map[string]any{"field1": "value1"}
    res, err := e.Evaluate(event)
    if err != nil {
        t.Fatalf("Evaluate error: %v", err)
    }
    if len(res.MatchedRules) != 1 {
        t.Fatalf("matched rules = %d, want 1", len(res.MatchedRules))
    }
    if res.MatchedRules[0] != ir.RuleId(1) {
        t.Fatalf("matched rule id = %d, want 1", res.MatchedRules[0])
    }
}
