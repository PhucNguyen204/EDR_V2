package dag

import (
	"testing"

	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func createOptTestDag() CompiledDag {
	dag := *NewCompiledDag()

	// Add primitive nodes 0 and 1
	p0 := NewDagNode(0, PrimitiveType(ir.PrimitiveId(0)))
	p0.Dependents = []NodeId{2}
	p1 := NewDagNode(1, PrimitiveType(ir.PrimitiveId(1)))
	p1.Dependents = []NodeId{2}
	dag.AddNode(p0)
	dag.AddNode(p1)

	// Logical AND node 2 depends on 0,1 and feeds 3
	ln := NewDagNode(2, LogicalType(LogicalAnd))
	ln.Dependencies = []NodeId{0, 1}
	ln.Dependents = []NodeId{3}
	dag.AddNode(ln)

	// Result node 3 depends on 2
	rn := NewDagNode(3, ResultType(ir.RuleId(1)))
	rn.Dependencies = []NodeId{2}
	dag.AddNode(rn)

	dag.PrimitiveMap[ir.PrimitiveId(0)] = 0
	dag.PrimitiveMap[ir.PrimitiveId(1)] = 1
	dag.RuleResults[ir.RuleId(1)] = 3
	dag.ExecutionOrder = []NodeId{0, 1, 2, 3}
	return dag
}

func TestDagOptimizerCreation(t *testing.T) {
	o := NewDagOptimizer()
	if !o.enableCSE || !o.enableDCE {
		t.Fatalf("defaults not enabled")
	}
}

func TestDagOptimizerConfig(t *testing.T) {
	o := NewDagOptimizer().WithCSE(false).WithDCE(false)
	if o.enableCSE || o.enableDCE {
		t.Fatalf("config did not apply")
	}
}

func TestDagOptimizerPartialConfig(t *testing.T) {
	o := NewDagOptimizer().WithCSE(false)
	if o.enableCSE {
		t.Fatalf("cse should be disabled")
	}
	if !o.enableDCE {
		t.Fatalf("dce should remain enabled by default")
	}
}

func TestOptimizeEmptyDag(t *testing.T) {
	o := NewDagOptimizer()
	dag := *NewCompiledDag()
	out, err := o.Optimize(dag)
	if err != nil {
		t.Fatalf("optimize empty: %v", err)
	}
	if len(out.Nodes) != 0 || len(out.ExecutionOrder) != 0 {
		t.Fatalf("expected empty outputs")
	}
}

func TestOptimizeSimpleDag(t *testing.T) {
	o := NewDagOptimizer()
	dag := createOptTestDag()
	out, err := o.Optimize(dag)
	if err != nil {
		t.Fatalf("optimize error: %v", err)
	}
	if len(out.Nodes) == 0 || len(out.ExecutionOrder) == 0 {
		t.Fatalf("unexpected empty results")
	}
}

func TestMarkReachable(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer()
	set := make(map[NodeId]struct{})
	o.markReachable(3, &dag, set)
	if _, ok := set[NodeId(3)]; !ok {
		t.Fatalf("3 not marked")
	}
	if _, ok := set[NodeId(2)]; !ok {
		t.Fatalf("2 not marked")
	}
	if _, ok := set[NodeId(1)]; !ok {
		t.Fatalf("1 not marked")
	}
	if _, ok := set[NodeId(0)]; !ok {
		t.Fatalf("0 not marked")
	}
}

func TestMarkReachableIdempotent(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer()
	set := map[NodeId]struct{}{2: {}}
	o.markReachable(2, &dag, set)
	if _, ok := set[2]; !ok {
		t.Fatalf("2 missing")
	}
}

func TestMarkReachableNonexistent(t *testing.T) {
	dag := *NewCompiledDag()
	o := NewDagOptimizer()
	set := make(map[NodeId]struct{})
	o.markReachable(999, &dag, set)
	if _, ok := set[999]; !ok {
		t.Fatalf("nonexistent not recorded")
	}
}

func TestTopologicalSort(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer()
	ord, err := o.topologicalSort(&dag)
	if err != nil {
		t.Fatalf("toposort error: %v", err)
	}
	if len(ord) != 4 {
		t.Fatalf("want 4, got %d", len(ord))
	}
	pos := func(id NodeId) int {
		for i, v := range ord {
			if v == id {
				return i
			}
		}
		return -1
	}
	if !(pos(0) < pos(2) && pos(1) < pos(2) && pos(2) < pos(3)) {
		t.Fatalf("order does not respect deps: %v", ord)
	}
}

func TestTopologicalSortEmpty(t *testing.T) {
	dag := *NewCompiledDag()
	o := NewDagOptimizer()
	ord, err := o.topologicalSort(&dag)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(ord) != 0 {
		t.Fatalf("expected empty order")
	}
}

func TestApplyNodeMapping(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer()
	mapping := map[NodeId]NodeId{1: 0}
	out, err := o.applyNodeMapping(dag, mapping)
	if err != nil {
		t.Fatalf("apply mapping err: %v", err)
	}
	if len(out.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(out.Nodes))
	}
	// find logical node and check deps
	var logical *DagNode
	for i := range out.Nodes {
		if out.Nodes[i].NodeType.Kind == NodeLogical {
			logical = &out.Nodes[i]
			break
		}
	}
	if logical == nil {
		t.Fatalf("logical node not found")
	}
	// After merging 1->0, deps should be [0] only
	if len(logical.Dependencies) != 1 || logical.Dependencies[0] != 0 {
		t.Fatalf("unexpected deps: %v", logical.Dependencies)
	}
}

func TestApplyNodeMappingEmpty(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer()
	out, err := o.applyNodeMapping(dag, map[NodeId]NodeId{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Nodes) != 4 {
		t.Fatalf("expected unchanged nodes=4, got %d", len(out.Nodes))
	}
}

func TestCSENoDuplicates(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer()
	out, err := o.commonSubexpressionElimination(dag)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(out.Nodes))
	}
}

func TestDCEAllReachable(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer()
	out, err := o.deadCodeElimination(dag)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(out.Nodes))
	}
}

func TestDCEWithUnreachable(t *testing.T) {
	dag := createOptTestDag()
	// add unreachable node
	u := NewDagNode(99, PrimitiveType(ir.PrimitiveId(99)))
	dag.AddNode(u)
	o := NewDagOptimizer()
	out, err := o.deadCodeElimination(dag)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Nodes) != 4 {
		t.Fatalf("expected 4 nodes after DCE, got %d", len(out.Nodes))
	}
	if _, ok := out.GetNode(99); ok {
		t.Fatalf("unreachable node still present")
	}
}

func TestRebuildExecutionOrder(t *testing.T) {
	dag := createOptTestDag()
	dag.ExecutionOrder = []NodeId{3, 2, 1, 0}
	o := NewDagOptimizer()
	out, err := o.rebuildExecutionOrderOptimized(dag)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.ExecutionOrder) != 4 {
		t.Fatalf("expected 4 order")
	}
	pos := func(id NodeId) int {
		for i, v := range out.ExecutionOrder {
			if v == id {
				return i
			}
		}
		return -1
	}
	if !(pos(0) < pos(2) && pos(1) < pos(2) && pos(2) < pos(3)) {
		t.Fatalf("order does not respect deps: %v", out.ExecutionOrder)
	}
}

func TestOptimizeWithAllDisabled(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer().WithCSE(false).WithDCE(false)
	out, err := o.Optimize(dag)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Nodes) != len(dag.Nodes) {
		t.Fatalf("node count changed")
	}
}

func TestOptimizeSelective(t *testing.T) {
	dag := createOptTestDag()
	o := NewDagOptimizer().WithCSE(true).WithDCE(false)
	out, err := o.Optimize(dag)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.ExecutionOrder) == 0 {
		t.Fatalf("expected non-empty order")
	}
}
