package dag

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func makeBool(b bool) *bool { return &b }

func createTestDag() *CompiledDag {
	dag := NewCompiledDag()

	// primitive 0 -> dependent 2
	p1 := NewDagNode(0, PrimitiveType(engine.PrimitiveId(0)))
	p1.AddDependent(2)
	// primitive 1 -> dependent 2
	p2 := NewDagNode(1, PrimitiveType(engine.PrimitiveId(1)))
	p2.AddDependent(2)

	dag.AddNode(p1)
	dag.AddNode(p2)

	// logical (AND) depends on 0,1 -> dependent 3
	l := NewDagNode(2, LogicalType(LogicalAnd))
	l.AddDependency(0)
	l.AddDependency(1)
	l.AddDependent(3)
	dag.AddNode(l)

	// result(rule_id=1) depends on 2
	r := NewDagNode(3, ResultType(engine.RuleId(1)))
	r.AddDependency(2)
	dag.AddNode(r)

	dag.PrimitiveMap[engine.PrimitiveId(0)] = 0
	dag.PrimitiveMap[engine.PrimitiveId(1)] = 1
	dag.RuleResults[engine.RuleId(1)] = 3
	dag.ExecutionOrder = []NodeId{0, 1, 2, 3}

	return dag
}

func TestLogicalOpEquality(t *testing.T) {
	if LogicalAnd != LogicalAnd || LogicalOr != LogicalOr || LogicalNot != LogicalNot {
		t.Fatalf("enum self equality failed")
	}
	if LogicalAnd == LogicalOr || LogicalOr == LogicalNot || LogicalAnd == LogicalNot {
		t.Fatalf("enum inequality failed")
	}
}

func TestLogicalOpString(t *testing.T) {
	if LogicalAnd.String() != "And" || LogicalOr.String() != "Or" || LogicalNot.String() != "Not" {
		t.Fatalf("stringer mismatch: %s %s %s", LogicalAnd, LogicalOr, LogicalNot)
	}
}

func TestNodeTypeEquality(t *testing.T) {
	primitive1 := PrimitiveType(engine.PrimitiveId(1))
	primitive2 := PrimitiveType(engine.PrimitiveId(1))
	primitive3 := PrimitiveType(engine.PrimitiveId(2))

	if !reflect.DeepEqual(primitive1, primitive2) {
		t.Fatalf("primitive equality failed")
	}
	if reflect.DeepEqual(primitive1, primitive3) {
		t.Fatalf("primitive inequality failed")
	}

	logical1 := LogicalType(LogicalAnd)
	logical2 := LogicalType(LogicalAnd)
	logical3 := LogicalType(LogicalOr)

	if !reflect.DeepEqual(logical1, logical2) {
		t.Fatalf("logical equality failed")
	}
	if reflect.DeepEqual(logical1, logical3) {
		t.Fatalf("logical inequality failed")
	}

	result1 := ResultType(engine.RuleId(1))
	result2 := ResultType(engine.RuleId(1))
	result3 := ResultType(engine.RuleId(2))

	if !reflect.DeepEqual(result1, result2) || reflect.DeepEqual(result1, result3) {
		t.Fatalf("result equality/inequality failed")
	}

	pref1 := PrefilterType(1, 5)
	pref2 := PrefilterType(1, 5)
	pref3 := PrefilterType(2, 5)

	if !reflect.DeepEqual(pref1, pref2) || reflect.DeepEqual(pref1, pref3) {
		t.Fatalf("prefilter equality/inequality failed")
	}

	if reflect.DeepEqual(primitive1, logical1) || reflect.DeepEqual(logical1, result1) || reflect.DeepEqual(primitive1, result1) {
		t.Fatalf("cross kind equality should fail")
	}
}

func TestNodeTypeString(t *testing.T) {
	primitive := PrimitiveType(engine.PrimitiveId(42))
	s1 := primitive.String()
	if !strings.Contains(s1, "Primitive") || !strings.Contains(s1, "42") {
		t.Fatalf("primitive string: %s", s1)
	}

	logical := LogicalType(LogicalAnd)
	s2 := logical.String()
	if !strings.Contains(s2, "Logical") || !strings.Contains(s2, "And") {
		t.Fatalf("logical string: %s", s2)
	}

	result := ResultType(engine.RuleId(123))
	s3 := result.String()
	if !strings.Contains(s3, "Result") || !strings.Contains(s3, "123") {
		t.Fatalf("result string: %s", s3)
	}
}

func TestDagNodeCreation(t *testing.T) {
	n := NewDagNode(42, PrimitiveType(engine.PrimitiveId(1)))
	if n.ID != 42 {
		t.Fatalf("id")
	}
	if !reflect.DeepEqual(n.NodeType, PrimitiveType(engine.PrimitiveId(1))) {
		t.Fatalf("node type")
	}
	if len(n.Dependencies) != 0 || len(n.Dependents) != 0 {
		t.Fatalf("deps/outs should be empty")
	}
	if n.CachedResult != nil {
		t.Fatalf("cache should be nil")
	}
}

func TestDagNodeAddDependency(t *testing.T) {
	n := NewDagNode(1, LogicalType(LogicalAnd))
	n.AddDependency(10)
	if !reflect.DeepEqual(n.Dependencies, []NodeId{10}) {
		t.Fatalf("deps 1")
	}
	n.AddDependency(20)
	if !reflect.DeepEqual(n.Dependencies, []NodeId{10, 20}) {
		t.Fatalf("deps 2")
	}
	n.AddDependency(10) // duplicate
	if !reflect.DeepEqual(n.Dependencies, []NodeId{10, 20}) {
		t.Fatalf("deps dup")
	}
}

func TestDagNodeAddDependent(t *testing.T) {
	n := NewDagNode(1, PrimitiveType(engine.PrimitiveId(1)))
	n.AddDependent(10)
	if !reflect.DeepEqual(n.Dependents, []NodeId{10}) {
		t.Fatalf("outs 1")
	}
	n.AddDependent(20)
	if !reflect.DeepEqual(n.Dependents, []NodeId{10, 20}) {
		t.Fatalf("outs 2")
	}
	n.AddDependent(10) // duplicate
	if !reflect.DeepEqual(n.Dependents, []NodeId{10, 20}) {
		t.Fatalf("outs dup")
	}
}

func TestDagNodeClearCache(t *testing.T) {
	n := NewDagNode(1, PrimitiveType(engine.PrimitiveId(1)))
	if n.CachedResult != nil {
		t.Fatalf("init cache")
	}
	b := true
	n.CachedResult = &b
	if n.CachedResult == nil || *n.CachedResult != true {
		t.Fatalf("set cache")
	}
	n.ClearCache()
	if n.CachedResult != nil {
		t.Fatalf("clear cache")
	}
}

func TestDagNodeIsLeaf(t *testing.T) {
	n := NewDagNode(1, PrimitiveType(engine.PrimitiveId(1)))
	if !n.IsLeaf() {
		t.Fatalf("leaf")
	}
	n.AddDependency(10)
	if n.IsLeaf() {
		t.Fatalf("not leaf")
	}
	n.Dependencies = nil
	if !n.IsLeaf() {
		t.Fatalf("leaf again")
	}
}

func TestDagNodeIsRoot(t *testing.T) {
	n := NewDagNode(1, ResultType(engine.RuleId(1)))
	if !n.IsRoot() {
		t.Fatalf("root")
	}
	n.AddDependent(10)
	if n.IsRoot() {
		t.Fatalf("not root")
	}
	n.Dependents = nil
	if !n.IsRoot() {
		t.Fatalf("root again")
	}
}

func TestDagNodeCopy(t *testing.T) {
	n := NewDagNode(1, LogicalType(LogicalOr))
	n.AddDependency(10)
	n.AddDependent(20)
	f := false
	n.CachedResult = &f

	cloned := n // value copy
	if cloned.ID != n.ID ||
		!reflect.DeepEqual(cloned.NodeType, n.NodeType) ||
		!reflect.DeepEqual(cloned.Dependencies, n.Dependencies) ||
		!reflect.DeepEqual(cloned.Dependents, n.Dependents) {
		t.Fatalf("copy mismatch")
	}
	if (cloned.CachedResult == nil) != (n.CachedResult == nil) || (cloned.CachedResult != nil && *cloned.CachedResult != *n.CachedResult) {
		t.Fatalf("cache mismatch")
	}
}

func TestCompiledDagCreation(t *testing.T) {
	d := NewCompiledDag()
	if len(d.Nodes) != 0 || len(d.ExecutionOrder) != 0 || len(d.PrimitiveMap) != 0 || len(d.RuleResults) != 0 {
		t.Fatalf("empty init expected")
	}
	if d.ResultBufSize != 0 {
		t.Fatalf("buf size 0 expected")
	}
}

func TestCompiledDagAddNode(t *testing.T) {
	d := NewCompiledDag()
	n := NewDagNode(42, PrimitiveType(engine.PrimitiveId(1)))
	ret := d.AddNode(n)
	if ret != 42 {
		t.Fatalf("returned id")
	}
	if len(d.Nodes) != 1 || d.ResultBufSize != 1 || d.Nodes[0].ID != 42 {
		t.Fatalf("node add mismatch")
	}
}

func TestCompiledDagGetNode(t *testing.T) {
	d := NewCompiledDag()
	d.AddNode(NewDagNode(0, PrimitiveType(engine.PrimitiveId(1))))
	n, ok := d.GetNode(0)
	if !ok || n.ID != 0 {
		t.Fatalf("get node 0")
	}
	b := true
	n.CachedResult = &b
	n2, _ := d.GetNode(0)
	if n2.CachedResult == nil || *n2.CachedResult != true {
		t.Fatalf("mutate via pointer failed")
	}
	if _, ok := d.GetNode(1); ok {
		t.Fatalf("get invalid should fail")
	}
}

func TestCompiledDagNodeCount(t *testing.T) {
	d := NewCompiledDag()
	if d.NodeCount() != 0 {
		t.Fatalf("count 0")
	}
	d.AddNode(NewDagNode(0, PrimitiveType(engine.PrimitiveId(1))))
	if d.NodeCount() != 1 {
		t.Fatalf("count 1")
	}
	d.AddNode(NewDagNode(1, LogicalType(LogicalAnd)))
	if d.NodeCount() != 2 {
		t.Fatalf("count 2")
	}
}

func TestCompiledDagValidateSuccess(t *testing.T) {
	d := createTestDag()
	if err := d.Validate(); err != nil {
		t.Fatalf("validate ok expected, got %v", err)
	}
}

func TestCompiledDagValidateExecutionOrderMismatch(t *testing.T) {
	d := createTestDag()
	d.ExecutionOrder = d.ExecutionOrder[:len(d.ExecutionOrder)-1]
	err := d.Validate()
	if err == nil || !strings.Contains(err.Error(), "Execution order length mismatch") {
		t.Fatalf("expected mismatch, got %v", err)
	}
}

func TestCompiledDagValidateInvalidDependency(t *testing.T) {
	d := NewCompiledDag()
	n := NewDagNode(0, LogicalType(LogicalAnd))
	n.AddDependency(999) // invalid
	d.AddNode(n)
	d.ExecutionOrder = []NodeId{0}

	err := d.Validate()
	if err == nil || !strings.Contains(err.Error(), "Invalid dependency") || !strings.Contains(err.Error(), "0 -> 999") {
		t.Fatalf("expected invalid dependency, got %v", err)
	}
}

func TestCompiledDagValidateInvalidResultNode(t *testing.T) {
	d := NewCompiledDag()
	d.AddNode(NewDagNode(0, PrimitiveType(engine.PrimitiveId(1))))
	d.RuleResults[engine.RuleId(1)] = 999 // invalid
	d.ExecutionOrder = []NodeId{0}

	err := d.Validate()
	if err == nil || !strings.Contains(err.Error(), "Invalid result node") || !strings.Contains(err.Error(), "999") {
		t.Fatalf("expected invalid result node, got %v", err)
	}
}

func TestCompiledDagClearCache(t *testing.T) {
	d := createTestDag()
	if n, ok := d.GetNode(0); ok {
		b := true
		n.CachedResult = &b
	}
	if n, ok := d.GetNode(1); ok {
		b := false
		n.CachedResult = &b
	}

	d.ClearCache()
	for i := range d.Nodes {
		if d.Nodes[i].CachedResult != nil {
			t.Fatalf("cache not cleared at %d", i)
		}
	}
}

func TestCompiledDagStatistics(t *testing.T) {
	d := createTestDag()
	st := d.Statistics()

	if st.TotalNodes != 4 || st.PrimitiveNodes != 2 || st.LogicalNodes != 1 || st.ResultNodes != 1 {
		t.Fatalf("counts mismatch: %#v", st)
	}
	if st.AvgFanout <= 0 {
		t.Fatalf("avg fanout > 0 expected")
	}
	if st.EstimatedMemoryBytes <= 0 {
		t.Fatalf("memory estimate > 0 expected")
	}
	if st.MaxDepth != 3 { // primitive -> logical -> result
		t.Fatalf("max depth 3 expected, got %d", st.MaxDepth)
	}
}

func TestDagStatisticsEmpty(t *testing.T) {
	d := NewCompiledDag()
	st := DagStatisticsFromDag(d)

	if st.TotalNodes != 0 || st.PrimitiveNodes != 0 || st.LogicalNodes != 0 || st.ResultNodes != 0 {
		t.Fatalf("counts should be 0: %#v", st)
	}
	if st.MaxDepth != 0 || st.AvgFanout != 0.0 || st.SharedPrimitives != 0 {
		t.Fatalf("stats zero expected: %#v", st)
	}
}

func TestDagStatisticsSingleNode(t *testing.T) {
	d := NewCompiledDag()
	d.AddNode(NewDagNode(0, PrimitiveType(engine.PrimitiveId(1))))
	d.ExecutionOrder = []NodeId{0}

	st := DagStatisticsFromDag(d)
	if st.TotalNodes != 1 || st.PrimitiveNodes != 1 || st.LogicalNodes != 0 || st.ResultNodes != 0 {
		t.Fatalf("counts mismatch: %#v", st)
	}
	if st.MaxDepth != 1 || st.AvgFanout != 0.0 || st.SharedPrimitives != 0 {
		t.Fatalf("stats mismatch: %#v", st)
	}
}

func TestDagStatisticsComplex(t *testing.T) {
	d := createTestDag()
	st := DagStatisticsFromDag(d)

	if st.TotalNodes != 4 || st.PrimitiveNodes != 2 || st.LogicalNodes != 1 || st.ResultNodes != 1 {
		t.Fatalf("counts mismatch: %#v", st)
	}
	if st.MaxDepth != 3 || st.SharedPrimitives != 0 {
		t.Fatalf("depth/shared mismatch: %#v", st)
	}
}

func TestDagStatisticsSharedPrimitives(t *testing.T) {
	d := NewCompiledDag()
	d.AddNode(NewDagNode(0, PrimitiveType(engine.PrimitiveId(1))))
	d.AddNode(NewDagNode(1, PrimitiveType(engine.PrimitiveId(1)))) // same primitive
	d.AddNode(NewDagNode(2, PrimitiveType(engine.PrimitiveId(2))))
	d.AddNode(NewDagNode(3, PrimitiveType(engine.PrimitiveId(2)))) // same primitive
	d.AddNode(NewDagNode(4, PrimitiveType(engine.PrimitiveId(3)))) // unique
	d.ExecutionOrder = []NodeId{0, 1, 2, 3, 4}

	st := DagStatisticsFromDag(d)
	if st.TotalNodes != 5 || st.PrimitiveNodes != 5 {
		t.Fatalf("counts mismatch: %#v", st)
	}
	if st.SharedPrimitives != 2 {
		t.Fatalf("shared primitives 2 expected, got %d", st.SharedPrimitives)
	}
}

func TestCompiledDagDebugish(t *testing.T) {
	d := createTestDag()
	s := fmt.Sprintf("%+v", d)
	if !(strings.Contains(s, "Nodes") && strings.Contains(s, "ExecutionOrder")) {
		t.Fatalf("debug-ish string: %s", s)
	}

	st := d.Statistics()
	ss := fmt.Sprintf("%+v", st)
	if !(strings.Contains(ss, "TotalNodes") && strings.Contains(ss, "PrimitiveNodes") && strings.Contains(ss, "MaxDepth")) {
		t.Fatalf("stats debug-ish string: %s", ss)
	}
}
