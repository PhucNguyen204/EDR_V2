package dag

import (
	"fmt"
	"unsafe"

	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// ---------- ID ----------
type NodeId = uint32

// ---------- LogicalOp ----------
type LogicalOp int

const (
	LogicalAnd LogicalOp = iota
	LogicalOr
	LogicalNot
)

func (op LogicalOp) String() string {
	switch op {
	case LogicalAnd:
		return "And"
	case LogicalOr:
		return "Or"
	case LogicalNot:
		return "Not"
	default:
		return fmt.Sprintf("LogicalOp(%d)", int(op))
	}
}

// ---------- NodeType (tagged union) ----------
type NodeKind int

const (
	NodePrimitive NodeKind = iota
	NodeLogical
	NodeResult
	NodePrefilter
)

type NodeType struct {
	Kind NodeKind

	// Primitive
	PrimitiveID ir.PrimitiveId

	// Logical
	Operation LogicalOp

	// Result
	RuleID ir.RuleId

	// Prefilter
	PrefilterID  uint32
	PatternCount int
}

func PrimitiveType(pid ir.PrimitiveId) NodeType {
	return NodeType{Kind: NodePrimitive, PrimitiveID: pid}
}
func LogicalType(op LogicalOp) NodeType {
	return NodeType{Kind: NodeLogical, Operation: op}
}
func ResultType(rid ir.RuleId) NodeType {
	return NodeType{Kind: NodeResult, RuleID: rid}
}
func PrefilterType(id uint32, patternCount int) NodeType {
	return NodeType{Kind: NodePrefilter, PrefilterID: id, PatternCount: patternCount}
}

func (nt NodeType) String() string {
	switch nt.Kind {
	case NodePrimitive:
		return fmt.Sprintf("Primitive{%d}", nt.PrimitiveID)
	case NodeLogical:
		return fmt.Sprintf("Logical{%s}", nt.Operation.String())
	case NodeResult:
		return fmt.Sprintf("Result{%d}", nt.RuleID)
	case NodePrefilter:
		return fmt.Sprintf("Prefilter{id:%d patterns:%d}", nt.PrefilterID, nt.PatternCount)
	default:
		return fmt.Sprintf("NodeType(kind=%d)", int(nt.Kind))
	}
}

// ---------- DagNode ----------
type DagNode struct {
	ID           NodeId
	NodeType     NodeType
	Dependencies []NodeId
	Dependents   []NodeId
	CachedResult *bool // nil = chưa evaluate
}

func NewDagNode(id NodeId, nt NodeType) DagNode {
	return DagNode{
		ID:           id,
		NodeType:     nt,
		Dependencies: make([]NodeId, 0),
		Dependents:   make([]NodeId, 0),
		CachedResult: nil,
	}
}

func (n *DagNode) AddDependency(dep NodeId) {
	for _, d := range n.Dependencies {
		if d == dep {
			return
		}
	}
	n.Dependencies = append(n.Dependencies, dep)
}
func (n *DagNode) AddDependent(dep NodeId) {
	for _, d := range n.Dependents {
		if d == dep {
			return
		}
	}
	n.Dependents = append(n.Dependents, dep)
}
func (n *DagNode) ClearCache()  { n.CachedResult = nil }
func (n *DagNode) IsLeaf() bool { return len(n.Dependencies) == 0 }
func (n *DagNode) IsRoot() bool { return len(n.Dependents) == 0 }

// ---------- CompiledDag ----------
type CompiledDag struct {
	Nodes          []DagNode
	ExecutionOrder []NodeId
	PrimitiveMap   map[ir.PrimitiveId]NodeId
	RuleResults    map[ir.RuleId]NodeId
	ResultBufSize  int
}

func NewCompiledDag() *CompiledDag {
	return &CompiledDag{
		Nodes:          make([]DagNode, 0),
		ExecutionOrder: make([]NodeId, 0),
		PrimitiveMap:   make(map[ir.PrimitiveId]NodeId),
		RuleResults:    make(map[ir.RuleId]NodeId),
		ResultBufSize:  0,
	}
}

func (d *CompiledDag) GetNode(id NodeId) (*DagNode, bool) {
	idx := int(id)
	if idx < 0 || idx >= len(d.Nodes) {
		return nil, false
	}
	return &d.Nodes[idx], true
}

func (d *CompiledDag) AddNode(node DagNode) NodeId {
	id := node.ID
	d.Nodes = append(d.Nodes, node)
	d.ResultBufSize = len(d.Nodes)
	return id
}

func (d *CompiledDag) NodeCount() int { return len(d.Nodes) }

// Validate: bỏ module error riêng, dùng error chuẩn
func (d *CompiledDag) Validate() error {
	if len(d.ExecutionOrder) != len(d.Nodes) {
		return fmt.Errorf("CompilationError: Execution order length mismatch")
	}
	for _, n := range d.Nodes {
		for _, dep := range n.Dependencies {
			if int(dep) >= len(d.Nodes) {
				return fmt.Errorf("CompilationError: Invalid dependency: %d -> %d", n.ID, dep)
			}
		}
	}
	for _, resNode := range d.RuleResults {
		if int(resNode) >= len(d.Nodes) {
			return fmt.Errorf("CompilationError: Invalid result node: %d", resNode)
		}
	}
	return nil
}

func (d *CompiledDag) ClearCache() {
	for i := range d.Nodes {
		d.Nodes[i].ClearCache()
	}
}

func (d *CompiledDag) Statistics() DagStatistics {
	return DagStatisticsFromDag(d)
}

// ---------- DagStatistics ----------
type DagStatistics struct {
	TotalNodes           int
	PrimitiveNodes       int
	LogicalNodes         int
	ResultNodes          int
	MaxDepth             int
	AvgFanout            float64
	SharedPrimitives     int
	EstimatedMemoryBytes int
}

func DagStatisticsFromDag(d *CompiledDag) DagStatistics {
	var prim, logi, res int
	totalDeps := 0

	for i := range d.Nodes {
		n := &d.Nodes[i]
		switch n.NodeType.Kind {
		case NodePrimitive:
			prim++
		case NodeLogical:
			logi++
		case NodeResult:
			res++
		case NodePrefilter:
			prim++ // Prefilter tính như primitive đặc biệt
		}
		totalDeps += len(n.Dependencies)
	}

	var avg float64
	if len(d.Nodes) > 0 {
		avg = float64(totalDeps) / float64(len(d.Nodes))
	}

	maxDepth := calculateMaxDepth(d)
	shared := calculateSharedPrimitives(d)

	estimated := len(d.Nodes)*int(unsafe.Sizeof(DagNode{})) +
		len(d.ExecutionOrder)*int(unsafe.Sizeof(NodeId(0))) +
		len(d.PrimitiveMap)*(int(unsafe.Sizeof(ir.PrimitiveId(0)))+int(unsafe.Sizeof(NodeId(0)))) +
		len(d.RuleResults)*(int(unsafe.Sizeof(ir.RuleId(0)))+int(unsafe.Sizeof(NodeId(0))))

	return DagStatistics{
		TotalNodes:           len(d.Nodes),
		PrimitiveNodes:       prim,
		LogicalNodes:         logi,
		ResultNodes:          res,
		MaxDepth:             maxDepth,
		AvgFanout:            avg,
		SharedPrimitives:     shared,
		EstimatedMemoryBytes: estimated,
	}
}

func calculateMaxDepth(d *CompiledDag) int {
	if len(d.Nodes) == 0 {
		return 0
	}
	depths := make(map[NodeId]int, len(d.Nodes))
	maxDepth := 0
	for _, id := range d.ExecutionOrder {
		n, ok := d.GetNode(id)
		if !ok {
			continue
		}
		depth := 1
		if len(n.Dependencies) > 0 {
			maxDep := 0
			for _, dep := range n.Dependencies {
				if v := depths[dep]; v > maxDep {
					maxDep = v
				}
			}
			depth = maxDep + 1
		}
		depths[id] = depth
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	return maxDepth
}

func calculateSharedPrimitives(d *CompiledDag) int {
	usage := make(map[ir.PrimitiveId]int)
	for i := range d.Nodes {
		n := &d.Nodes[i]
		if n.NodeType.Kind == NodePrimitive {
			pid := n.NodeType.PrimitiveID
			usage[pid]++
		}
	}
	shared := 0
	for _, c := range usage {
		if c > 1 {
			shared++
		}
	}
	return shared
}
