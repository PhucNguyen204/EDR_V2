package dag

import (
	"fmt"
	"sort"
)

// DagOptimizer performs simple, effective optimization passes on a compiled DAG.
type DagOptimizer struct {
	enableCSE bool
	enableDCE bool
}

func NewDagOptimizer() *DagOptimizer {
	return &DagOptimizer{enableCSE: true, enableDCE: true}
}

func (o *DagOptimizer) WithCSE(enable bool) *DagOptimizer { o.enableCSE = enable; return o }
func (o *DagOptimizer) WithDCE(enable bool) *DagOptimizer { o.enableDCE = enable; return o }

// Optimize applies CSE, DCE, and rebuilds execution order.
func (o *DagOptimizer) Optimize(dag CompiledDag) (CompiledDag, error) {
	if o.enableCSE {
		var err error
		dag, err = o.commonSubexpressionElimination(dag)
		if err != nil {
			return dag, err
		}
	}
	if o.enableDCE {
		var err error
		dag, err = o.deadCodeElimination(dag)
		if err != nil {
			return dag, err
		}
	}
	return o.rebuildExecutionOrderOptimized(dag)
}

// commonSubexpressionElimination merges duplicate expression nodes.
func (o *DagOptimizer) commonSubexpressionElimination(dag CompiledDag) (CompiledDag, error) {
	changed := true
	iterations := 0
	const maxIterations = 5

	for changed && iterations < maxIterations {
		changed = false
		iterations++

		exprMap := make(map[string]NodeId)
		nodeMap := make(map[NodeId]NodeId)
		for i := range dag.Nodes {
			n := &dag.Nodes[i]
			if n.NodeType.Kind == NodeResult { // never merge result nodes
				continue
			}
			sig := o.buildExpressionSignature(n, &dag)
			if exist, ok := exprMap[sig]; ok {
				if n.ID != exist {
					nodeMap[n.ID] = exist
					changed = true
				}
			} else {
				exprMap[sig] = n.ID
			}
		}

		if len(nodeMap) > 0 {
			var err error
			dag, err = o.applyNodeMapping(dag, nodeMap)
			if err != nil {
				return dag, err
			}
		}
	}
	return dag, nil
}

// deadCodeElimination removes nodes not reachable from any rule result.
func (o *DagOptimizer) deadCodeElimination(dag CompiledDag) (CompiledDag, error) {
	reachable := make(map[NodeId]struct{})
	for _, resultNodeId := range dag.RuleResults {
		o.markReachable(resultNodeId, &dag, reachable)
	}
	// retain reachable nodes
	filtered := make([]DagNode, 0, len(dag.Nodes))
	for i := range dag.Nodes {
		if _, ok := reachable[dag.Nodes[i].ID]; ok {
			filtered = append(filtered, dag.Nodes[i])
		}
	}
	dag.Nodes = filtered

	// filter maps to reachable only
	for k, v := range dag.PrimitiveMap {
		if _, ok := reachable[v]; !ok {
			delete(dag.PrimitiveMap, k)
		}
	}
	for k, v := range dag.RuleResults {
		if _, ok := reachable[v]; !ok {
			delete(dag.RuleResults, k)
		}
	}
	return dag, nil
}

// rebuildExecutionOrderOptimized recalculates a topological execution order.
func (o *DagOptimizer) rebuildExecutionOrderOptimized(dag CompiledDag) (CompiledDag, error) {
	order, err := o.topologicalSort(&dag)
	if err != nil {
		return dag, err
	}
	dag.ExecutionOrder = order
	return dag, nil
}

// buildExpressionSignature builds a canonical signature for a node expression.
func (o *DagOptimizer) buildExpressionSignature(node *DagNode, dag *CompiledDag) string {
	switch node.NodeType.Kind {
	case NodePrimitive:
		return fmt.Sprintf("P%d", node.NodeType.PrimitiveID)
	case NodeLogical:
		sigs := make([]string, 0, len(node.Dependencies))
		for _, dep := range node.Dependencies {
			if depNode, ok := dag.GetNode(dep); ok {
				sigs = append(sigs, o.buildExpressionSignature(depNode, dag))
			}
		}
		sort.Strings(sigs)
		switch node.NodeType.Operation {
		case LogicalAnd:
			return "AND(" + joinComma(sigs) + ")"
		case LogicalOr:
			return "OR(" + joinComma(sigs) + ")"
		case LogicalNot:
			return "NOT(" + joinComma(sigs) + ")"
		default:
			return "LOGIC(" + joinComma(sigs) + ")"
		}
	case NodeResult:
		return fmt.Sprintf("R%d", node.NodeType.RuleID)
	case NodePrefilter:
		return fmt.Sprintf("F%d:%d", node.NodeType.PrefilterID, node.NodeType.PatternCount)
	default:
		return fmt.Sprintf("K%d", int(node.NodeType.Kind))
	}
}

func joinComma(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	// strings.Join without importing strings heavily
	n := 0
	for _, s := range parts {
		n += len(s)
	}
	b := make([]byte, 0, n+len(parts)-1)
	for i, s := range parts {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, s...)
	}
	return string(b)
}

// applyNodeMapping merges nodes by mapping IDs and deduplicating edges.
func (o *DagOptimizer) applyNodeMapping(dag CompiledDag, mapping map[NodeId]NodeId) (CompiledDag, error) {
	toRemove := make(map[NodeId]struct{}, len(mapping))
	for k := range mapping {
		toRemove[k] = struct{}{}
	}

	// retain nodes not in toRemove
	filtered := make([]DagNode, 0, len(dag.Nodes))
	for i := range dag.Nodes {
		if _, ok := toRemove[dag.Nodes[i].ID]; !ok {
			filtered = append(filtered, dag.Nodes[i])
		}
	}
	dag.Nodes = filtered

	// Update dependencies/dependents for remaining nodes
	for i := range dag.Nodes {
		// deps
		newDeps := make([]NodeId, 0, len(dag.Nodes[i].Dependencies))
		seen := make(map[NodeId]struct{})
		for _, dep := range dag.Nodes[i].Dependencies {
			if mapped, ok := mapping[dep]; ok {
				dep = mapped
			}
			if _, ok := seen[dep]; !ok {
				seen[dep] = struct{}{}
				newDeps = append(newDeps, dep)
			}
		}
		dag.Nodes[i].Dependencies = newDeps

		// dependents
		newDents := make([]NodeId, 0, len(dag.Nodes[i].Dependents))
		seen2 := make(map[NodeId]struct{})
		for _, dep := range dag.Nodes[i].Dependents {
			if mapped, ok := mapping[dep]; ok {
				dep = mapped
			}
			if _, ok := seen2[dep]; !ok {
				seen2[dep] = struct{}{}
				newDents = append(newDents, dep)
			}
		}
		dag.Nodes[i].Dependents = newDents
	}

	// Update primitive map and rule results
	for k, v := range dag.PrimitiveMap {
		if mapped, ok := mapping[v]; ok {
			dag.PrimitiveMap[k] = mapped
		}
	}
	for k, v := range dag.RuleResults {
		if mapped, ok := mapping[v]; ok {
			dag.RuleResults[k] = mapped
		}
	}
	return dag, nil
}

// markReachable marks a node and all its dependencies as reachable.
func (o *DagOptimizer) markReachable(nodeID NodeId, dag *CompiledDag, reachable map[NodeId]struct{}) {
	if _, ok := reachable[nodeID]; ok {
		return
	}
	reachable[nodeID] = struct{}{}
	if node, ok := dag.GetNode(nodeID); ok {
		for _, dep := range node.Dependencies {
			o.markReachable(dep, dag, reachable)
		}
	}
}

// topologicalSort returns a valid execution order or error when cycle detected.
func (o *DagOptimizer) topologicalSort(dag *CompiledDag) ([]NodeId, error) {
	inDegree := make(map[NodeId]int, len(dag.Nodes))
	for i := range dag.Nodes {
		inDegree[dag.Nodes[i].ID] = 0
	}
	for i := range dag.Nodes {
		for _, dep := range dag.Nodes[i].Dependencies {
			if _, ok := dag.GetNode(dep); ok {
				inDegree[dag.Nodes[i].ID] = inDegree[dag.Nodes[i].ID] + 1
			}
		}
	}
	// queue of nodes with in-degree 0
	queue := make([]NodeId, 0, len(dag.Nodes))
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	// simple FIFO
	order := make([]NodeId, 0, len(dag.Nodes))
	head := 0
	for head < len(queue) {
		id := queue[head]
		head++
		order = append(order, id)
		if node, ok := dag.GetNode(id); ok {
			for _, dep := range node.Dependents {
				if d, ok := inDegree[dep]; ok {
					d--
					inDegree[dep] = d
					if d == 0 {
						queue = append(queue, dep)
					}
				}
			}
		}
	}
	if len(order) != len(dag.Nodes) {
		return nil, fmt.Errorf("CompilationError: Cycle detected in DAG during optimization")
	}
	return order, nil
}
