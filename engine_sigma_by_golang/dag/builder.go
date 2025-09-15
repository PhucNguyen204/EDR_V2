package dag

import (
    "fmt"
    "sort"

    compiler "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// DagBuilder constructs a DAG from IR CompiledRuleset or raw primitives, mirroring Rust builder.
type DagBuilder struct {
    nodes []DagNode
    nextNodeId NodeId

    primitiveNodes map[ir.PrimitiveId]NodeId
    ruleResultNodes map[ir.RuleId]NodeId

    enableOptimization bool
    enablePrefilter bool // reserved; prefilter integration optional
}

func NewDagBuilder() *DagBuilder {
    return &DagBuilder{
        nodes:            make([]DagNode, 0),
        nextNodeId:       0,
        primitiveNodes:   make(map[ir.PrimitiveId]NodeId),
        ruleResultNodes:  make(map[ir.RuleId]NodeId),
        enableOptimization: true,
        enablePrefilter:    true,
    }
}

// FromRuleset builds primitive nodes and rule subgraphs from a ruleset.
func (b *DagBuilder) FromRuleset(ruleset *ir.CompiledRuleset) *DagBuilder {
    // First pass: create primitive nodes (shared across rules)
    seen := make(map[ir.PrimitiveId]struct{})
    for _, pid := range ruleset.PrimitiveMap {
        if _, ok := seen[pid]; ok { continue }
        seen[pid] = struct{}{}
        nid := b.createPrimitiveNode(pid)
        b.primitiveNodes[pid] = nid
    }

    // Second pass: build condition subgraph per rule and attach result node
    for i := range ruleset.Rules {
        rule := &ruleset.Rules[i]
        tokens, err := compiler.TokenizeCondition(rule.Condition)
        if err != nil { continue }
        ast, err := compiler.ParseTokens(tokens, rule.Selections)
        if err != nil { continue }
        rootID, err := b.buildConditionSubgraph(ast, rule.Selections, rule.Disjunctions)
        if err != nil { continue }
        res := b.createResultNode(rule.RuleId)
        b.addDependency(res, rootID)
        b.ruleResultNodes[rule.RuleId] = res
    }
    return b
}

// FromPrimitives builds a DAG consisting only of primitive nodes (optional prefilter reserved).
func (b *DagBuilder) FromPrimitives(primitives []ir.Primitive) *DagBuilder {
    for i := range primitives {
        pid := ir.PrimitiveId(i)
        nid := b.createPrimitiveNode(pid)
        b.primitiveNodes[pid] = nid
    }
    return b
}

// Optimize applies optimizer passes if enabled.
func (b *DagBuilder) Optimize() *DagBuilder {
    if !b.enableOptimization { return b }
    if dag, err := b.buildTemporaryDag(); err == nil {
        if out, err2 := NewDagOptimizer().WithCSE(true).WithDCE(true).Optimize(dag); err2 == nil {
            b.updateFromOptimizedDag(out)
        }
    }
    return b
}

// Build final CompiledDag: topologically sort, validate and return.
func (b *DagBuilder) Build() (*CompiledDag, error) {
    order, err := b.topologicalSort()
    if err != nil { return nil, err }
    if err := b.validateDagStructure(); err != nil { return nil, err }
    dag := &CompiledDag{
        Nodes:            b.nodes,
        ExecutionOrder:   order,
        PrimitiveMap:     b.primitiveNodes,
        RuleResults:      b.ruleResultNodes,
        ResultBufSize:    int(b.nextNodeId),
    }
    if err := dag.Validate(); err != nil { return nil, err }
    return dag, nil
}

// ---- internal helpers ----

func (b *DagBuilder) createPrimitiveNode(pid ir.PrimitiveId) NodeId {
    id := b.nextNodeId
    b.nextNodeId++
    n := NewDagNode(id, PrimitiveType(pid))
    b.nodes = append(b.nodes, n)
    return id
}

func (b *DagBuilder) ensurePrimitiveNode(pid ir.PrimitiveId) NodeId {
    if nid, ok := b.primitiveNodes[pid]; ok { return nid }
    nid := b.createPrimitiveNode(pid)
    b.primitiveNodes[pid] = nid
    return nid
}

func (b *DagBuilder) createLogicalNode(op LogicalOp) NodeId {
    id := b.nextNodeId
    b.nextNodeId++
    n := NewDagNode(id, LogicalType(op))
    b.nodes = append(b.nodes, n)
    return id
}

func (b *DagBuilder) createResultNode(rid ir.RuleId) NodeId {
    id := b.nextNodeId
    b.nextNodeId++
    n := NewDagNode(id, ResultType(rid))
    b.nodes = append(b.nodes, n)
    return id
}

func (b *DagBuilder) addDependency(dependent, dependency NodeId) {
    if depNode, ok := b.GetNode(dependent); ok {
        depNode.AddDependency(dependency)
    }
    if baseNode, ok := b.GetNode(dependency); ok {
        baseNode.AddDependent(dependent)
    }
}

func (b *DagBuilder) GetNode(id NodeId) (*DagNode, bool) {
    if int(id) < 0 || int(id) >= len(b.nodes) { return nil, false }
    return &b.nodes[id], true
}

func (b *DagBuilder) buildConditionSubgraph(ast *compiler.ConditionAst, sel map[string][]ir.PrimitiveId, disj map[string][][]ir.PrimitiveId) (NodeId, error) {
    switch ast.Kind {
    case compiler.AstIdentifier:
        // Merge Disjunctions (OR-of-AND groups) với Selections (AND group) nếu cả hai cùng tồn tại
        merged := make([][]ir.PrimitiveId, 0)
        if groups, ok := disj[ast.Name]; ok && len(groups) > 0 {
            merged = append(merged, groups...)
        }
        if pids, ok := sel[ast.Name]; ok && len(pids) > 0 {
            grp := append([]ir.PrimitiveId(nil), pids...)
            merged = append(merged, grp)
        }
        if len(merged) == 0 {
            return 0, fmt.Errorf("Unknown or empty selection: %s", ast.Name)
        }
        return b.buildOrOfAnd(merged), nil
    case compiler.AstAnd:
        ln, err := b.buildConditionSubgraph(ast.Left, sel, disj); if err != nil { return 0, err }
        rn, err := b.buildConditionSubgraph(ast.Right, sel, disj); if err != nil { return 0, err }
        and := b.createLogicalNode(LogicalAnd)
        b.addDependency(and, ln)
        b.addDependency(and, rn)
        return and, nil
    case compiler.AstOr:
        ln, err := b.buildConditionSubgraph(ast.Left, sel, disj); if err != nil { return 0, err }
        rn, err := b.buildConditionSubgraph(ast.Right, sel, disj); if err != nil { return 0, err }
        or := b.createLogicalNode(LogicalOr)
        b.addDependency(or, ln)
        b.addDependency(or, rn)
        return or, nil
    case compiler.AstNot:
        on, err := b.buildConditionSubgraph(ast.Operand, sel, disj); if err != nil { return 0, err }
        not := b.createLogicalNode(LogicalNot)
        b.addDependency(not, on)
        return not, nil
    case compiler.AstOneOfThem:
        // OR across selection nodes (each selection node is OR-of-AND or AND-of-primitives)
        or := b.createLogicalNode(LogicalOr)
        any := false
        names := make(map[string]struct{}, len(sel)+len(disj))
        for k := range sel { names[k] = struct{}{} }
        for k := range disj { names[k] = struct{}{} }
        keys := make([]string, 0, len(names))
        for k := range names { keys = append(keys, k) }
        sort.Strings(keys)
        for _, name := range keys {
            // prefer disjunctions when present
            if groups, ok := disj[name]; ok && len(groups) > 0 {
                node := b.buildOrOfAnd(groups)
                b.addDependency(or, node)
                any = true
                continue
            }
            if pids, ok := sel[name]; ok && len(pids) > 0 {
                if len(pids) == 1 {
                    b.addDependency(or, b.ensurePrimitiveNode(pids[0]))
                } else {
                    andSel := b.createLogicalNode(LogicalAnd)
                    for _, pid := range pids { b.addDependency(andSel, b.ensurePrimitiveNode(pid)) }
                    b.addDependency(or, andSel)
                }
                any = true
            }
        }
        if !any { return 0, fmt.Errorf("No selections found for 'one of them'") }
        return or, nil
    case compiler.AstAllOfThem:
        // AND across selection nodes (each selection node is OR-of-AND or AND-of-primitives)
        and := b.createLogicalNode(LogicalAnd)
        any := false
        names := make(map[string]struct{}, len(sel)+len(disj))
        for k := range sel { names[k] = struct{}{} }
        for k := range disj { names[k] = struct{}{} }
        keys := make([]string, 0, len(names))
        for k := range names { keys = append(keys, k) }
        sort.Strings(keys)
        for _, name := range keys {
            if groups, ok := disj[name]; ok && len(groups) > 0 {
                node := b.buildOrOfAnd(groups)
                b.addDependency(and, node)
                any = true
                continue
            }
            if pids, ok := sel[name]; ok && len(pids) > 0 {
                if len(pids) == 1 {
                    b.addDependency(and, b.ensurePrimitiveNode(pids[0]))
                } else {
                    andSel := b.createLogicalNode(LogicalAnd)
                    for _, pid := range pids { b.addDependency(andSel, b.ensurePrimitiveNode(pid)) }
                    b.addDependency(and, andSel)
                }
                any = true
            }
        }
        if !any { return 0, fmt.Errorf("No selections found for 'all of them'") }
        return and, nil
    case compiler.AstAllOfPattern:
        and := b.createLogicalNode(LogicalAnd)
        matched := false
        names := make(map[string]struct{}, len(sel)+len(disj))
        for k := range sel { names[k] = struct{}{} }
        for k := range disj { names[k] = struct{}{} }
        keys := make([]string, 0, len(names))
        for k := range names { keys = append(keys, k) }
        sort.Strings(keys)
        for _, name := range keys {
            if !containsPattern(name, ast.Pattern) { continue }
            if groups, ok := disj[name]; ok && len(groups) > 0 {
                node := b.buildOrOfAnd(groups)
                b.addDependency(and, node)
                matched = true
                continue
            }
            if pids, ok := sel[name]; ok {
                if len(pids) == 1 {
                    b.addDependency(and, b.ensurePrimitiveNode(pids[0]))
                    matched = true
                } else if len(pids) > 1 {
                    subAnd := b.createLogicalNode(LogicalAnd)
                    for _, pid := range pids { b.addDependency(subAnd, b.ensurePrimitiveNode(pid)) }
                    b.addDependency(and, subAnd)
                    matched = true
                }
            }
        }
        if !matched { return 0, fmt.Errorf("No selections found matching pattern: %s", ast.Pattern) }
        return and, nil
    case compiler.AstCountOfPattern:
        // Proper handling for the common case: 1 of selection*
        if ast.Count == 1 {
            // OR across selection nodes (each selection node is OR-of-AND or AND-of-primitives)
            or := b.createLogicalNode(LogicalOr)
            matched := false
            names := make(map[string]struct{}, len(sel)+len(disj))
            for k := range sel { names[k] = struct{}{} }
            for k := range disj { names[k] = struct{}{} }
            keys := make([]string, 0, len(names))
            for k := range names { keys = append(keys, k) }
            sort.Strings(keys)
            for _, name := range keys {
                if !containsPattern(name, ast.Pattern) { continue }
                if groups, ok := disj[name]; ok && len(groups) > 0 {
                    node := b.buildOrOfAnd(groups)
                    b.addDependency(or, node)
                    matched = true
                    continue
                }
                if pids, ok := sel[name]; ok && len(pids) > 0 {
                    if len(pids) == 1 {
                        b.addDependency(or, b.ensurePrimitiveNode(pids[0]))
                    } else {
                        andSel := b.createLogicalNode(LogicalAnd)
                        for _, pid := range pids { b.addDependency(andSel, b.ensurePrimitiveNode(pid)) }
                        b.addDependency(or, andSel)
                    }
                    matched = true
                }
            }
            if !matched { return 0, fmt.Errorf("No selections found matching pattern: %s", ast.Pattern) }
            return or, nil
        }
        // Fallback: simplify as OR across primitives (count ignored)
        or := b.createLogicalNode(LogicalOr)
        matched := false
        for name, pids := range sel {
            if containsPattern(name, ast.Pattern) {
                for _, pid := range pids {
                    b.addDependency(or, b.ensurePrimitiveNode(pid))
                    matched = true
                }
            }
        }
        if !matched { return 0, fmt.Errorf("No selections found matching pattern: %s", ast.Pattern) }
        return or, nil
    default:
        return 0, fmt.Errorf("Unsupported AST kind")
    }
}

// buildOrOfAnd constructs an OR of AND-groups from disjunctions
func (b *DagBuilder) buildOrOfAnd(groups [][]ir.PrimitiveId) NodeId {
    if len(groups) == 0 {
        return b.createLogicalNode(LogicalOr)
    }
    if len(groups) == 1 {
        g := groups[0]
        if len(g) == 1 { return b.ensurePrimitiveNode(g[0]) }
        and := b.createLogicalNode(LogicalAnd)
        for _, pid := range g { b.addDependency(and, b.ensurePrimitiveNode(pid)) }
        return and
    }
    or := b.createLogicalNode(LogicalOr)
    for _, g := range groups {
        if len(g) == 1 {
            b.addDependency(or, b.ensurePrimitiveNode(g[0]))
            continue
        }
        and := b.createLogicalNode(LogicalAnd)
        for _, pid := range g { b.addDependency(and, b.ensurePrimitiveNode(pid)) }
        b.addDependency(or, and)
    }
    return or
}

func containsPattern(name, pattern string) bool {
    // Treat '*' in pattern as wildcard: we match by stripping '*' and doing substring check.
    if len(pattern) == 0 { return true }
    base := make([]byte, 0, len(pattern))
    for i := 0; i < len(pattern); i++ { if pattern[i] != '*' { base = append(base, pattern[i]) } }
    if len(base) == 0 { return true }
    sub := string(base)
    return indexOf(name, sub) >= 0
}

func indexOf(s, sub string) int {
    for i := 0; i+len(sub) <= len(s); i++ {
        if s[i:i+len(sub)] == sub { return i }
    }
    return -1
}

func (b *DagBuilder) buildTemporaryDag() (CompiledDag, error) {
    order, err := b.topologicalSort()
    if err != nil { return CompiledDag{}, err }
    if err := b.validateDagStructure(); err != nil { return CompiledDag{}, err }
    return CompiledDag{
        Nodes:          append([]DagNode(nil), b.nodes...),
        ExecutionOrder: order,
        PrimitiveMap:   copyPrimMap(b.primitiveNodes),
        RuleResults:    copyRuleMap(b.ruleResultNodes),
        ResultBufSize:  int(b.nextNodeId),
    }, nil
}

func copyPrimMap(m map[ir.PrimitiveId]NodeId) map[ir.PrimitiveId]NodeId {
    out := make(map[ir.PrimitiveId]NodeId, len(m))
    for k, v := range m { out[k] = v }
    return out
}
func copyRuleMap(m map[ir.RuleId]NodeId) map[ir.RuleId]NodeId {
    out := make(map[ir.RuleId]NodeId, len(m))
    for k, v := range m { out[k] = v }
    return out
}

func (b *DagBuilder) updateFromOptimizedDag(dag CompiledDag) {
    b.nodes = dag.Nodes
    b.primitiveNodes = dag.PrimitiveMap
    b.ruleResultNodes = dag.RuleResults
    if len(b.nodes) == 0 { b.nextNodeId = 0 } else {
        max := NodeId(0)
        for i := range b.nodes { if b.nodes[i].ID > max { max = b.nodes[i].ID } }
        b.nextNodeId = max + 1
    }
}

func (b *DagBuilder) topologicalSort() ([]NodeId, error) {
    inDeg := make(map[NodeId]int, len(b.nodes))
    for i := range b.nodes { inDeg[b.nodes[i].ID] = 0 }
    for i := range b.nodes {
        for _, dep := range b.nodes[i].Dependencies {
            if _, ok := b.GetNode(dep); ok { inDeg[b.nodes[i].ID] = inDeg[b.nodes[i].ID] + 1 }
        }
    }
    // queue of zero in-degree
    queue := make([]NodeId, 0, len(b.nodes))
    for id, d := range inDeg { if d == 0 { queue = append(queue, id) } }
    order := make([]NodeId, 0, len(b.nodes))
    head := 0
    for head < len(queue) {
        id := queue[head]; head++
        order = append(order, id)
        if node, ok := b.GetNode(id); ok {
            for _, dep := range node.Dependents {
                if d, ok := inDeg[dep]; ok {
                    d--
                    inDeg[dep] = d
                    if d == 0 { queue = append(queue, dep) }
                }
            }
        }
    }
    if len(order) != len(b.nodes) {
        return nil, fmt.Errorf("CompilationError: Cycle detected in DAG")
    }
    return order, nil
}

func (b *DagBuilder) validateDagStructure() error {
    // ensure every rule result node exists (keys and values check)
    for _, nid := range b.ruleResultNodes {
        if _, ok := b.GetNode(nid); !ok {
            return fmt.Errorf("CompilationError: Missing result node: %d", nid)
        }
    }
    // dependencies valid
    for i := range b.nodes {
        for _, dep := range b.nodes[i].Dependencies {
            if _, ok := b.GetNode(dep); !ok {
                return fmt.Errorf("CompilationError: Invalid dependency: %d -> %d", b.nodes[i].ID, dep)
            }
        }
    }
    return nil
}
