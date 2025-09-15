// Package dag - Unified DAG evaluation for high-performance rule execution.
package dag

import (
    "encoding/json"
    "fmt"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

// DagEvaluationResult mirrors the Rust struct: matched_rules, nodes_evaluated, primitive_evaluations.
type DagEvaluationResult struct {
    MatchedRules         []ir.RuleId
    NodesEvaluated       int
    PrimitiveEvaluations int
}

func (r *DagEvaluationResult) reset() {
    r.MatchedRules = r.MatchedRules[:0]
    r.NodesEvaluated = 0
    r.PrimitiveEvaluations = 0
}

type EvaluationStrategy int

const (
    EvalSingle EvaluationStrategy = iota
    EvalBatch
)

// BatchMemoryPool keeps reusable buffers to avoid per-batch allocations.
type BatchMemoryPool struct {
    PrimitiveResults [][]bool // [primitive_id][event_idx]
    NodeResults      [][]bool // [node_id][event_idx]
}

func newBatchMemoryPool() *BatchMemoryPool { return &BatchMemoryPool{} }

func (p *BatchMemoryPool) ResizeFor(batchSize, nodeCount, primitiveCount int) {
    // primitives
    if len(p.PrimitiveResults) < primitiveCount {
        diff := primitiveCount - len(p.PrimitiveResults)
        for i := 0; i < diff; i++ {
            p.PrimitiveResults = append(p.PrimitiveResults, make([]bool, 0))
        }
    }
    for i := 0; i < primitiveCount; i++ {
        if cap(p.PrimitiveResults[i]) < batchSize {
            p.PrimitiveResults[i] = make([]bool, batchSize)
        } else {
            p.PrimitiveResults[i] = p.PrimitiveResults[i][:batchSize]
        }
        for j := range p.PrimitiveResults[i] {
            p.PrimitiveResults[i][j] = false
        }
    }

    // nodes
    if len(p.NodeResults) < nodeCount {
        diff := nodeCount - len(p.NodeResults)
        for i := 0; i < diff; i++ {
            p.NodeResults = append(p.NodeResults, make([]bool, 0))
        }
    }
    for i := 0; i < nodeCount; i++ {
        if cap(p.NodeResults[i]) < batchSize {
            p.NodeResults[i] = make([]bool, batchSize)
        } else {
            p.NodeResults[i] = p.NodeResults[i][:batchSize]
        }
        for j := range p.NodeResults[i] {
            p.NodeResults[i][j] = false
        }
    }
}

func (p *BatchMemoryPool) Reset() {
    for i := range p.PrimitiveResults {
        for j := range p.PrimitiveResults[i] {
            p.PrimitiveResults[i][j] = false
        }
    }
    for i := range p.NodeResults {
        for j := range p.NodeResults[i] {
            p.NodeResults[i][j] = false
        }
    }
}

// DagEvaluator – adaptive evaluator for single/batch processing.
type DagEvaluator struct {
    dag        *CompiledDag
    primitives map[uint32]*matcher.CompiledPrimitive

    fastResults []bool
    batchPool   *BatchMemoryPool

    nodesEvaluated       int
    primitiveEvaluations int

    prefilter       Prefilter
    prefilterHits   int
    prefilterMisses int
}

// WithPrimitives is the basic constructor (no prefilter).
func WithPrimitives(dag *CompiledDag, primitives map[uint32]*matcher.CompiledPrimitive) *DagEvaluator {
    return WithPrimitivesAndPrefilter(dag, primitives, nil)
}

// WithPrimitivesAndPrefilter enables optional literal prefiltering.
func WithPrimitivesAndPrefilter(dag *CompiledDag, primitives map[uint32]*matcher.CompiledPrimitive, prefilter Prefilter) *DagEvaluator {
    fr := make([]bool, len(dag.Nodes))
    return &DagEvaluator{
        dag:                  dag,
        primitives:           primitives,
        fastResults:          fr,
        batchPool:            newBatchMemoryPool(),
        prefilter:            prefilter,
        nodesEvaluated:       0,
        primitiveEvaluations: 0,
        prefilterHits:        0,
        prefilterMisses:      0,
    }
}

func (e *DagEvaluator) selectStrategy(eventCount int) EvaluationStrategy {
    if eventCount == 1 { return EvalSingle }
    return EvalBatch
}

func (e *DagEvaluator) reset() {
    for i := range e.fastResults { e.fastResults[i] = false }
    if e.batchPool != nil { e.batchPool.Reset() }
    e.nodesEvaluated = 0
    e.primitiveEvaluations = 0
}

// Evaluate a single event (any parsed JSON object).
func (e *DagEvaluator) Evaluate(event any) (DagEvaluationResult, error) {
    // Optional prefilter fast-path
    if e.prefilter != nil {
        if !e.prefilter.MatchesJSON(event) {
            e.prefilterMisses++
            return DagEvaluationResult{MatchedRules: nil, NodesEvaluated: 1, PrimitiveEvaluations: 0}, nil
        }
        e.prefilterHits++
    }
    return e.evaluateSingleVec(event)
}

// EvaluateBatch processes multiple events with memory pooling.
func (e *DagEvaluator) EvaluateBatch(events []any) ([]DagEvaluationResult, error) {
    if len(events) == 0 { return []DagEvaluationResult{}, nil }
    switch e.selectStrategy(len(events)) {
    case EvalBatch:
        return e.evaluateBatchInternal(events)
    default:
        out := make([]DagEvaluationResult, 0, len(events))
        for _, ev := range events {
            r, err := e.Evaluate(ev)
            if err != nil { return nil, err }
            out = append(out, r)
        }
        return out, nil
    }
}

// EvaluateRaw parses JSON then evaluates.
func (e *DagEvaluator) EvaluateRaw(jsonStr string) (DagEvaluationResult, error) {
    if e.prefilter != nil {
        if !e.prefilter.MatchesRaw(jsonStr) {
            e.prefilterMisses++
            return DagEvaluationResult{MatchedRules: nil, NodesEvaluated: 1, PrimitiveEvaluations: 0}, nil
        }
        e.prefilterHits++
    }

    var event any
    if err := json.Unmarshal([]byte(jsonStr), &event); err != nil {
        return DagEvaluationResult{}, fmt.Errorf("ExecutionError: Invalid JSON: %v", err)
    }
    return e.Evaluate(event)
}

// Stats: (nodes_evaluated, primitive_evaluations, prefilter_hits, prefilter_misses)
func (e *DagEvaluator) Stats() (int, int, int, int) {
    return e.nodesEvaluated, e.primitiveEvaluations, e.prefilterHits, e.prefilterMisses
}

func (e *DagEvaluator) HasPrefilter() bool { return e.prefilter != nil }

// ---- Single-event path (fast vec) ----

func (e *DagEvaluator) evaluateSingleVec(event any) (DagEvaluationResult, error) {
    e.reset()
    for _, nodeID := range e.dag.ExecutionOrder {
        node := e.dag.Nodes[int(nodeID)]
        e.nodesEvaluated++

        var res bool
        switch node.NodeType.Kind {
        case NodePrimitive:
            e.primitiveEvaluations++
            primID := uint32(node.NodeType.PrimitiveID)
            if prim, ok := e.primitives[primID]; ok && prim != nil {
                ctx := matcher.NewEventContext(event)
                res = prim.Matches(ctx)
            } else {
                res = false
            }
        case NodeLogical:
            ok, err := e.evaluateLogicalOperationWithVec(node.NodeType.Operation, node.Dependencies)
            if err != nil { return DagEvaluationResult{}, err }
            res = ok
        case NodeResult:
            if len(node.Dependencies) == 1 {
                res = e.fastResults[int(node.Dependencies[0])]
            } else {
                res = false
            }
        case NodePrefilter:
            // Treat prefilter nodes as boolean evaluation against the event if desired.
            if e.prefilter != nil {
                res = e.prefilter.MatchesJSON(event)
            } else {
                res = false
            }
        default:
            res = false
        }
        e.fastResults[int(nodeID)] = res
    }

    // collect matched rules
    matched := make([]ir.RuleId, 0, len(e.dag.RuleResults))
    for rid, resNode := range e.dag.RuleResults {
        if e.fastResults[int(resNode)] { matched = append(matched, rid) }
    }
    return DagEvaluationResult{
        MatchedRules:         matched,
        NodesEvaluated:       e.nodesEvaluated,
        PrimitiveEvaluations: e.primitiveEvaluations,
    }, nil
}

func (e *DagEvaluator) evaluateLogicalOperationWithVec(op LogicalOp, deps []NodeId) (bool, error) {
    switch op {
    case LogicalAnd:
        for _, id := range deps {
            if !e.fastResults[int(id)] { return false, nil }
        }
        return true, nil
    case LogicalOr:
        for _, id := range deps {
            if e.fastResults[int(id)] { return true, nil }
        }
        return false, nil
    case LogicalNot:
        if len(deps) != 1 { return false, fmt.Errorf("ExecutionError: NOT operation requires exactly one dependency") }
        return !e.fastResults[int(deps[0])], nil
    default:
        return false, nil
    }
}

// ---- Batch path ----

func (e *DagEvaluator) evaluateBatchInternal(events []any) ([]DagEvaluationResult, error) {
    batchSize := len(events)
    e.batchPool.ResizeFor(batchSize, len(e.dag.Nodes), len(e.primitives))
    e.batchPool.Reset()
    e.nodesEvaluated = 0
    e.primitiveEvaluations = 0

    if err := e.evaluatePrimitivesBatch(events); err != nil { return nil, err }
    if err := e.evaluateLogicalBatch(events); err != nil { return nil, err }
    return e.collectBatchResults(events), nil
}

func (e *DagEvaluator) evaluatePrimitivesBatch(events []any) error {
    for primitiveID, nodeID := range e.dag.PrimitiveMap {
        prim := e.primitives[uint32(primitiveID)]
        if prim == nil { continue }
        for idx := range events {
            ctx := matcher.NewEventContext(events[idx])
            res := prim.Matches(ctx)
            e.primitiveEvaluations++
            if int(primitiveID) < len(e.batchPool.PrimitiveResults) {
                e.batchPool.PrimitiveResults[int(primitiveID)][idx] = res
            }
            if int(nodeID) < len(e.batchPool.NodeResults) {
                e.batchPool.NodeResults[int(nodeID)][idx] = res
            }
        }
    }
    return nil
}

func (e *DagEvaluator) evaluateLogicalBatch(events []any) error {
    for _, nodeID := range e.dag.ExecutionOrder {
        node := e.dag.Nodes[int(nodeID)]
        if node.NodeType.Kind == NodeLogical {
            for idx := range events {
                val, err := e.evaluateLogicalOperationBatch(node.NodeType.Operation, node.Dependencies, idx)
                if err != nil { return err }
                if int(nodeID) < len(e.batchPool.NodeResults) {
                    e.batchPool.NodeResults[int(nodeID)][idx] = val
                }
                e.nodesEvaluated++
            }
        }
    }
    return nil
}

func (e *DagEvaluator) evaluateLogicalOperationBatch(op LogicalOp, deps []NodeId, eventIdx int) (bool, error) {
    switch op {
    case LogicalAnd:
        for _, id := range deps {
            if int(id) >= len(e.batchPool.NodeResults) || !e.batchPool.NodeResults[int(id)][eventIdx] {
                return false, nil
            }
        }
        return true, nil
    case LogicalOr:
        for _, id := range deps {
            if int(id) < len(e.batchPool.NodeResults) && e.batchPool.NodeResults[int(id)][eventIdx] {
                return true, nil
            }
        }
        return false, nil
    case LogicalNot:
        if len(deps) != 1 { return false, fmt.Errorf("ExecutionError: NOT operation requires exactly one dependency") }
        id := int(deps[0])
        if id < len(e.batchPool.NodeResults) { return !e.batchPool.NodeResults[id][eventIdx], nil }
        return false, nil
    default:
        return false, nil
    }
}

func (e *DagEvaluator) collectBatchResults(events []any) []DagEvaluationResult {
    out := make([]DagEvaluationResult, 0, len(events))
    avgNodes := 0
    avgPrims := 0
    if len(events) > 0 {
        avgNodes = e.nodesEvaluated / len(events)
        avgPrims = e.primitiveEvaluations / len(events)
    }
    for idx := range events {
        matched := make([]ir.RuleId, 0, len(e.dag.RuleResults))
        for rid, resNode := range e.dag.RuleResults {
            if int(resNode) < len(e.batchPool.NodeResults) && e.batchPool.NodeResults[int(resNode)][idx] {
                matched = append(matched, rid)
            }
        }
        out = append(out, DagEvaluationResult{MatchedRules: matched, NodesEvaluated: avgNodes, PrimitiveEvaluations: avgPrims})
    }
    return out
}

// EvaluatePrimitive – helper used in tests / debugging.
func (e *DagEvaluator) EvaluatePrimitive(primitiveID uint32, event any) (bool, error) {
    prim := e.primitives[primitiveID]
    if prim == nil {
        return false, fmt.Errorf("ExecutionError: Primitive %d not found", primitiveID)
    }
    ctx := matcher.NewEventContext(event)
    return prim.Matches(ctx), nil
}

func (e *DagEvaluator) PrefilterStats() (hits, misses int) { return e.prefilterHits, e.prefilterMisses }
