package dag

import (
    "fmt"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

// EngineConfig controls DAG engine build-time options.
type EngineConfig struct {
	EnablePrefilter          bool
	EnableParallelProcessing bool
	BatchSize                int
}

// DefaultEngineConfig returns sensible defaults.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		EnablePrefilter:          true,
		EnableParallelProcessing: true,
		BatchSize:                100,
	}
}

// DagEngine wires a compiled DAG with compiled primitives and optional prefilter.
// Evaluation is intentionally not implemented per requirements.
type DagEngine struct {
    dag        *CompiledDag
    primitives map[uint32]*matcher.CompiledPrimitive
    config     EngineConfig

    evaluator  *DagEvaluator
    prefilter  *LiteralPrefilter
}

// FromRuleset builds a DAG engine from a compiled ruleset and configuration.
func FromRuleset(ruleset *ir.CompiledRuleset, cfg EngineConfig) (*DagEngine, error) {
	if ruleset == nil {
		return nil, fmt.Errorf("nil ruleset")
	}

	// Build DAG from ruleset via builder (+optimizer)
	builder := NewDagBuilder().Optimize().FromRuleset(ruleset)
	dag, err := builder.Build()
	if err != nil {
		return nil, err
	}

	// Compile primitives
	prims := make(map[uint32]*matcher.CompiledPrimitive, len(ruleset.Primitives))
	for i := range ruleset.Primitives {
		cp, err := matcher.FromPrimitive(ruleset.Primitives[i])
		if err != nil {
			return nil, err
		}
		prims[uint32(i)] = cp
	}

	
    var pf *LiteralPrefilter
    if cfg.EnablePrefilter {
        pfv := PrefilterFromPrimitives(ruleset.Primitives)
        pf = &pfv
    }

	return &DagEngine{
		dag:        dag,
		primitives: prims,
		config:     cfg,
		prefilter:  pf,
	}, nil
}

// Accessors (metrics and configuration)

func (e *DagEngine) GetStatistics() DagStatistics {
	if e == nil || e.dag == nil {
		return DagStatistics{}
	}
	return e.dag.Statistics()
}

func (e *DagEngine) RuleCount() int {
	if e == nil || e.dag == nil {
		return 0
	}
	return len(e.dag.RuleResults)
}

func (e *DagEngine) NodeCount() int {
	if e == nil || e.dag == nil {
		return 0
	}
	return e.dag.NodeCount()
}

func (e *DagEngine) PrimitiveCount() int {
	if e == nil {
		return 0
	}
	return len(e.primitives)
}

func (e *DagEngine) ContainsRule(ruleID ir.RuleId) bool {
	if e == nil || e.dag == nil {
		return false
	}
	_, ok := e.dag.RuleResults[ruleID]
	return ok
}

func (e *DagEngine) Config() EngineConfig {
	if e == nil {
		return DefaultEngineConfig()
	}
	return e.config
}

func (e *DagEngine) Evaluate(event any) (DagEvaluationResult, error) {
    if e.evaluator == nil {
        if e.prefilter != nil {
            e.evaluator = WithPrimitivesAndPrefilter(e.dag, e.primitives, e.prefilter)
        } else {
            e.evaluator = WithPrimitives(e.dag, e.primitives)
        }
    }
    return e.evaluator.Evaluate(event)
}

func (e *DagEngine) EvaluateRaw(jsonStr string) (DagEvaluationResult, error) {
    if e.evaluator == nil {
        if e.prefilter != nil {
            e.evaluator = WithPrimitivesAndPrefilter(e.dag, e.primitives, e.prefilter)
        } else {
            e.evaluator = WithPrimitives(e.dag, e.primitives)
        }
    }
    return e.evaluator.EvaluateRaw(jsonStr)
}

func (e *DagEngine) EvaluateBatch(events []any) ([]DagEvaluationResult, error) {
    if e.evaluator == nil {
        if e.prefilter != nil {
            e.evaluator = WithPrimitivesAndPrefilter(e.dag, e.primitives, e.prefilter)
        } else {
            e.evaluator = WithPrimitives(e.dag, e.primitives)
        }
    }
    return e.evaluator.EvaluateBatch(events)
}

func FromRules(ruleYAMLs []string, cfg EngineConfig) (*DagEngine, error) {
	c := compiler.New()
	rs, err := c.CompileRuleset(ruleYAMLs)
	if err != nil { return nil, err }
	return FromRuleset(rs, cfg)
}

func (e *DagEngine) PrefilterStats() (hits, misses int) {
    if e == nil || e.evaluator == nil { return 0, 0 }
    return e.evaluator.PrefilterStats()
}

// Convenience: return only matched rule IDs for an event.
func (e *DagEngine) EvaluateMatches(event any) ([]ir.RuleId, error) {
    r, err := e.Evaluate(event)
    if err != nil { return nil, err }
    return append([]ir.RuleId(nil), r.MatchedRules...), nil
}

// Stats proxy
func (e *DagEngine) Stats() (nodesEvaluated, primitiveEvaluations, prefilterHits, prefilterMisses int) {
    if e == nil || e.evaluator == nil { return 0, 0, 0, 0 }
    return e.evaluator.Stats()
}

// PrefilterPatternCount returns how many literal patterns are loaded into the prefilter (0 if disabled).
func (e *DagEngine) PrefilterPatternCount() int {
    if e == nil || e.prefilter == nil { return 0 }
    // Prefilter is implemented in both aho and stub builds with Stats()
    st := e.prefilter.Stats()
    return st.PatternCount
}
