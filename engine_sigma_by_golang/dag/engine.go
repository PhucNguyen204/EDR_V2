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

	evaluator         *DagEvaluator
	prefilter         *LiteralPrefilter
	correlationEngine *CorrelationEngine
	batchProcessor    *BatchProcessor
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

	// Initialize correlation engine if correlation rules exist
	var correlationEngine *CorrelationEngine
	if len(ruleset.Correlations) > 0 {
		correlationEngine = NewCorrelationEngine(ruleset.Correlations)

		// Build rule name to rule ID mapping
		ruleNameMap := make(map[string]ir.RuleId)
		for _, rule := range ruleset.Rules {
			if rule.RuleName != "" {
				ruleNameMap[rule.RuleName] = rule.RuleId
			}
		}
		correlationEngine.SetRuleMetadata(ruleNameMap)
	}

	engine := &DagEngine{
		dag:               dag,
		primitives:        prims,
		config:            cfg,
		prefilter:         pf,
		correlationEngine: correlationEngine,
	}

	// Initialize batch processor
	// engine.batchProcessor = NewBatchProcessor(engine) // Temporarily disabled

	return engine, nil
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
	if err != nil {
		return nil, err
	}
	return FromRuleset(rs, cfg)
}

func (e *DagEngine) PrefilterStats() (hits, misses int) {
	if e == nil || e.evaluator == nil {
		return 0, 0
	}
	return e.evaluator.PrefilterStats()
}

// Convenience: return only matched rule IDs for an event.
func (e *DagEngine) EvaluateMatches(event any) ([]ir.RuleId, error) {
	r, err := e.Evaluate(event)
	if err != nil {
		return nil, err
	}
	return append([]ir.RuleId(nil), r.MatchedRules...), nil
}

// Stats proxy
func (e *DagEngine) Stats() (nodesEvaluated, primitiveEvaluations, prefilterHits, prefilterMisses int) {
	if e == nil || e.evaluator == nil {
		return 0, 0, 0, 0
	}
	return e.evaluator.Stats()
}

// PrefilterPatternCount returns how many literal patterns are loaded into the prefilter (0 if disabled).
func (e *DagEngine) PrefilterPatternCount() int {
	if e == nil || e.prefilter == nil {
		return 0
	}
	// Prefilter is implemented in both aho and stub builds with Stats()
	st := e.prefilter.Stats()
	return st.PatternCount
}

// EvaluateWithCorrelation evaluates an event and processes correlation rules
func (e *DagEngine) EvaluateWithCorrelation(event any) (DagEvaluationResult, []CorrelationAlert, error) {
	// First, evaluate single-event rules
	result, err := e.Evaluate(event)
	if err != nil {
		return result, nil, err
	}

	// Process correlation rules if correlation engine exists
	var correlationAlerts []CorrelationAlert
	if e.correlationEngine != nil {
		correlationAlerts = e.correlationEngine.ProcessEvent(event, result.MatchedRules)
	}

	return result, correlationAlerts, nil
}

// GetCorrelationStats returns statistics about the correlation engine
func (e *DagEngine) GetCorrelationStats() map[string]int {
	if e.correlationEngine == nil {
		return make(map[string]int)
	}
	return e.correlationEngine.GetWindowStats()
}

// GetCorrelationWindowCount returns the number of active correlation windows
func (e *DagEngine) GetCorrelationWindowCount() int {
	if e.correlationEngine == nil {
		return 0
	}
	return e.correlationEngine.GetWindowCount()
}

// ProcessBatch processes a batch of events using the batch processor
func (e *DagEngine) ProcessBatch(events []any) (*BatchResult, error) {
	return nil, fmt.Errorf("batch processor temporarily disabled")
}

// GetBatchStats returns batch processing statistics
func (e *DagEngine) GetBatchStats() map[string]interface{} {
	return map[string]interface{}{"error": "batch processor temporarily disabled"}
}
