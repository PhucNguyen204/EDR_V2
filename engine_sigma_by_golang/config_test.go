package engine_sigma_by_golang

import "testing"

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultEngineConfig()

	if cfg.BatchSize != 100 {
		t.Fatalf("batch_size")
	}
	if cfg.Strategy != ExecutionAdaptive {
		t.Fatalf("strategy default should be Adaptive")
	}
	if !cfg.EnableParallelProcessing {
		t.Fatalf("parallel default true")
	}
	if !cfg.EnablePrefilter {
		t.Fatalf("prefilter default true")
	}
	if cfg.MaxMemoryBytes != 512*1024*1024 {
		t.Fatalf("memory default 512MB")
	}
}

func TestProductionConfig(t *testing.T) {
	cfg := ProductionConfig()

	if cfg.BatchSize != 1000 {
		t.Fatalf("batch_size")
	}
	if cfg.Strategy != ExecutionProduction {
		t.Fatalf("strategy prod")
	}
	if !cfg.EnableParallelProcessing || !cfg.EnablePrefilter {
		t.Fatalf("prod toggles should be true")
	}
	if cfg.MaxMemoryBytes != 1024*1024*1024 {
		t.Fatalf("memory prod 1GB")
	}
}

func TestDevelopmentConfig(t *testing.T) {
	cfg := DevelopmentConfig()

	if cfg.BatchSize != 10 {
		t.Fatalf("batch_size")
	}
	if cfg.Strategy != ExecutionDevelopment {
		t.Fatalf("strategy dev")
	}
	if cfg.EnableParallelProcessing || cfg.EnablePrefilter {
		t.Fatalf("dev toggles should be false")
	}
	if cfg.MaxMemoryBytes != 64*1024*1024 {
		t.Fatalf("memory dev 64MB")
	}
}

func TestBuilderMethods(t *testing.T) {
	cfg := NewEngineConfig().
		WithBatchSize(500).
		WithExecutionStrategy(ExecutionProduction).
		WithParallelProcessing(false).
		WithPrefilter(true).
		WithMaxMemory(256 * 1024 * 1024)

	if cfg.BatchSize != 500 {
		t.Fatalf("batch")
	}
	if cfg.Strategy != ExecutionProduction {
		t.Fatalf("strategy")
	}
	if cfg.EnableParallelProcessing {
		t.Fatalf("parallel false")
	}
	if !cfg.EnablePrefilter {
		t.Fatalf("prefilter true")
	}
	if cfg.MaxMemoryBytes != 256*1024*1024 {
		t.Fatalf("memory 256MB")
	}
}

func TestExecutionStrategyZeroValueIsAdaptive(t *testing.T) {
	var s ExecutionStrategy
	if s != ExecutionAdaptive {
		t.Fatalf("zero value strategy should be Adaptive")
	}
}

func TestComplexityHeuristics(t *testing.T) {
	if AnalyzeRuleComplexity(2, 2, 1) != ComplexitySimple {
		t.Fatalf("simple expected")
	}
	if AnalyzeRuleComplexity(9, 1, 1) != ComplexityComplex {
		t.Fatalf("complex by opcode")
	}
	if AnalyzeRuleComplexity(4, 5, 1) != ComplexityComplex {
		t.Fatalf("complex by stack")
	}
	if AnalyzeRuleComplexity(4, 2, 11) != ComplexityComplex {
		t.Fatalf("complex by primitives")
	}
	if AnalyzeRuleComplexity(5, 3, 5) != ComplexityMedium {
		t.Fatalf("medium expected")
	}
}

func TestRecommendedStrategy(t *testing.T) {
	if ComplexitySimple.RecommendedStrategy() != ExecutionProduction {
		t.Fatalf("simple -> production")
	}
	if ComplexityMedium.RecommendedStrategy() != ExecutionAdaptive {
		t.Fatalf("medium -> adaptive")
	}
	if ComplexityComplex.RecommendedStrategy() != ExecutionAdaptive {
		t.Fatalf("complex -> adaptive")
	}
}
