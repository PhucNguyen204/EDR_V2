package engine_sigma_by_golang

// Unified configuration for SIGMA Engine (Go port)

import "fmt"

// -------------------- Enums --------------------

type ExecutionStrategy int

const (
	// Đặt Adaptive = 0 để zero-value hữu ích (giống Default của Rust)
	ExecutionAdaptive ExecutionStrategy = iota
	ExecutionDevelopment
	ExecutionProduction
)

func (s ExecutionStrategy) String() string {
	switch s {
	case ExecutionAdaptive:
		return "Adaptive"
	case ExecutionDevelopment:
		return "Development"
	case ExecutionProduction:
		return "Production"
	default:
		return fmt.Sprintf("ExecutionStrategy(%d)", int(s))
	}
}

type RuleComplexity int

const (
	ComplexitySimple RuleComplexity = iota
	ComplexityMedium
	ComplexityComplex
)

func (c RuleComplexity) String() string {
	switch c {
	case ComplexitySimple:
		return "Simple"
	case ComplexityMedium:
		return "Medium"
	case ComplexityComplex:
		return "Complex"
	default:
		return fmt.Sprintf("RuleComplexity(%d)", int(c))
	}
}

// -------------------- Heuristics --------------------

// AnalyzeRuleComplexity tương đương RuleComplexity::analyze(...)
func AnalyzeRuleComplexity(opcodeCount, maxStackDepth, primitiveCount int) RuleComplexity {
	// Simple: ít opcode + stack nông
	if opcodeCount <= 3 && maxStackDepth <= 2 {
		return ComplexitySimple
	}
	// Complex: rất nhiều opcode hoặc stack sâu hoặc nhiều primitive
	if opcodeCount > 8 || maxStackDepth > 4 || primitiveCount > 10 {
		return ComplexityComplex
	}
	// Còn lại là Medium
	return ComplexityMedium
}

// RecommendedStrategy tương đương recommended_strategy()
func (c RuleComplexity) RecommendedStrategy() ExecutionStrategy {
	switch c {
	case ComplexitySimple:
		return ExecutionProduction
	case ComplexityMedium, ComplexityComplex:
		return ExecutionAdaptive
	default:
		return ExecutionAdaptive
	}
}

// -------------------- EngineConfig --------------------

type EngineConfig struct {
	// Batch size cho xử lý sự kiện theo lô
	BatchSize int `json:"batch_size"`

	// Chiến lược thực thi: mặc định Adaptive
	Strategy ExecutionStrategy `json:"execution_strategy"`

	// Bật đa luồng
	EnableParallelProcessing bool `json:"enable_parallel_processing"`

	// Bật prefilter literal
	EnablePrefilter bool `json:"enable_prefilter"`

	// Giới hạn bộ nhớ (bytes)
	MaxMemoryBytes int `json:"max_memory_bytes"`
}

// Default “chuẩn” tương đương impl Default của Rust
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		BatchSize:               100,
		Strategy:                ExecutionAdaptive,
		EnableParallelProcessing: true,
		EnablePrefilter:          true,
		MaxMemoryBytes:           512 * 1024 * 1024, // 512MB
	}
}

// NewEngineConfig tạo config mặc định (thân thiện người dùng)
func NewEngineConfig() EngineConfig {
	return DefaultEngineConfig()
}

// Preset production() của Rust
func ProductionConfig() EngineConfig {
	return EngineConfig{
		BatchSize:               1000,
		Strategy:                ExecutionProduction,
		EnableParallelProcessing: true,
		EnablePrefilter:          true,
		MaxMemoryBytes:           1024 * 1024 * 1024, // 1GB
	}
}

// Preset development() của Rust
func DevelopmentConfig() EngineConfig {
	return EngineConfig{
		BatchSize:               10,
		Strategy:                ExecutionDevelopment,
		EnableParallelProcessing: false,
		EnablePrefilter:          false,
		MaxMemoryBytes:           64 * 1024 * 1024, // 64MB
	}
}

func (c EngineConfig) WithBatchSize(size int) EngineConfig {
	c.BatchSize = size
	return c
}

func (c EngineConfig) WithExecutionStrategy(s ExecutionStrategy) EngineConfig {
	c.Strategy = s
	return c
}

func (c EngineConfig) WithParallelProcessing(enable bool) EngineConfig {
	c.EnableParallelProcessing = enable
	return c
}

func (c EngineConfig) WithPrefilter(enable bool) EngineConfig {
	c.EnablePrefilter = enable
	return c
}

func (c EngineConfig) WithMaxMemory(bytes int) EngineConfig {
	c.MaxMemoryBytes = bytes
	return c
}
