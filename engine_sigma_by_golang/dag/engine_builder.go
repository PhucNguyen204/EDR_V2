package dag

import (
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
)

// EngineBuilder builds a DagEngine from rule YAMLs with optional compiler/config.
type EngineBuilder struct {
    comp  *compiler.Compiler
    cfg   EngineConfig
}

func NewEngineBuilder() *EngineBuilder {
    return &EngineBuilder{cfg: DefaultEngineConfig()}
}

func (b *EngineBuilder) WithCompiler(c *compiler.Compiler) *EngineBuilder { b.comp = c; return b }
func (b *EngineBuilder) WithConfig(cfg EngineConfig) *EngineBuilder       { b.cfg = cfg; return b }

func (b *EngineBuilder) Build(ruleYAMLs []string) (*DagEngine, error) {
    comp := b.comp
    if comp == nil { comp = compiler.New() }
    rs, err := comp.CompileRuleset(ruleYAMLs)
    if err != nil { return nil, err }
    return FromRuleset(rs, b.cfg)
}
